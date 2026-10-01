//! The command guard of the IMAP and ManageSieve relay after login.
//!
//! Invariant: once logged in, a client cannot take the session back to the
//! unauthenticated state, whatever the backend offers. `UNAUTHENTICATE`
//! (RFC 8437, RFC 5804 §2.14.1) would let it try passwords for any account
//! directly at the backend, past the password gate, the rate limit and the
//! account throttle. The guard therefore keeps these commands from the
//! backend:
//!
//! - IMAP: `UNAUTHENTICATE`, `AUTHENTICATE` and `LOGIN` (a second
//!   credential), `STARTTLS` and `COMPRESS` (either would turn the rest of
//!   the stream into bytes the guard cannot read).
//! - ManageSieve: `UNAUTHENTICATE`, `AUTHENTICATE` and `STARTTLS`.
//!
//! and takes `UNAUTHENTICATE` and `COMPRESS=…` (IMAP), `"UNAUTHENTICATE"`
//! and `"STARTTLS"` (ManageSieve) out of the capabilities the backend sends.
//!
//! A command is only where the backend's parser starts one, so the guard
//! frames the client stream the way the backend does: lines, quoted strings
//! and literals. It only lets octets pass unchecked that the backend
//! provably reads as literal data:
//!
//! - IMAP: an octet count the backend has answered with a continuation
//!   (`+`). A non-synchronizing literal (`{n+}`, `{n-}`, RFC 7888) is passed
//!   on as a synchronizing one (`{n}`) and the backend's `+` is not relayed;
//!   if the backend refuses the command, the octets the client sent anyway
//!   are dropped. One round trip per literal is the price. Commands that may
//!   be answered with a continuation for other reasons (`IDLE`, anything
//!   unknown) are completed before the next command is read.
//! - ManageSieve has no continuation (RFC 5804 §4: client literals are
//!   non-synchronizing), so literal data is checked line by line as well,
//!   for `UNAUTHENTICATE` only (a script line that starts with it is
//!   implausible; one that starts with "authenticate" is not).
//!
//! When the backend answers in a way the framing does not expect (a
//! continuation nobody asked for, an untagged `BAD`), IMAP falls back to
//! checking every line, literal data included, for the rest of the session.
//!
//! A blocked command at a command position the guard is sure of is answered
//! locally, as by a server that does not know the command (IMAP `<tag> BAD`,
//! RFC 9051 §7.1.3; ManageSieve `NO`), and never reaches the backend. One
//! anywhere else (in literal data, in the fallback, in an `IDLE`) ends the
//! session.
//!
//! The guard is sans-I/O: `on_client` and `on_server` take what was read
//! and return what to write; `wire::relay` moves the bytes.

use std::collections::VecDeque;

/// The protocol the guard frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Imap,
    Sieve,
}

/// What the guard did with a client chunk, beyond forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    None,
    /// A blocked command was answered locally (the reply is queued).
    Refused(&'static str),
    /// A blocked command where the guard cannot answer it: end the session.
    Close(&'static str),
}

const IMAP_BLOCKED: &[&str] = &[
    "UNAUTHENTICATE",
    "AUTHENTICATE",
    "LOGIN",
    "STARTTLS",
    "COMPRESS",
];
const SIEVE_BLOCKED: &[&str] = &["UNAUTHENTICATE", "AUTHENTICATE", "STARTTLS"];
/// Checked in ManageSieve literal data.
const SIEVE_IN_DATA: &[&str] = &["UNAUTHENTICATE"];

/// IMAP commands that are answered with a continuation for their literals
/// only (RFC 9051 and the extensions the backends offer). Any other command
/// is completed before the next one is read.
const IMAP_PLAIN: &[&str] = &[
    "APPEND",
    "CAPABILITY",
    "CHECK",
    "CLOSE",
    "COPY",
    "CREATE",
    "DELETE",
    "DELETEACL",
    "ENABLE",
    "EXAMINE",
    "EXPUNGE",
    "FETCH",
    "GETACL",
    "GETMETADATA",
    "GETQUOTA",
    "GETQUOTAROOT",
    "ID",
    "LIST",
    "LISTRIGHTS",
    "LOGOUT",
    "LSUB",
    "MOVE",
    "MYRIGHTS",
    "NAMESPACE",
    "NOOP",
    "RENAME",
    "REPLACE",
    "SEARCH",
    "SELECT",
    "SETACL",
    "SETMETADATA",
    "SETQUOTA",
    "SORT",
    "STATUS",
    "STORE",
    "SUBSCRIBE",
    "THREAD",
    "UID",
    "UNSELECT",
    "UNSUBSCRIBE",
];

/// Longest command word compared; no listed command is longer.
const WORD_MAX: usize = 16;
/// Longest IMAP tag the guard tracks; a longer one (no client uses one)
/// makes the session fall back to checking every line.
const TAG_MAX: usize = 64;
/// Most octets of a line start held back until its command is known.
const HOLD_MAX: usize = 256;
/// Most octets of a server line held back until it is classified.
const SERVER_HOLD_MAX: usize = 256;
/// Longest capability line filtered; a longer one is relayed as it is (the
/// commands stay blocked either way).
const CAP_LINE_MAX: usize = 16 * 1024;
/// Most ManageSieve responses tracked for the capability filter.
const PENDING_MAX: usize = 256;

fn is_space(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'=')
}

fn find(list: &[&'static str], word: &[u8]) -> Option<&'static str> {
    list.iter()
        .copied()
        .find(|w| w.as_bytes().eq_ignore_ascii_case(word))
}

/// The start of a line, read until its command word is known: optional
/// blanks, the tag (IMAP), blanks, the command, optionally quoted. Lenient
/// on purpose: whatever a backend might take for the command is compared.
#[derive(Debug, Clone)]
struct Head {
    step: Step,
    word: [u8; WORD_MAX],
    len: usize,
    /// The word overflowed `WORD_MAX`: no listed command.
    long: bool,
    quoted: bool,
    tag: Vec<u8>,
    /// A literal where the tag or the command would be: no sure framing,
    /// but the words are compared all the same.
    odd: bool,
    imap: bool,
    /// The run of word characters in the tag being read, and a listed
    /// command one of the runs so far named.
    seg: [u8; WORD_MAX],
    seg_len: usize,
    seg_long: bool,
    tag_blocked: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Lead,
    Tag,
    Gap,
    Word,
}

/// A decided line start.
#[derive(Debug, Clone)]
struct Decided {
    /// The listed command it names, if any.
    blocked: Option<&'static str>,
    /// The command word (empty if the line has none).
    word: Vec<u8>,
    /// The IMAP tag.
    tag: Vec<u8>,
    /// The tag or command is not an atom (a literal, an overlong tag): no
    /// sure framing.
    odd: bool,
    /// The deciding octet belongs to the head (a closing quote); otherwise
    /// it is the first octet of the rest of the line.
    took_last: bool,
}

impl Head {
    fn new(dialect: Dialect) -> Head {
        Head {
            step: if dialect == Dialect::Imap {
                Step::Lead
            } else {
                Step::Word
            },
            word: [0; WORD_MAX],
            len: 0,
            long: false,
            quoted: false,
            tag: Vec::new(),
            odd: false,
            imap: dialect == Dialect::Imap,
            seg: [0; WORD_MAX],
            seg_len: 0,
            seg_long: false,
            tag_blocked: None,
        }
    }

    fn decided(&self, list: &[&'static str], took_last: bool) -> Decided {
        let word = &self.word[..self.len];
        // The tag is compared too, and each run of word characters in it: a
        // backend that splits `a"UNAUTHENTICATE"` or takes a lone word for
        // the command must not get a listed one past the guard.
        let blocked = (!self.long)
            .then(|| find(list, word))
            .flatten()
            .or(self.tag_blocked);
        Decided {
            blocked,
            word: word.to_vec(),
            tag: self.tag.clone(),
            odd: self.odd || self.tag.len() > TAG_MAX || self.tag.contains(&b'{'),
            took_last,
        }
    }

    /// End the current run of word characters in the tag.
    fn end_seg(&mut self, list: &[&'static str]) {
        if !self.seg_long && self.tag_blocked.is_none() {
            self.tag_blocked = find(list, &self.seg[..self.seg_len]);
        }
        self.seg_len = 0;
        self.seg_long = false;
    }

    /// Feed one octet; `Some` once the line start is decided.
    fn feed(&mut self, b: u8, list: &[&'static str]) -> Option<Decided> {
        loop {
            match self.step {
                Step::Lead => {
                    if is_space(b) {
                        return None;
                    }
                    if b == b'\n' {
                        return Some(self.decided(list, false));
                    }
                    self.step = Step::Tag;
                }
                Step::Tag => {
                    // Only blanks end the tag here (a lone CR does not); what
                    // else a backend might split at is covered by comparing
                    // the tag's parts.
                    if b == b'\n' || is_space(b) {
                        self.end_seg(list);
                        if b == b'\n' {
                            return Some(self.decided(list, false));
                        }
                        self.step = Step::Gap;
                        return None;
                    }
                    if is_word(b) {
                        if self.seg_len < WORD_MAX {
                            self.seg[self.seg_len] = b;
                            self.seg_len += 1;
                        } else {
                            self.seg_long = true;
                        }
                    } else {
                        self.end_seg(list);
                    }
                    // Kept up to one past `TAG_MAX`: enough to tell it is
                    // too long.
                    if self.tag.len() <= TAG_MAX {
                        self.tag.push(b);
                    }
                    return None;
                }
                Step::Gap => {
                    if is_space(b) {
                        return None;
                    }
                    self.step = Step::Word;
                }
                Step::Word => {
                    // Before the command word: blanks, a quote, a literal marker
                    // or, for IMAP, anything else a backend might skip. Not for
                    // ManageSieve, whose literal data is checked too: a script
                    // line `# UNAUTHENTICATE` is a comment.
                    let skip = self.imap || is_space(b) || matches!(b, b'\r' | b'"' | b'{' | b'~');
                    if self.len == 0 && !self.long && b != b'\n' && !is_word(b) && skip {
                        match b {
                            b'"' => self.quoted = true,
                            b'{' | b'~' => self.odd = true,
                            _ => {}
                        }
                        return None;
                    }
                    if is_word(b) {
                        if self.len < WORD_MAX {
                            self.word[self.len] = b;
                            self.len += 1;
                        } else {
                            self.long = true;
                        }
                        return None;
                    }
                    let closing = self.quoted && b == b'"';
                    return Some(self.decided(list, closing));
                }
            }
        }
    }
}

/// Checks every line start of a stream it does not frame (literal data,
/// the fallback, a continuation line) and reports a listed command at the
/// octet that decides it, before that octet is forwarded. A backend acts on
/// a command line only once it has its end, so stopping there is enough.
#[derive(Debug, Clone)]
struct LineScan {
    /// `None`: inside a line.
    head: Option<Head>,
}

impl LineScan {
    fn at_line_start(dialect: Dialect) -> LineScan {
        LineScan {
            head: Some(Head::new(dialect)),
        }
    }

    fn mid_line() -> LineScan {
        LineScan { head: None }
    }

    fn feed(&mut self, b: u8, dialect: Dialect, list: &[&'static str]) -> Option<&'static str> {
        if let Some(head) = &mut self.head {
            if let Some(d) = head.feed(b, list) {
                self.head = None;
                if d.blocked.is_some() {
                    return d.blocked;
                }
            }
        }
        if b == b'\n' {
            self.head = Some(Head::new(dialect));
        }
        None
    }
}

/// A literal marker at the end of a line: `{n}`, `{n+}`, `{n-}`, and for
/// IMAP `~{…}` (RFC 3516).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Marker {
    n: u64,
    nonsync: bool,
    binary: bool,
    cr: bool,
}

/// Reads a candidate literal marker. `cand` holds its octets so far
/// (starting with `{` or `~`).
enum MarkStep {
    More,
    Fail,
    Done(Marker),
}

fn marker_step(cand: &[u8], b: u8, imap: bool) -> MarkStep {
    let binary = cand.first() == Some(&b'~');
    let body = if binary { &cand[1..] } else { cand };
    // `body` starts with `{` once past a `~`.
    if body.is_empty() {
        return if b == b'{' {
            MarkStep::More
        } else {
            MarkStep::Fail
        };
    }
    let inner = &body[1..];
    let digits = inner.iter().take_while(|c| c.is_ascii_digit()).count();
    let after = &inner[digits..];
    let done = |cr: bool, inner: &[u8]| {
        let d = inner.iter().take_while(|c| c.is_ascii_digit()).count();
        let n = std::str::from_utf8(&inner[..d])
            .ok()
            .and_then(|s| s.parse::<u64>().ok());
        let nonsync = matches!(inner.get(d), Some(b'+' | b'-'));
        match n {
            Some(n) => MarkStep::Done(Marker {
                n,
                nonsync,
                binary,
                cr,
            }),
            None => MarkStep::Fail,
        }
    };
    match after {
        [] => {
            let digit = b.is_ascii_digit() && digits < 19;
            let close = digits > 0 && b == b'}';
            // `{n-}` is IMAP's (RFC 7888); ManageSieve has `{n+}` only.
            let nonsync = digits > 0 && (b == b'+' || (imap && b == b'-'));
            if digit || close || nonsync {
                MarkStep::More
            } else {
                MarkStep::Fail
            }
        }
        [b'+' | b'-'] => {
            if b == b'}' {
                MarkStep::More
            } else {
                MarkStep::Fail
            }
        }
        [.., b'}'] if !after.ends_with(b"\r") => match b {
            b'\r' => MarkStep::More,
            b'\n' => done(false, inner),
            _ => MarkStep::Fail,
        },
        [.., b'}', b'\r'] => {
            if b == b'\n' {
                done(true, inner)
            } else {
                MarkStep::Fail
            }
        }
        _ => MarkStep::Fail,
    }
}

/// The rest of a command line after its head: quoted strings, and the
/// literal marker it may end with.
#[derive(Debug, Clone, Default)]
struct Body {
    quote: Quote,
    /// Octets of a candidate literal marker, not yet forwarded.
    cand: Vec<u8>,
    /// A line start in ManageSieve literal data not decided when the
    /// literal ended: its command word may continue past it.
    scan: Option<Head>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Quote {
    #[default]
    Out,
    In,
    Esc,
}

enum BodyStep {
    /// Forward these octets.
    Pass,
    /// Held as part of a marker candidate.
    Held,
    /// A failed candidate: forward the held octets, then feed this octet
    /// again.
    Retry,
    /// The line ended without a literal (the LF is forwarded).
    End,
    /// The line ends with a literal marker (the held marker is consumed).
    Literal(Marker),
}

impl Body {
    fn feed(&mut self, b: u8, imap: bool) -> BodyStep {
        if !self.cand.is_empty() {
            return match marker_step(&self.cand, b, imap) {
                MarkStep::More => {
                    self.cand.push(b);
                    BodyStep::Held
                }
                MarkStep::Fail => BodyStep::Retry,
                MarkStep::Done(m) => {
                    self.cand.clear();
                    BodyStep::Literal(m)
                }
            };
        }
        if b == b'\n' {
            self.quote = Quote::Out;
            return BodyStep::End;
        }
        match self.quote {
            Quote::Out => match b {
                b'"' => self.quote = Quote::In,
                b'{' => {
                    self.cand.push(b);
                    return BodyStep::Held;
                }
                b'~' if imap => {
                    self.cand.push(b);
                    return BodyStep::Held;
                }
                _ => {}
            },
            Quote::In => match b {
                b'\\' => self.quote = Quote::Esc,
                b'"' => self.quote = Quote::Out,
                _ => {}
            },
            Quote::Esc => self.quote = Quote::In,
        }
        BodyStep::Pass
    }
}

/// Where the guard is in the client stream.
#[derive(Debug)]
enum Pos {
    /// A command line starts; `held` is not forwarded yet.
    Head { head: Head, held: Vec<u8> },
    /// The rest of a command line.
    Body(Body),
    /// A line with a blocked command, dropped up to its end.
    Blocked { body: Body, word: &'static str },
    /// Literal octets the backend has asked for, passed unchecked (IMAP).
    Literal(u64),
    /// Literal octets of a refused command the client sent anyway (IMAP).
    Drop(u64),
    /// The rest of a refused command (IMAP).
    DropBody(Body),
    /// ManageSieve literal data, checked line by line.
    Data { left: u64, scan: LineScan },
    /// One line answering a server continuation (IMAP `IDLE`'s `DONE`).
    Cont(LineScan),
    /// The line before the next one is decided waits for the backend.
    Waiting,
    /// No sure framing: every line is checked (IMAP fallback).
    Scan(LineScan),
}

/// What the client waits for before the guard reads on (IMAP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wait {
    None,
    /// The backend's answer to a literal marker: `+`, or the tagged reply.
    Plus {
        marker: Marker,
    },
    /// The tagged reply to a command that is not plain; a `+` asks the
    /// client for one line.
    Done,
}

/// Where the guard is in the backend stream.
#[derive(Debug)]
enum SPos {
    /// A response line starts; `held` is not relayed yet.
    Head { held: Vec<u8> },
    /// The rest of a line. `cap`: the line is buffered for the capability
    /// filter; `drop`: it is not relayed.
    Rest {
        literals: bool,
        cap: Option<Vec<u8>>,
        drop: bool,
        mark: SMark,
        completes: bool,
    },
    /// Literal octets of a response.
    Literal { left: u64, completes: bool },
}

/// A server literal marker at the end of a line, read as the octets pass.
#[derive(Debug, Clone, Copy, Default)]
enum SMark {
    #[default]
    None,
    Open(u64, u8),
    Close(u64),
    Cr(u64),
}

impl SMark {
    fn feed(self, b: u8) -> SMark {
        match (self, b) {
            (_, b'{') => SMark::Open(0, 0),
            (SMark::Open(n, d), b'0'..=b'9') if d < 19 => {
                SMark::Open(n * 10 + u64::from(b - b'0'), d + 1)
            }
            (SMark::Open(n, d), b'}') if d > 0 => SMark::Close(n),
            (SMark::Close(n), b'\r') => SMark::Cr(n),
            _ => SMark::None,
        }
    }

    fn literal(self) -> Option<u64> {
        match self {
            SMark::Close(n) | SMark::Cr(n) => Some(n),
            _ => None,
        }
    }
}

/// The guard of one session.
#[derive(Debug)]
pub struct Guard {
    dialect: Dialect,
    pos: Pos,
    wait: Wait,
    /// IMAP: the line starts the guard checks are no longer sure.
    fallback: bool,
    /// IMAP: the tag of the command being read or awaited.
    tag: Vec<u8>,
    /// IMAP: the command being read is plain (`IMAP_PLAIN`).
    plain: bool,
    /// A local reply to write before the client is read on.
    local: Option<Vec<u8>>,
    spos: SPos,
    /// ManageSieve: responses outstanding, `true` for one to CAPABILITY.
    pending: VecDeque<bool>,
    /// The backend has closed: nothing more to wait for.
    server_closed: bool,
    /// Held client octets released by `fall_back`, forwarded first.
    carry: Vec<u8>,
}

impl Guard {
    pub fn new(dialect: Dialect) -> Guard {
        Guard {
            dialect,
            pos: Pos::Head {
                head: Head::new(dialect),
                held: Vec::new(),
            },
            wait: Wait::None,
            fallback: false,
            tag: Vec::new(),
            plain: true,
            local: None,
            spos: SPos::Head { held: Vec::new() },
            pending: VecDeque::new(),
            server_closed: false,
            carry: Vec::new(),
        }
    }

    fn blocked(&self) -> &'static [&'static str] {
        match self.dialect {
            Dialect::Imap => IMAP_BLOCKED,
            Dialect::Sieve => SIEVE_BLOCKED,
        }
    }

    /// The client is not read until the backend has answered, or a local
    /// reply is written.
    pub fn client_waits(&self) -> bool {
        !self.server_closed && (self.wait != Wait::None || self.local.is_some())
    }

    /// The backend has closed its side.
    pub fn server_closed(&mut self) {
        self.server_closed = true;
    }

    /// Give up the framing: check every line from here on (IMAP). Octets
    /// held back so far go to the backend with the next client octets.
    fn fall_back(&mut self) {
        if self.dialect != Dialect::Imap || self.fallback {
            return;
        }
        self.fallback = true;
        self.wait = Wait::None;
        let pos = std::mem::replace(&mut self.pos, Pos::Waiting);
        self.pos = match pos {
            Pos::Head { head, held } => {
                self.carry.extend_from_slice(&held);
                Pos::Scan(LineScan { head: Some(head) })
            }
            Pos::Body(body) => {
                self.carry.extend_from_slice(&body.cand);
                Pos::Scan(LineScan::mid_line())
            }
            Pos::DropBody(_) => Pos::Scan(LineScan::mid_line()),
            // After a line end: the next octet starts a line.
            Pos::Waiting | Pos::Drop(_) => Pos::Scan(LineScan::at_line_start(self.dialect)),
            Pos::Blocked { .. } => pos,
            Pos::Literal(_) | Pos::Cont(_) | Pos::Data { .. } | Pos::Scan(_) => {
                Pos::Scan(LineScan::mid_line())
            }
        };
    }

    /// Take client octets from `input` while the client need not wait; what
    /// goes to the backend is appended to `to_server`. Returns how much of
    /// `input` was taken; the rest is fed again once `client_waits` is false.
    pub fn on_client(&mut self, input: &[u8], to_server: &mut Vec<u8>) -> (usize, Event) {
        let imap = self.dialect == Dialect::Imap;
        let list = self.blocked();
        to_server.append(&mut self.carry);
        let mut i = 0;
        while i < input.len() && !self.client_waits() {
            match &mut self.pos {
                Pos::Head { head, held } => {
                    let b = input[i];
                    i += 1;
                    held.push(b);
                    let Some(d) = head.feed(b, list) else {
                        if held.len() > HOLD_MAX {
                            if !imap {
                                return (i, Event::Close("(overlong command start)"));
                            }
                            self.fall_back();
                            to_server.append(&mut self.carry);
                        }
                        continue;
                    };
                    let mut held = std::mem::take(held);
                    if !d.took_last {
                        // The deciding octet starts the rest of the line.
                        held.pop();
                        i -= 1;
                    }
                    if let Some(word) = d.blocked {
                        if self.fallback || d.odd {
                            return (i, Event::Close(word));
                        }
                        self.tag = d.tag;
                        self.pos = Pos::Blocked {
                            body: Body::default(),
                            word,
                        };
                        continue;
                    }
                    to_server.extend_from_slice(&held);
                    if d.odd && imap {
                        self.pos = Pos::Body(Body::default());
                        self.fall_back();
                        continue;
                    }
                    if imap {
                        self.tag = d.tag;
                        self.plain = d.word.is_empty() || find(IMAP_PLAIN, &d.word).is_some();
                    } else if !d.word.is_empty() && self.pending.len() < PENDING_MAX {
                        self.pending
                            .push_back(d.word.eq_ignore_ascii_case(b"CAPABILITY"));
                    }
                    self.pos = Pos::Body(Body::default());
                }
                Pos::Body(body) => {
                    let b = input[i];
                    if let Some(head) = &mut body.scan {
                        if let Some(d) = head.feed(b, SIEVE_IN_DATA) {
                            body.scan = None;
                            if let Some(word) = d.blocked {
                                return (i, Event::Close(word));
                            }
                        }
                    }
                    match body.feed(b, imap) {
                        BodyStep::Pass => {
                            to_server.push(b);
                            i += 1;
                        }
                        BodyStep::Held => i += 1,
                        BodyStep::Retry => {
                            to_server.extend_from_slice(&body.cand);
                            body.cand.clear();
                        }
                        BodyStep::End => {
                            to_server.push(b);
                            i += 1;
                            self.line_end(None, to_server);
                        }
                        BodyStep::Literal(m) => {
                            i += 1;
                            self.line_end(Some(m), to_server);
                        }
                    }
                }
                Pos::Blocked { body, word } => {
                    let word = *word;
                    let b = input[i];
                    i += 1;
                    match body.feed(b, imap) {
                        BodyStep::Retry => {
                            body.cand.clear();
                            i -= 1;
                        }
                        BodyStep::Pass | BodyStep::Held => {}
                        // A literal would follow: no sure end of the command.
                        BodyStep::Literal(_) => return (i, Event::Close(word)),
                        BodyStep::End => {
                            // ManageSieve answers in order: only when
                            // nothing else is outstanding.
                            if !imap && !self.pending.is_empty() {
                                return (i, Event::Close(word));
                            }
                            self.local = Some(self.refusal());
                            self.pos = Pos::Head {
                                head: Head::new(self.dialect),
                                held: Vec::new(),
                            };
                            return (i, Event::Refused(word));
                        }
                    }
                }
                Pos::Literal(left) => {
                    let k = usize::try_from(*left)
                        .unwrap_or(usize::MAX)
                        .min(input.len() - i);
                    to_server.extend_from_slice(&input[i..i + k]);
                    i += k;
                    *left -= k as u64;
                    if *left == 0 {
                        self.pos = Pos::Body(Body::default());
                    }
                }
                Pos::Drop(left) => {
                    let k = usize::try_from(*left)
                        .unwrap_or(usize::MAX)
                        .min(input.len() - i);
                    i += k;
                    *left -= k as u64;
                    if *left == 0 {
                        self.pos = Pos::DropBody(Body::default());
                    }
                }
                Pos::DropBody(body) => {
                    let b = input[i];
                    match body.feed(b, imap) {
                        BodyStep::Pass | BodyStep::Held => i += 1,
                        BodyStep::Retry => body.cand.clear(),
                        BodyStep::End => {
                            i += 1;
                            self.next_command();
                        }
                        BodyStep::Literal(m) => {
                            i += 1;
                            // A synchronizing literal is never sent: the
                            // client has the tagged reply.
                            self.pos = if m.nonsync {
                                Pos::Drop(m.n)
                            } else {
                                Pos::Head {
                                    head: Head::new(self.dialect),
                                    held: Vec::new(),
                                }
                            };
                            if !m.nonsync {
                                self.tag.clear();
                            }
                        }
                    }
                }
                Pos::Data { left, scan } => {
                    let b = input[i];
                    if let Some(word) = scan.feed(b, self.dialect, SIEVE_IN_DATA) {
                        return (i, Event::Close(word));
                    }
                    to_server.push(b);
                    i += 1;
                    *left -= 1;
                    if *left == 0 {
                        self.pos = Pos::Body(Body {
                            scan: scan.head.take(),
                            ..Body::default()
                        });
                    }
                }
                Pos::Cont(scan) => {
                    let b = input[i];
                    if let Some(word) = scan.feed(b, self.dialect, list) {
                        return (i, Event::Close(word));
                    }
                    to_server.push(b);
                    i += 1;
                    if b == b'\n' {
                        self.pos = Pos::Waiting;
                        self.wait = Wait::Done;
                    }
                }
                Pos::Scan(scan) => {
                    let b = input[i];
                    if let Some(word) = scan.feed(b, self.dialect, list) {
                        return (i, Event::Close(word));
                    }
                    to_server.push(b);
                    i += 1;
                }
                // Waiting for a backend that has closed: nothing reaches it
                // any more, so the client's octets are taken and dropped.
                Pos::Waiting => {
                    i = input.len();
                }
            }
        }
        (i, Event::None)
    }

    /// The command line ended, with a literal marker or without.
    fn line_end(&mut self, marker: Option<Marker>, to_server: &mut Vec<u8>) {
        match (self.dialect, marker) {
            (Dialect::Sieve, None) => self.next_command(),
            (Dialect::Sieve, Some(m)) => {
                // Relayed as sent; the data is checked line by line.
                to_server.push(b'{');
                to_server.extend_from_slice(m.n.to_string().as_bytes());
                if m.nonsync {
                    to_server.push(b'+');
                }
                to_server.extend_from_slice(if m.cr { b"}\r\n" } else { b"}\n" });
                // After an empty literal too: the next octet would start a
                // command for a backend that did not read it as one.
                self.pos = if m.n == 0 {
                    Pos::Body(Body {
                        scan: Some(Head::new(Dialect::Sieve)),
                        ..Body::default()
                    })
                } else {
                    Pos::Data {
                        left: m.n,
                        scan: LineScan::at_line_start(Dialect::Sieve),
                    }
                };
            }
            (Dialect::Imap, None) => {
                if self.plain {
                    self.next_command();
                } else {
                    self.pos = Pos::Waiting;
                    self.wait = Wait::Done;
                }
            }
            (Dialect::Imap, Some(m)) => {
                // Always synchronizing: the backend confirms with `+`.
                if m.binary {
                    to_server.push(b'~');
                }
                to_server.push(b'{');
                to_server.extend_from_slice(m.n.to_string().as_bytes());
                to_server.extend_from_slice(if m.cr { b"}\r\n" } else { b"}\n" });
                self.pos = Pos::Waiting;
                self.wait = Wait::Plus { marker: m };
            }
        }
    }

    fn next_command(&mut self) {
        self.pos = Pos::Head {
            head: Head::new(self.dialect),
            held: Vec::new(),
        };
    }

    fn refusal(&self) -> Vec<u8> {
        match self.dialect {
            Dialect::Imap => {
                let mut r = self.tag_of_blocked();
                r.extend_from_slice(b" BAD Command not permitted after login\r\n");
                r
            }
            Dialect::Sieve => b"NO \"Command not permitted after login\"\r\n".to_vec(),
        }
    }

    /// The tag of the blocked IMAP command (decided in its head); `*` for
    /// one that is not a valid tag (RFC 9051 §9: `astring-char` except `+`),
    /// which a server answers untagged.
    fn tag_of_blocked(&self) -> Vec<u8> {
        let valid = |b: &u8| {
            b.is_ascii_graphic()
                && !matches!(b, b'(' | b')' | b'{' | b'"' | b'\\' | b'%' | b'*' | b'+')
        };
        if !self.tag.is_empty() && self.tag.iter().all(valid) {
            self.tag.clone()
        } else {
            b"*".to_vec()
        }
    }

    /// The local reply, once the backend stream is between responses.
    pub fn take_local(&mut self) -> Option<Vec<u8>> {
        match &self.spos {
            SPos::Head { held } if held.is_empty() => self.local.take(),
            _ => None,
        }
    }

    /// Take backend octets; what goes to the client is appended to
    /// `to_client`. Everything is taken.
    pub fn on_server(&mut self, input: &[u8], to_client: &mut Vec<u8>) {
        let mut i = 0;
        while i < input.len() {
            match &mut self.spos {
                SPos::Head { held } => {
                    let b = input[i];
                    i += 1;
                    held.push(b);
                    let held = std::mem::take(held);
                    match self.classify(&held) {
                        Some(class) => self.start_line(held, class, to_client),
                        None => self.spos = SPos::Head { held },
                    }
                }
                SPos::Rest {
                    literals,
                    cap,
                    drop,
                    mark,
                    completes,
                } => {
                    let b = input[i];
                    i += 1;
                    // The marker is read at the LF, before it would reset.
                    if *literals && b != b'\n' {
                        *mark = mark.feed(b);
                    }
                    match cap {
                        Some(line) if line.len() < CAP_LINE_MAX => line.push(b),
                        Some(line) => {
                            to_client.extend_from_slice(line);
                            to_client.push(b);
                            *cap = None;
                        }
                        None if !*drop => to_client.push(b),
                        None => {}
                    }
                    if b != b'\n' {
                        continue;
                    }
                    let (completes, literal) = (*completes, mark.literal().filter(|_| *literals));
                    if let Some(line) = cap.take() {
                        self.filter_caps(&line, to_client);
                    }
                    match literal {
                        Some(n) if n > 0 => self.spos = SPos::Literal { left: n, completes },
                        Some(_) => self.spos = rest_after_literal(completes),
                        None => {
                            if completes {
                                self.pending.pop_front();
                            }
                            self.spos = SPos::Head { held: Vec::new() };
                        }
                    }
                }
                SPos::Literal { left, completes } => {
                    let k = usize::try_from(*left)
                        .unwrap_or(usize::MAX)
                        .min(input.len() - i);
                    to_client.extend_from_slice(&input[i..i + k]);
                    i += k;
                    *left -= k as u64;
                    if *left == 0 {
                        self.spos = rest_after_literal(*completes);
                    }
                }
            }
        }
    }

    /// Classify a held server line start, `None` while more is needed.
    fn classify(&self, held: &[u8]) -> Option<Class> {
        let full = held.len() >= SERVER_HOLD_MAX || held.ends_with(b"\n");
        match self.dialect {
            Dialect::Imap => classify_imap(held, full),
            Dialect::Sieve => classify_sieve(held, full, self.pending.front() == Some(&true)),
        }
    }

    fn start_line(&mut self, held: Vec<u8>, class: Class, to_client: &mut Vec<u8>) {
        let mut drop = false;
        match class.kind {
            Kind::Continuation if !self.fallback => match self.wait {
                Wait::Plus { marker } => {
                    drop = marker.nonsync;
                    self.wait = Wait::None;
                    self.pos = if marker.n == 0 {
                        Pos::Body(Body::default())
                    } else {
                        Pos::Literal(marker.n)
                    };
                }
                Wait::Done => {
                    self.wait = Wait::None;
                    self.pos = Pos::Cont(LineScan::at_line_start(self.dialect));
                }
                // A continuation nobody asked for: the framing is not sure.
                Wait::None => self.fall_back(),
            },
            Kind::Tagged(ref tag) if !self.fallback && self.wait != Wait::None => {
                if *tag == self.tag {
                    match self.wait {
                        Wait::Plus { marker } if marker.nonsync => {
                            // Refused: the client sent the literal anyway.
                            self.pos = if marker.n == 0 {
                                Pos::DropBody(Body::default())
                            } else {
                                Pos::Drop(marker.n)
                            };
                        }
                        _ => self.next_command(),
                    }
                    self.wait = Wait::None;
                }
            }
            Kind::UntaggedBad if self.wait != Wait::None => self.fall_back(),
            Kind::Drop => drop = true,
            _ => {}
        }
        let cap = class.caps.then(Vec::new);
        let mut rest = SPos::Rest {
            literals: class.literals,
            cap,
            drop,
            mark: SMark::None,
            completes: class.completes,
        };
        // Replay the held octets through the line state.
        if let SPos::Rest {
            cap: Some(line), ..
        } = &mut rest
        {
            line.extend_from_slice(&held[..held.len() - 1]);
        } else if !drop {
            to_client.extend_from_slice(&held[..held.len() - 1]);
        }
        if let SPos::Rest {
            literals: true,
            mark,
            ..
        } = &mut rest
        {
            for &b in &held[..held.len() - 1] {
                *mark = mark.feed(b);
            }
        }
        self.spos = rest;
        // The last held octet goes through `Rest` (it may end the line).
        let last = held[held.len() - 1];
        self.on_server(&[last], to_client);
    }

    /// Relay a buffered capability line without the filtered capabilities.
    fn filter_caps(&self, line: &[u8], to_client: &mut Vec<u8>) {
        match self.dialect {
            Dialect::Imap => to_client.extend_from_slice(&filter_imap_caps(line)),
            // The whole line is the capability; `drop` handled listed ones.
            Dialect::Sieve => to_client.extend_from_slice(line),
        }
    }
}

/// An IMAP response line as the guard relays it after the login (the
/// tagged OK of the backend login, written before the relay starts).
pub(crate) fn imap_response(line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    Guard::new(Dialect::Imap).on_server(line, &mut out);
    out
}

fn rest_after_literal(completes: bool) -> SPos {
    SPos::Rest {
        literals: true,
        cap: None,
        drop: false,
        mark: SMark::None,
        completes,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Continuation,
    Tagged(Vec<u8>),
    UntaggedBad,
    /// A capability line the client must not see (ManageSieve).
    Drop,
    Other,
}

#[derive(Debug)]
struct Class {
    kind: Kind,
    /// The line may end with a literal marker (not a status response, whose
    /// text could end in `{n}` and is never a literal, RFC 9051 §7.1).
    literals: bool,
    /// The line carries capabilities to filter (IMAP).
    caps: bool,
    /// The line ends a response (ManageSieve `OK`/`NO`/`BYE`).
    completes: bool,
}

/// The first space-separated token of `s` and what follows the space, or
/// `None` if `s` has no space yet.
fn token(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = s
        .iter()
        .position(|&b| b == b' ' || b == b'\r' || b == b'\n')?;
    Some((&s[..end], &s[end..]))
}

fn is_status(t: &[u8]) -> bool {
    ["OK", "NO", "BAD", "BYE", "PREAUTH"]
        .iter()
        .any(|s| s.as_bytes().eq_ignore_ascii_case(t))
}

fn classify_imap(held: &[u8], full: bool) -> Option<Class> {
    let other = |literals| Class {
        kind: Kind::Other,
        literals,
        caps: false,
        completes: false,
    };
    if held[0] == b'+' {
        return Some(Class {
            kind: Kind::Continuation,
            literals: false,
            caps: false,
            completes: false,
        });
    }
    let Some((first, rest)) = token(held) else {
        return full.then(|| other(true));
    };
    let tagged = first != b"*";
    let Some(rest) = rest.strip_prefix(b" ") else {
        // A line of one token.
        return Some(Class {
            kind: if tagged {
                Kind::Tagged(first.to_vec())
            } else {
                Kind::Other
            },
            literals: !tagged,
            caps: false,
            completes: false,
        });
    };
    let Some((second, after)) = token(rest) else {
        return full.then(|| other(true));
    };
    if !tagged && second.eq_ignore_ascii_case(b"CAPABILITY") {
        return Some(Class {
            kind: Kind::Other,
            literals: false,
            caps: true,
            completes: false,
        });
    }
    if !is_status(second) {
        return Some(Class {
            kind: if tagged {
                Kind::Tagged(first.to_vec())
            } else {
                Kind::Other
            },
            literals: !tagged,
            caps: false,
            completes: false,
        });
    }
    // A status response: a `[CAPABILITY …]` code is filtered.
    const CODE: &[u8] = b" [CAPABILITY ";
    let n = after.len().min(CODE.len());
    if !after[..n].eq_ignore_ascii_case(&CODE[..n]) {
        return Some(status_class(tagged, first, second, false));
    }
    if n < CODE.len() && !full {
        return None;
    }
    Some(status_class(tagged, first, second, n == CODE.len()))
}

fn status_class(tagged: bool, first: &[u8], second: &[u8], caps: bool) -> Class {
    Class {
        kind: if tagged {
            Kind::Tagged(first.to_vec())
        } else if second.eq_ignore_ascii_case(b"BAD") {
            Kind::UntaggedBad
        } else {
            Kind::Other
        },
        literals: false,
        caps,
        completes: false,
    }
}

fn classify_sieve(held: &[u8], full: bool, in_caps: bool) -> Option<Class> {
    let data = |kind| Class {
        kind,
        literals: true,
        caps: false,
        completes: false,
    };
    if held[0] == b'"' {
        // A capability line names its capability first (RFC 5804 §1.7).
        let name_end = held[1..].iter().position(|&b| b == b'"' || b == b'\n');
        let Some(end) = name_end else {
            return full.then(|| data(Kind::Other));
        };
        let name = &held[1..1 + end];
        let drop = in_caps
            && (name.eq_ignore_ascii_case(b"UNAUTHENTICATE")
                || name.eq_ignore_ascii_case(b"STARTTLS"));
        return Some(data(if drop { Kind::Drop } else { Kind::Other }));
    }
    let end = held
        .iter()
        .position(|&b| !b.is_ascii_alphabetic())
        .or(full.then_some(held.len()))?;
    let word = &held[..end];
    let completes = ["OK", "NO", "BYE"]
        .iter()
        .any(|s| s.as_bytes().eq_ignore_ascii_case(word));
    Some(Class {
        kind: Kind::Other,
        literals: true,
        caps: false,
        completes,
    })
}

/// An IMAP capability line (`* CAPABILITY …` or a status response with a
/// `[CAPABILITY …]` code) without `UNAUTHENTICATE` and `COMPRESS=…`.
fn filter_imap_caps(line: &[u8]) -> Vec<u8> {
    let drop = |t: &[u8]| {
        t.eq_ignore_ascii_case(b"UNAUTHENTICATE")
            || t.get(..9)
                .is_some_and(|p| p.eq_ignore_ascii_case(b"COMPRESS="))
    };
    // The capabilities run to the line end (`* CAPABILITY`) or to `]`.
    let (start, end) = if line
        .get(..13)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"* CAPABILITY "))
    {
        let end = line
            .iter()
            .rposition(|&b| b != b'\r' && b != b'\n')
            .map_or(0, |p| p + 1);
        (13, end)
    } else {
        // The code follows the tag (which may hold a `[`) and the status.
        const CODE: &[u8] = b" [CAPABILITY ";
        let sp = |from: usize| {
            line[from..]
                .iter()
                .position(|&b| b == b' ')
                .map(|p| from + p)
        };
        let Some(code) = sp(0).and_then(|first| sp(first + 1)).filter(|&at| {
            line[at..]
                .get(..CODE.len())
                .is_some_and(|c| c.eq_ignore_ascii_case(CODE))
        }) else {
            return line.to_vec();
        };
        let start = code + CODE.len();
        let Some(close) = line[start..].iter().position(|&b| b == b']') else {
            return line.to_vec();
        };
        (start, start + close)
    };
    let kept: Vec<&[u8]> = line[start..end]
        .split(|&b| b == b' ')
        .filter(|t| !t.is_empty() && !drop(t))
        .collect();
    let mut out = line[..start].to_vec();
    out.extend_from_slice(&kept.join(&b' '));
    out.extend_from_slice(&line[end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `client` (all of it, as far as the guard reads) and return what
    /// reaches the backend and the event.
    fn client(g: &mut Guard, input: &[u8]) -> (Vec<u8>, usize, Event) {
        let mut out = Vec::new();
        let (used, ev) = g.on_client(input, &mut out);
        (out, used, ev)
    }

    fn server(g: &mut Guard, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        g.on_server(input, &mut out);
        out
    }

    #[test]
    fn imap_blocks_unauthenticate_with_a_local_bad() {
        for line in [
            &b"a1 UNAUTHENTICATE\r\n"[..],
            b"a1 unauthenticate\r\n",
            b"  a1\t UNAUTHENTICATE\r\n",
            b"a1 \"UNAUTHENTICATE\"\r\n",
            b"a1 UNAUTHENTICATE extra args\r\n",
            b"a1  UNAUTHENTICATE\r\n",
            b"a1\tUNAUTHENTICATE\r\n",
            b"a1 UNAUTHENTICATE\n",
            b"a1 LOGIN user pass\r\n",
            b"a1 AUTHENTICATE PLAIN\r\n",
            b"a1 COMPRESS DEFLATE\r\n",
            b"a1 STARTTLS\r\n",
            b"\x08a1 UNAUTHENTICATE\r\n",
            b"a1\"UNAUTHENTICATE\"\r\n",
        ] {
            let mut g = Guard::new(Dialect::Imap);
            let (out, used, ev) = client(&mut g, line);
            assert!(out.is_empty(), "{:?}", String::from_utf8_lossy(line));
            assert_eq!(used, line.len());
            assert!(matches!(ev, Event::Refused(_)), "{ev:?}");
            assert!(g.client_waits(), "paused until the reply is written");
            let reply = g.take_local().unwrap();
            let tag = if line.starts_with(b"a1 ")
                || line.starts_with(b"a1\t")
                || line.starts_with(b"  a1")
            {
                "a1"
            } else {
                "*"
            };
            assert_eq!(
                String::from_utf8(reply).unwrap(),
                format!("{tag} BAD Command not permitted after login\r\n")
            );
            assert!(!g.client_waits());
            // The next command passes.
            let (out, _, ev) = client(&mut g, b"a2 NOOP\r\n");
            assert_eq!(out, b"a2 NOOP\r\n");
            assert_eq!(ev, Event::None);
        }
    }

    #[test]
    fn imap_passes_other_commands_unchanged() {
        let mut g = Guard::new(Dialect::Imap);
        // The unknown command last: the next one waits for its reply.
        let input = b"a1 SELECT INBOX\r\na2 FETCH 1:* (FLAGS)\r\na4 SEARCH SUBJECT \"x {5}\"\r\na3 UNAUTHENTICATEX\r\n";
        let (out, used, ev) = client(&mut g, input);
        assert_eq!(out, input);
        assert_eq!(used, input.len());
        assert_eq!(ev, Event::None);
    }

    #[test]
    fn imap_line_split_anywhere() {
        let input = b"a1 NOOP\r\nb2 UNAUTHENTICATE\r\nc3 NOOP\r\n";
        for split in 0..input.len() {
            let mut g = Guard::new(Dialect::Imap);
            let mut out = Vec::new();
            let mut pending: Vec<u8> = Vec::new();
            for part in [&input[..split], &input[split..]] {
                pending.extend_from_slice(part);
                loop {
                    let (used, _) = g.on_client(&pending, &mut out);
                    pending.drain(..used);
                    if g.take_local().is_none() {
                        break;
                    }
                }
            }
            assert_eq!(out, b"a1 NOOP\r\nc3 NOOP\r\n", "split at {split}");
        }
    }

    /// A synchronizing literal waits for the backend's `+`; its data passes
    /// unchecked, so a mail line that reads like the command is not blocked.
    #[test]
    fn imap_confirmed_literal_is_data() {
        let mut g = Guard::new(Dialect::Imap);
        let (out, used, _) = client(
            &mut g,
            b"a1 APPEND INBOX {24}\r\nb UNAUTHENTICATE\r\nxxxxx\r\n",
        );
        assert_eq!(out, b"a1 APPEND INBOX {24}\r\n");
        assert_eq!(used, 22);
        assert!(g.client_waits());
        assert_eq!(server(&mut g, b"+ Ready\r\n"), b"+ Ready\r\n");
        let (out, _, ev) = client(&mut g, b"b UNAUTHENTICATE\r\nxxxxx\r\n\r\n");
        assert_eq!(ev, Event::None);
        assert_eq!(out, b"b UNAUTHENTICATE\r\nxxxxx\r\n\r\n");
        // Back to commands.
        let (_, _, ev) = client(&mut g, b"c UNAUTHENTICATE\r\n");
        assert_eq!(ev, Event::Refused("UNAUTHENTICATE"));
    }

    /// A non-synchronizing literal goes out synchronizing; the `+` is not
    /// relayed; on a refusal the data the client sent is dropped.
    #[test]
    fn imap_nonsync_literal_is_confirmed_by_the_backend() {
        let mut g = Guard::new(Dialect::Imap);
        let data = b"a1 APPEND INBOX {18+}\r\nb UNAUTHENTICATE\r\n\r\n";
        let (out, used, _) = client(&mut g, data);
        assert_eq!(out, b"a1 APPEND INBOX {18}\r\n");
        assert!(g.client_waits());
        assert_eq!(server(&mut g, b"+ OK\r\n"), b"");
        let (out, _, ev) = client(&mut g, &data[used..]);
        assert_eq!(ev, Event::None);
        assert_eq!(out, b"b UNAUTHENTICATE\r\n\r\n");

        // Refused: the backend never sees the literal or the rest.
        let mut g = Guard::new(Dialect::Imap);
        let data = b"a1 APPEND nope {18+}\r\nb UNAUTHENTICATE\r\n {3+}\r\nabc\r\nc NOOP\r\n";
        let (_, used, _) = client(&mut g, data);
        assert_eq!(
            server(&mut g, b"a1 NO [TRYCREATE] no such mailbox\r\n"),
            b"a1 NO [TRYCREATE] no such mailbox\r\n"
        );
        let (out, _, ev) = client(&mut g, &data[used..]);
        assert_eq!(ev, Event::None);
        assert_eq!(out, b"c NOOP\r\n");
    }

    /// An unknown command with a literal that holds the command (Stalwart
    /// refuses the command and does not read the literal): the literal never
    /// reaches the backend.
    #[test]
    fn imap_unknown_command_literal_is_dropped() {
        let mut g = Guard::new(Dialect::Imap);
        let data = b"a XFOO {18+}\r\nb UNAUTHENTICATE\r\n\r\nc NOOP\r\n";
        let (out, used, _) = client(&mut g, data);
        assert_eq!(out, b"a XFOO {18}\r\n");
        server(&mut g, b"a BAD [PARSE] Unrecognized command 'XFOO'.\r\n");
        let (out, _, ev) = client(&mut g, &data[used..]);
        assert_eq!(ev, Event::None);
        assert_eq!(out, b"c NOOP\r\n");
    }

    /// IDLE: the next command is read only after the tagged reply; the
    /// `DONE` line is checked as it passes.
    #[test]
    fn imap_idle() {
        let mut g = Guard::new(Dialect::Imap);
        let (out, used, _) = client(&mut g, b"a IDLE\r\nDONE\r\nb NOOP\r\n");
        assert_eq!(out, b"a IDLE\r\n");
        assert_eq!(used, 8);
        assert!(g.client_waits());
        assert_eq!(
            server(&mut g, b"+ idling\r\n* 3 EXISTS\r\n"),
            b"+ idling\r\n* 3 EXISTS\r\n"
        );
        let (out, used, _) = client(&mut g, b"DONE\r\nb NOOP\r\n");
        assert_eq!(out, b"DONE\r\n");
        assert_eq!(used, 6);
        assert!(g.client_waits());
        server(&mut g, b"a OK Idle completed.\r\n");
        let (out, _, _) = client(&mut g, b"b NOOP\r\n");
        assert_eq!(out, b"b NOOP\r\n");

        // A blocked command in place of DONE ends the session.
        let mut g = Guard::new(Dialect::Imap);
        client(&mut g, b"a IDLE\r\n");
        server(&mut g, b"+ idling\r\n");
        let (out, _, ev) = client(&mut g, b"b UNAUTHENTICATE\r\n");
        assert_eq!(ev, Event::Close("UNAUTHENTICATE"));
        assert!(!out.ends_with(b"\n"), "{out:?}");
    }

    /// A continuation nobody asked for: every line is checked from then on,
    /// literal data included.
    #[test]
    fn imap_unexpected_continuation_falls_back() {
        let mut g = Guard::new(Dialect::Imap);
        client(&mut g, b"a NOOP\r\n");
        server(&mut g, b"+ surprise\r\n");
        assert!(g.fallback);
        let (out, _, ev) = client(&mut g, b"x APPEND INBOX {20+}\r\nb UNAUTHENTICATE\r\n");
        assert_eq!(ev, Event::Close("UNAUTHENTICATE"));
        assert_eq!(out, b"x APPEND INBOX {20+}\r\nb UNAUTHENTICATE");
    }

    #[test]
    fn imap_odd_heads_fall_back() {
        let long_tag = [&[b'x'; 80][..], b" NOOP\r\n"].concat();
        let long_start = [b' '; HOLD_MAX + 1];
        for line in [&b"a {14}\r\n"[..], b"{1}\r\n", &long_tag, &long_start] {
            let mut g = Guard::new(Dialect::Imap);
            let (out, used, _) = client(&mut g, line);
            assert!(g.fallback, "{:?}", String::from_utf8_lossy(line));
            assert_eq!((out.as_slice(), used), (line, line.len()));
        }
        // A listed command after an overlong tag is still found.
        let mut g = Guard::new(Dialect::Imap);
        let line = [&[b'x'; 300][..], b" UNAUTHENTICATE\r\n"].concat();
        let (out, _, ev) = client(&mut g, &line);
        assert_eq!(ev, Event::Close("UNAUTHENTICATE"));
        assert!(!out.contains(&b'\n'));
    }

    /// A backend that closes while the guard waits for it: the client is
    /// read on (and its octets dropped), never left waiting.
    #[test]
    fn backend_close_while_waiting() {
        let mut g = Guard::new(Dialect::Imap);
        client(&mut g, b"a APPEND INBOX {5}\r\n");
        assert!(g.client_waits());
        g.server_closed();
        assert!(!g.client_waits());
        let (out, used, ev) = client(&mut g, b"hello\r\n");
        assert_eq!((out.len(), used, ev), (0, 7, Event::None));
    }

    #[test]
    fn imap_capabilities_are_filtered() {
        let mut g = Guard::new(Dialect::Imap);
        let out = server(
            &mut g,
            b"* CAPABILITY IMAP4rev1 UNAUTHENTICATE IDLE COMPRESS=DEFLATE\r\n\
              a OK [CAPABILITY IMAP4rev1 unauthenticate MOVE] done\r\n\
              * OK [CAPABILITY UNAUTHENTICATE] x\r\n\
              * ENABLED UNAUTHENTICATE\r\n\
              a[1 OK [CAPABILITY IMAP4rev1 UNAUTHENTICATE] done\r\n",
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "* CAPABILITY IMAP4rev1 IDLE\r\n\
             a OK [CAPABILITY IMAP4rev1 MOVE] done\r\n\
             * OK [CAPABILITY ] x\r\n\
             * ENABLED UNAUTHENTICATE\r\n\
             a[1 OK [CAPABILITY IMAP4rev1] done\r\n"
        );
        // Inside a FETCH literal nothing changes.
        let mut g = Guard::new(Dialect::Imap);
        let body = b"* 1 FETCH (BODY[] {34}\r\n* CAPABILITY UNAUTHENTICATE IDLE\r\n)\r\n";
        assert_eq!(server(&mut g, body), body);
        // Split anywhere, the result is the same.
        let input = b"* CAPABILITY IMAP4rev1 UNAUTHENTICATE IDLE\r\n";
        for split in 0..input.len() {
            let mut g = Guard::new(Dialect::Imap);
            let mut out = server(&mut g, &input[..split]);
            out.extend(server(&mut g, &input[split..]));
            assert_eq!(out, b"* CAPABILITY IMAP4rev1 IDLE\r\n", "{split}");
        }
    }

    /// Status text that ends in `{n}` is not a literal.
    #[test]
    fn imap_status_text_is_not_a_literal() {
        let mut g = Guard::new(Dialect::Imap);
        server(&mut g, b"a NO Mailbox doesn't exist: x{40}\r\n");
        assert!(matches!(g.spos, SPos::Head { .. }));
    }

    #[test]
    fn sieve_blocks_at_command_position_and_in_literals() {
        // The spellings Stalwart 0.16 executes, and the quoted one.
        for line in [
            &b"UNAUTHENTICATE\r\n"[..],
            b"unauthenticate\r\n",
            b"  unauthenticate\r\n",
            b"\tUNAUTHENTICATE\r\n",
            b"UNAUTHENTICATE x\r\n",
            b"UNAUTHENTICATE\n",
            b"\"UNAUTHENTICATE\"\r\n",
        ] {
            let mut g = Guard::new(Dialect::Sieve);
            let (out, used, ev) = client(&mut g, line);
            assert!(out.is_empty(), "{:?}", String::from_utf8_lossy(line));
            assert_eq!(used, line.len());
            assert_eq!(ev, Event::Refused("UNAUTHENTICATE"));
            assert_eq!(
                g.take_local().unwrap(),
                b"NO \"Command not permitted after login\"\r\n"
            );
        }
        // In literal data only UNAUTHENTICATE ends the session.
        let mut g = Guard::new(Dialect::Sieve);
        let script = b"PUTSCRIPT \"s\" {40+}\r\nauthenticate yourself\r\nUNAUTHENTICATE\r\n\r\n";
        let (out, _, ev) = client(&mut g, script);
        assert_eq!(ev, Event::Close("UNAUTHENTICATE"));
        assert!(out.ends_with(b"\r\nUNAUTHENTICATE"), "{out:?}");
        // A script that only mentions it passes.
        let mut g = Guard::new(Dialect::Sieve);
        let script =
            b"PUTSCRIPT \"s\" {44+}\r\n# UNAUTHENTICATE\r\nif header \"UNAUTHENTICATE\"\r\n\r\n";
        let (out, used, ev) = client(&mut g, script);
        assert_eq!(ev, Event::None);
        assert_eq!(used, script.len());
        assert_eq!(out, script);
        // After an empty literal as well.
        let mut g = Guard::new(Dialect::Sieve);
        let (_, _, ev) = client(&mut g, b"PUTSCRIPT \"s\" {0+}\r\nUNAUTHENTICATE\r\n");
        assert_eq!(ev, Event::Close("UNAUTHENTICATE"));
        // A pipelined blocked command after an outstanding one closes.
        let mut g = Guard::new(Dialect::Sieve);
        let (_, _, ev) = client(&mut g, b"LISTSCRIPTS\r\nUNAUTHENTICATE\r\n");
        assert_eq!(ev, Event::Close("UNAUTHENTICATE"));
    }

    #[test]
    fn sieve_capability_response_is_filtered() {
        let mut g = Guard::new(Dialect::Sieve);
        client(&mut g, b"CAPABILITY\r\n");
        let out = server(
            &mut g,
            b"\"IMPLEMENTATION\" \"x\"\r\n\"UNAUTHENTICATE\"\r\n\"SASL\" \"PLAIN\"\r\nOK \"done\"\r\n",
        );
        assert_eq!(
            out,
            b"\"IMPLEMENTATION\" \"x\"\r\n\"SASL\" \"PLAIN\"\r\nOK \"done\"\r\n"
        );
        // A script named UNAUTHENTICATE is listed.
        client(&mut g, b"LISTSCRIPTS\r\n");
        let list = b"\"UNAUTHENTICATE\" ACTIVE\r\nOK \"ok\"\r\n";
        assert_eq!(server(&mut g, list), list);
    }

    #[test]
    fn markers() {
        let parse = |s: &[u8], imap: bool| {
            let mut cand = vec![s[0]];
            for &b in &s[1..] {
                match marker_step(&cand, b, imap) {
                    MarkStep::More => cand.push(b),
                    MarkStep::Fail => return None,
                    MarkStep::Done(m) => return Some(m),
                }
            }
            None
        };
        let m = parse(b"{12}\r\n", true).unwrap();
        assert_eq!((m.n, m.nonsync, m.binary, m.cr), (12, false, false, true));
        let m = parse(b"~{3+}\n", true).unwrap();
        assert_eq!((m.n, m.nonsync, m.binary, m.cr), (3, true, true, false));
        assert!(parse(b"{3-}\r\n", true).unwrap().nonsync);
        assert!(parse(b"{3-}\r\n", false).is_none());
        assert!(parse(b"{3+}\r\n", false).unwrap().nonsync);
        assert!(parse(b"{}\r\n", true).is_none());
        assert!(parse(b"{3} \r\n", true).is_none());
        assert!(parse(b"{99999999999999999999}\r\n", true).is_none());
    }
}
