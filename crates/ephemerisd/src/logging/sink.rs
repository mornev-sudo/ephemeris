//! Where log lines go: the journal (or stderr), the files under
//! `/var/log/ephemeris`, and a ring of recent lines in memory.
//!
//! Whoever logs (a worker, the API, the DHCP service) only formats the line
//! and hands it to one writer thread through a bounded queue: it never
//! waits on a file. If the queue is full, the line is dropped and counted,
//! and the writer says how many were lost once it catches up.

use super::{control, Lvl, AUDIT_TARGET};
use serde::Serialize;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tracing::field::{Field, Visit};
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Filter, Layer};
use tracing_subscriber::prelude::*;

/// Lines kept in memory for `ephctl log show`.
pub const RING_LINES: usize = 5000;
/// Lines waiting for the writer, at most.
const QUEUE: usize = 8192;

/// One log line.
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    /// Increases by one per line kept: `ephctl log show --follow` asks for
    /// what came after the last one it saw.
    pub seq: u64,
    pub unix_ms: u64,
    pub level: Lvl,
    pub category: String,
    /// The message, then any fields as `key=value`.
    pub message: String,
}

impl Record {
    /// As a line in a file: `2026-10-22T17:04:58.123Z WARN  dhcp-client ...`.
    pub fn line(&self) -> String {
        format!(
            "{} {:<5} {:<11} {}",
            rfc3339(self.unix_ms),
            self.level.name().to_uppercase(),
            self.category,
            self.message
        )
    }
}

/// What the writer is told to do.
enum Msg {
    Record(Record),
    Files(FileSettings),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileSettings {
    pub dir: PathBuf,
    pub debug_bytes: u64,
    pub audit_bytes: u64,
}

/// The sinks' shared state.
pub struct Logs {
    tx: SyncSender<Msg>,
    ring: Mutex<VecDeque<Record>>,
    seq: AtomicU64,
    /// Lines lost because the queue was full.
    pub dropped: AtomicU64,
    files: Mutex<Option<FileSettings>>,
    /// The last error opening or writing a file (shown by `ephctl log`).
    pub file_error: Mutex<Option<String>>,
}

static LOGS: OnceLock<Arc<Logs>> = OnceLock::new();

/// The sinks, once [`init`] ran.
pub fn logs() -> Option<&'static Arc<Logs>> {
    LOGS.get()
}

impl Logs {
    fn new() -> (Arc<Logs>, Receiver<Msg>) {
        let (tx, rx) = sync_channel(QUEUE);
        let logs = Arc::new(Logs {
            tx,
            ring: Mutex::new(VecDeque::with_capacity(RING_LINES)),
            seq: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            files: Mutex::new(None),
            file_error: Mutex::new(None),
        });
        (logs, rx)
    }

    fn push(&self, mut r: Record) {
        r.seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        if let Err(TrySendError::Full(_)) = self.tx.try_send(Msg::Record(r)) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Start writing debug.log and audit.log in `dir` (or switch to new
    /// settings). Nothing happens if they're unchanged.
    pub fn set_files(&self, f: FileSettings) {
        let mut cur = self.files.lock().unwrap();
        if cur.as_ref() != Some(&f) {
            *cur = Some(f.clone());
            let _ = self.tx.send(Msg::Files(f));
        }
    }

    /// Recent lines after `after` (a `seq`), at `min` or more severe, in
    /// `category` if given; the newest `limit`, oldest first.
    pub fn recent(
        &self,
        after: u64,
        min: Lvl,
        category: Option<&str>,
        limit: usize,
    ) -> Vec<Record> {
        let ring = self.ring.lock().unwrap();
        let mut out: Vec<Record> = ring
            .iter()
            .rev()
            .filter(|r| r.seq > after && r.level <= min)
            .filter(|r| category.is_none_or(|c| r.category == c))
            .take(limit)
            .cloned()
            .collect();
        out.reverse();
        out
    }
}

/// A file that rotates: past half the limit, it becomes `<name>.1`
/// (replacing the older one) and a new one starts. So the two together
/// never hold much more than the limit.
pub struct RotatingFile {
    path: PathBuf,
    half: u64,
    out: Option<BufWriter<File>>,
    size: u64,
}

impl RotatingFile {
    pub fn open(path: PathBuf, limit: u64) -> std::io::Result<Self> {
        let f = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = f.metadata()?.len();
        Ok(RotatingFile {
            path,
            half: (limit / 2).max(4096),
            out: Some(BufWriter::new(f)),
            size,
        })
    }

    pub fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        if self.size + line.len() as u64 + 1 > self.half && self.size > 0 {
            self.rotate()?;
        }
        let out = self.out.as_mut().expect("open");
        out.write_all(line.as_bytes())?;
        out.write_all(b"\n")?;
        self.size += line.len() as u64 + 1;
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        if let Some(mut out) = self.out.take() {
            out.flush()?;
            let _ = out.get_ref().sync_data();
        }
        let mut old = self.path.clone().into_os_string();
        old.push(".1");
        std::fs::rename(&self.path, &old)?;
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.out = Some(BufWriter::new(f));
        self.size = 0;
        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.out {
            Some(o) => o.flush(),
            None => Ok(()),
        }
    }
}

/// The two files, as the writer has them open.
struct Files {
    debug: Option<RotatingFile>,
    audit: Option<RotatingFile>,
}

fn open_files(f: &FileSettings) -> Result<Files, String> {
    std::fs::create_dir_all(&f.dir).map_err(|e| format!("{}: {e}", f.dir.display()))?;
    let open = |name: &str, limit: u64| {
        RotatingFile::open(f.dir.join(name), limit)
            .map_err(|e| format!("{}: {e}", f.dir.join(name).display()))
    };
    Ok(Files {
        debug: Some(open("debug.log", f.debug_bytes)?),
        audit: Some(open("audit.log", f.audit_bytes)?),
    })
}

/// The writer thread: keeps the ring, writes the files. Lines are flushed
/// to disk when the queue goes quiet (at least once a second); audit lines
/// straight away.
fn writer(logs: Arc<Logs>, rx: Receiver<Msg>) {
    let mut files = Files {
        debug: None,
        audit: None,
    };
    let mut reported_drops = 0u64;
    let fail = |logs: &Logs, e: String| {
        let mut cur = logs.file_error.lock().unwrap();
        if cur.as_deref() != Some(e.as_str()) {
            eprintln!("logging: {e}");
            *cur = Some(e);
        }
    };
    loop {
        let msg = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(m) => m,
            Err(RecvTimeoutError::Timeout) => {
                if let Some(d) = &mut files.debug {
                    let _ = d.flush();
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let r = match msg {
            Msg::Files(f) => {
                match open_files(&f) {
                    Ok(fs) => {
                        files = fs;
                        *logs.file_error.lock().unwrap() = None;
                    }
                    Err(e) => fail(&logs, e),
                }
                continue;
            }
            Msg::Record(r) => r,
        };
        let line = r.line();
        if let Some(d) = &mut files.debug {
            if let Err(e) = d.write_line(&line) {
                fail(&logs, format!("debug.log: {e}"));
            }
        }
        if r.category == AUDIT_TARGET {
            if let Some(a) = &mut files.audit {
                if let Err(e) = a.write_line(&line).and_then(|_| a.flush()) {
                    fail(&logs, format!("audit.log: {e}"));
                }
            }
        }
        {
            let mut ring = logs.ring.lock().unwrap();
            if ring.len() == RING_LINES {
                ring.pop_front();
            }
            ring.push_back(r);
        }
        // Lost lines are said once the writer has room again.
        let dropped = logs.dropped.load(Ordering::Relaxed);
        if dropped > reported_drops && rx.try_recv().is_err() {
            let n = dropped - reported_drops;
            reported_drops = dropped;
            tracing::warn!(target: "system", "logging fell behind: {n} log line(s) were dropped");
        }
    }
    if let Some(d) = &mut files.debug {
        let _ = d.flush();
    }
}

/// Collects an event's message and fields into one string.
#[derive(Default)]
struct Text {
    message: String,
    fields: String,
}

impl Visit for Text {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

/// Category name for a line: its target, or `system` for ephemerisd's own
/// untargeted ones.
fn category_name(meta: &Metadata) -> String {
    let t = meta.target();
    if super::category(t).is_some() {
        t.to_string()
    } else if t.starts_with("ephemerisd") {
        "system".into()
    } else {
        t.split("::").next().unwrap_or(t).to_string()
    }
}

/// Turns events into [`Record`]s for the writer.
struct RecordLayer(Arc<Logs>);

impl<S: Subscriber> Layer<S> for RecordLayer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut t = Text::default();
        event.record(&mut t);
        t.message.push_str(&t.fields);
        // One record, one line, whatever a message carries (ASVS V16.4.1).
        let t = Text {
            message: super::escape_controls(&t.message),
            fields: String::new(),
        };
        self.0.push(Record {
            seq: 0,
            unix_ms: crate::report::unix_ms(),
            level: Lvl::of(event.metadata().level()),
            category: category_name(event.metadata()),
            message: t.message,
        });
    }
}

/// Keeps what the categories' levels allow, and at most `max` (the
/// journal gets info and up; debug goes to the files).
#[derive(Clone, Copy)]
struct CategoryFilter {
    max: Lvl,
}

impl<S> Filter<S> for CategoryFilter {
    fn enabled(&self, meta: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        Lvl::of(meta.level()) <= self.max && control().enabled(meta.target(), meta.level())
    }
    // Levels change at run time: ask every time, don't let tracing cache
    // the answer per call site.
    fn callsite_enabled(&self, _: &'static Metadata<'static>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
}

/// Set up logging for this process: the journal when running under
/// systemd (else stderr), and the writer thread for the files and the
/// ring. The files start once [`Logs::set_files`] says where.
pub fn init() {
    let (logs, rx) = Logs::new();
    let _ = LOGS.set(logs.clone());
    let w = logs.clone();
    std::thread::Builder::new()
        .name("eph-log".into())
        .spawn(move || writer(w, rx))
        .expect("spawning the log writer");

    let journal = journal_layer().map(|l| l.with_filter(CategoryFilter { max: Lvl::Info }));
    let stderr = journal.is_none().then(|| {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(CategoryFilter { max: Lvl::Info })
    });
    tracing_subscriber::registry()
        .with(journal)
        .with(stderr)
        .with(RecordLayer(logs).with_filter(CategoryFilter { max: Lvl::Trace }))
        .init();
}

/// Structured entries straight to journald, when systemd started us.
#[cfg(target_os = "linux")]
fn journal_layer() -> Option<tracing_journald::Layer> {
    std::env::var_os("JOURNAL_STREAM")?;
    tracing_journald::layer()
        .ok()
        .map(|l| l.with_syslog_identifier("ephemerisd".into()))
}

#[cfg(not(target_os = "linux"))]
fn journal_layer() -> Option<tracing_subscriber::layer::Identity> {
    None
}

/// The last `n` lines of `path` and, if needed, its rotated `.1`.
pub fn tail(path: &Path, n: usize) -> std::io::Result<Vec<String>> {
    let read = |p: &Path| -> std::io::Result<Vec<String>> {
        match std::fs::read_to_string(p) {
            Ok(s) => Ok(s.lines().map(str::to_string).collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
            Err(e) => Err(e),
        }
    };
    let mut lines = read(path)?;
    if lines.len() < n {
        let mut old = path.as_os_str().to_owned();
        old.push(".1");
        let mut older = read(Path::new(&old))?;
        older.append(&mut lines);
        lines = older;
    }
    let skip = lines.len().saturating_sub(n);
    Ok(lines.split_off(skip))
}

/// Unix milliseconds as RFC 3339 UTC.
pub fn rfc3339(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        ms % 1000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_793_637_898_123), "2026-11-02T16:44:58.123Z");
        assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn files_rotate_within_their_limit() {
        let dir = std::env::temp_dir().join(format!("eph-log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("debug.log");
        let mut f = RotatingFile::open(path.clone(), 10_000).unwrap();
        let line = "x".repeat(99); // 100 bytes with the newline
        for i in 0..250 {
            f.write_line(&format!("{i:03}{}", &line[3..])).unwrap();
        }
        f.flush().unwrap();
        let size = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        let old = dir.join("debug.log.1");
        assert!(size(&path) <= 5000 && size(&old) <= 5000);
        assert!(size(&path) + size(&old) > 5000, "the older half is kept");
        // The newest lines, across both files, in order.
        let t = tail(&path, 60).unwrap();
        assert_eq!(t.len(), 60);
        assert!(
            t[59].starts_with("249") && t[0].starts_with("190"),
            "{:?}",
            &t[..2]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_ring_filters_and_follows() {
        let (logs, rx) = Logs::new();
        let w = logs.clone();
        let h = std::thread::spawn(move || writer(w, rx));
        for (i, (lvl, c)) in [
            (Lvl::Info, "dhcp-client"),
            (Lvl::Debug, "dhcp-client"),
            (Lvl::Warn, "pppoe"),
        ]
        .into_iter()
        .enumerate()
        {
            logs.push(Record {
                seq: 0,
                unix_ms: i as u64,
                level: lvl,
                category: c.into(),
                message: format!("m{i}"),
            });
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while logs.recent(0, Lvl::Trace, None, 10).len() < 3 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let msgs = |v: Vec<Record>| v.into_iter().map(|r| r.message).collect::<Vec<_>>();
        assert_eq!(msgs(logs.recent(0, Lvl::Info, None, 10)), ["m0", "m2"]);
        assert_eq!(
            msgs(logs.recent(0, Lvl::Trace, Some("dhcp-client"), 10)),
            ["m0", "m1"]
        );
        assert_eq!(
            msgs(logs.recent(2, Lvl::Trace, None, 10)),
            ["m2"],
            "after seq 2"
        );
        assert_eq!(
            msgs(logs.recent(0, Lvl::Trace, None, 1)),
            ["m2"],
            "the newest"
        );
        drop(logs);
        // The writer holds its own reference; it's fine to leave it running.
        drop(h);
    }
}
