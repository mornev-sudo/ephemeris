//! Logins: the admin password, web sessions, and limits on guessing.
//!
//! There's one administrator. Their password is stored as a yescrypt hash
//! (`$y$...`, the format Debian's /etc/shadow uses), so the same hash serves
//! console/SSH login as `root` and web login as `admin`. yescrypt is slow
//! and memory-hard on purpose: a stolen hash is expensive to guess at
//! (ASVS V11.4.2). Older SHA-512 crypt hashes (`$6$`) still work, and are
//! replaced by yescrypt at the next successful login. It lives in
//! `/var/lib/ephemeris/admin.hash`, and the router's `/etc/shadow` is a bind
//! mount of `/var/lib/ephemeris/shadow` (the root filesystem is read-only).
//!
//! Web sessions are random 256-bit tokens in an HttpOnly cookie, kept in
//! memory: restarting ephemerisd logs everyone out, which is fine. A session
//! ends after [`SESSION_IDLE`] without use or [`SESSION_LIFETIME`] in all,
//! and every session ends when the password changes.
//!
//! [`LoginThrottle`] locks out an address after repeated wrong passwords,
//! and slows everyone down when wrong passwords arrive from many addresses
//! at once.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const SESSION_COOKIE: &str = "eph_session";
pub const SESSION_LIFETIME: Duration = Duration::from_secs(12 * 3600);
pub const SESSION_IDLE: Duration = Duration::from_secs(30 * 60);
/// Web sessions at once; the oldest is ended to make room.
pub const MAX_SESSIONS: usize = 16;
pub const MIN_PASSWORD_LEN: usize = 10;
/// What crypt(3) accepts (libxcrypt's limit is 512 bytes).
pub const MAX_PASSWORD_LEN: usize = 256;

struct Session {
    created: Instant,
    last_used: Instant,
}

impl Session {
    fn live(&self, now: Instant) -> bool {
        now.duration_since(self.created) < SESSION_LIFETIME
            && now.duration_since(self.last_used) < SESSION_IDLE
    }
}

pub struct Auth {
    /// Normally /var/lib/ephemeris.
    pub state_dir: PathBuf,
    sessions: Mutex<HashMap<String, Session>>,
    pub throttle: LoginThrottle,
    /// Development portal on a non-Linux machine only (no crypt there).
    #[cfg(not(target_os = "linux"))]
    pub dev_password: Option<String>,
}

impl Auth {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Auth {
            state_dir: state_dir.into(),
            sessions: Mutex::new(HashMap::new()),
            throttle: LoginThrottle::default(),
            #[cfg(not(target_os = "linux"))]
            dev_password: None,
        }
    }

    fn hash_path(&self) -> PathBuf {
        self.state_dir.join("admin.hash")
    }

    /// Check the admin password. Always takes about the same time, whether or
    /// not a hash exists, so timing doesn't reveal anything.
    pub fn check_password(&self, password: &str) -> bool {
        if password.len() > MAX_PASSWORD_LEN {
            return false; // can't be it: set_password refuses longer ones
        }
        #[cfg(not(target_os = "linux"))]
        if let Some(p) = &self.dev_password {
            return crate::mgmt::constant_time_eq(p.as_bytes(), password.as_bytes());
        }
        let stored = std::fs::read_to_string(self.hash_path()).unwrap_or_default();
        let stored = stored.trim();
        if stored.is_empty() {
            // No password set: do the same work anyway, then refuse.
            static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
            let dummy = DUMMY.get_or_init(|| {
                crypt::hash(&random_hex(16).unwrap_or_default()).unwrap_or_default()
            });
            let _ = crypt::verify(password, dummy);
            return false;
        }
        let ok = crypt::verify(password, stored);
        if ok && crypt::needs_upgrade(stored) {
            // The password is right and we have it in hand: store it the
            // stronger way. Sessions stay; nothing about the password changed.
            match crypt::hash(password).and_then(|h| self.store_hash(&h)) {
                Ok(()) => tracing::info!(target: crate::logging::cat::AUDIT,
                    "admin password hash upgraded to yescrypt"),
                Err(e) => tracing::warn!(target: crate::logging::cat::AUDIT,
                    "could not upgrade the admin password hash: {e:#}"),
            }
        }
        ok
    }

    /// Save `hash` as the admin's: the web login hash and root's
    /// /etc/shadow entry.
    fn store_hash(&self, hash: &str) -> Result<()> {
        write_private(&self.hash_path(), &format!("{hash}\n"))?;
        let shadow = self.state_dir.join("shadow");
        if shadow.exists() {
            set_shadow_hash(&shadow, "root", hash)?;
        }
        Ok(())
    }

    /// Set a new admin password: the web login hash and root's /etc/shadow
    /// entry. Every web session ends: whoever knew the old password must not
    /// stay logged in.
    pub fn set_password(&self, password: &str) -> Result<()> {
        if password.chars().count() < MIN_PASSWORD_LEN {
            bail!("the password must be at least {MIN_PASSWORD_LEN} characters");
        }
        if let Some(why) = weak_password(password) {
            bail!("that password is too easy to guess: {why}");
        }
        if password.len() > MAX_PASSWORD_LEN {
            bail!("the password must be at most {MAX_PASSWORD_LEN} bytes");
        }
        self.store_hash(&crypt::hash(password)?)?;
        self.end_all_sessions();
        Ok(())
    }

    pub fn new_session(&self) -> Result<String> {
        let token = random_hex(32)?;
        let mut s = self.sessions.lock().unwrap();
        let now = Instant::now();
        s.retain(|_, x| x.live(now));
        while s.len() >= MAX_SESSIONS {
            let Some(oldest) = s
                .iter()
                .min_by_key(|(_, x)| x.last_used)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            s.remove(&oldest);
        }
        s.insert(
            token.clone(),
            Session {
                created: now,
                last_used: now,
            },
        );
        Ok(token)
    }

    /// Is `token` a live session? Using it keeps it alive (idle timeout).
    pub fn session_valid(&self, token: &str) -> bool {
        let mut s = self.sessions.lock().unwrap();
        let now = Instant::now();
        match s.get_mut(token) {
            Some(x) if x.live(now) => {
                x.last_used = now;
                true
            }
            Some(_) => {
                s.remove(token);
                false
            }
            None => false,
        }
    }

    pub fn end_session(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }

    pub fn end_all_sessions(&self) {
        self.sessions.lock().unwrap().clear();
    }
}

/// Words that make up a large share of guessed passwords, and the obvious
/// ones for this device. A password that is one of these (or one repeated)
/// with digits and symbols around it is refused.
const COMMON_WORDS: &[&str] = &[
    "password",
    "passw0rd",
    "p@ssword",
    "p@ssw0rd",
    "admin",
    "administrator",
    "root",
    "router",
    "ephemeris",
    "letmein",
    "welcome",
    "changeme",
    "default",
    "secret",
    "master",
    "qwerty",
    "iloveyou",
    "dragon",
    "monkey",
    "football",
    "baseball",
    "sunshine",
    "princess",
    "superman",
    "batman",
    "trustno1",
    "login",
    "access",
    "shadow",
    "michael",
    "jennifer",
    "charlie",
    "computer",
    "internet",
    "network",
    "firewall",
    "abc",
    "test",
    "guest",
    "user",
];

/// Rows and diagonals people walk along on a keyboard.
const KEYBOARD_WALKS: &[&str] = &[
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "1qaz2wsx3edc4rfv5tgb",
    "qazwsxedcrfvtgb",
    "zaq12wsxcde34rfv",
    "1q2w3e4r5t6y7u8i9o0p",
];

/// Why `pw` is too easy to guess, if it is (ASVS V6.2.4: refuse common
/// passwords). Not a full breach-list check: rules that catch the patterns
/// those lists are full of, on top of the length minimum.
pub fn weak_password(pw: &str) -> Option<&'static str> {
    let lower = pw.to_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    if chars.windows(2).all(|w| w[0] == w[1]) {
        return Some("one character repeated");
    }
    let steps: Vec<i64> = chars
        .windows(2)
        .map(|w| w[1] as i64 - w[0] as i64)
        .collect();
    if steps.iter().all(|&d| d == 1) || steps.iter().all(|&d| d == -1) {
        return Some("a run of characters like 1234567890 or abcdefghij");
    }
    let compact: String = lower.chars().filter(|c| c.is_alphanumeric()).collect();
    for walk in KEYBOARD_WALKS {
        let rev: String = walk.chars().rev().collect();
        if compact.len() >= 6 && (walk.contains(&compact) || rev.contains(&compact)) {
            return Some("a walk along the keyboard");
        }
    }
    // The letters left once leading and trailing digits and symbols go.
    let core = lower.trim_matches(|c: char| !c.is_alphabetic());
    let core_compact: String = core
        .chars()
        .filter(|c| c.is_alphanumeric() || "@$".contains(*c))
        .collect();
    for w in COMMON_WORDS {
        let n = core_compact.len() / w.len().max(1);
        if !core_compact.is_empty() && n >= 1 && core_compact == w.repeat(n) {
            return Some("a common word with digits or symbols added");
        }
    }
    None
}

/// Hash a password the way the admin password is stored (yescrypt); used
/// by first boot (`ephemerisd --hash-password`).
pub fn hash_password(password: &str) -> Result<String> {
    crypt::hash(password)
}

/// Wrong passwords from one address before it's locked out...
const MAX_FAILURES: u32 = 5;
/// ...within this long...
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// ...and for how long.
const LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Wrong passwords per minute from everywhere together before all web
/// logins pause for the rest of that minute (many addresses guessing).
const GLOBAL_FAILURES_PER_MINUTE: u32 = 30;
/// Addresses remembered; the stalest are forgotten first.
const MAX_TRACKED: usize = 4096;

#[derive(Clone, Copy)]
struct Failures {
    count: u32,
    first: Instant,
    locked_until: Option<Instant>,
}

#[derive(Default)]
struct ThrottleState {
    by_ip: HashMap<IpAddr, Failures>,
    minute_start: Option<Instant>,
    minute_failures: u32,
}

/// Brute-force protection for web logins.
#[derive(Default)]
pub struct LoginThrottle {
    state: Mutex<ThrottleState>,
}

impl LoginThrottle {
    /// May `ip` try a password now? `Err(wait)` if not.
    pub fn check(&self, ip: IpAddr) -> Result<(), Duration> {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let st = self.state.lock().unwrap();
        if let Some(until) = st.by_ip.get(&ip).and_then(|f| f.locked_until) {
            if until > now {
                return Err(until - now);
            }
        }
        if let Some(start) = st.minute_start {
            let minute = Duration::from_secs(60);
            if now.duration_since(start) < minute
                && st.minute_failures >= GLOBAL_FAILURES_PER_MINUTE
            {
                return Err(minute - now.duration_since(start));
            }
        }
        Ok(())
    }

    /// A wrong password from `ip`. True if that just locked it out.
    pub fn failed(&self, ip: IpAddr) -> bool {
        self.failed_at(ip, Instant::now())
    }

    fn failed_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut st = self.state.lock().unwrap();
        match st.minute_start {
            Some(s) if now.duration_since(s) < Duration::from_secs(60) => {
                st.minute_failures += 1;
            }
            _ => {
                st.minute_start = Some(now);
                st.minute_failures = 1;
            }
        }
        if st.by_ip.len() >= MAX_TRACKED && !st.by_ip.contains_key(&ip) {
            st.by_ip.retain(|_, f| {
                now.duration_since(f.first) < FAILURE_WINDOW
                    || f.locked_until.is_some_and(|u| u > now)
            });
            if st.by_ip.len() >= MAX_TRACKED {
                let stalest = st
                    .by_ip
                    .iter()
                    .min_by_key(|(_, f)| f.first)
                    .map(|(k, _)| *k);
                if let Some(k) = stalest {
                    st.by_ip.remove(&k);
                }
            }
        }
        let f = st.by_ip.entry(ip).or_insert(Failures {
            count: 0,
            first: now,
            locked_until: None,
        });
        if now.duration_since(f.first) >= FAILURE_WINDOW {
            *f = Failures {
                count: 0,
                first: now,
                locked_until: None,
            };
        }
        f.count += 1;
        if f.count >= MAX_FAILURES {
            f.locked_until = Some(now + LOCKOUT);
            f.count = 0;
            f.first = now;
            return true;
        }
        false
    }

    /// The right password: forget that address's failures.
    pub fn succeeded(&self, ip: IpAddr) {
        self.state.lock().unwrap().by_ip.remove(&ip);
    }
}

/// Replace one user's hash in a shadow file, *in place*. The file is
/// bind-mounted over /etc/shadow, so it must keep its inode (no rename).
fn set_shadow_hash(path: &Path, user: &str, hash: &str) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut found = false;
    let out: Vec<String> = text
        .lines()
        .map(|l| {
            let mut f: Vec<&str> = l.split(':').collect();
            if f.len() >= 2 && f[0] == user {
                found = true;
                f[1] = hash;
            }
            f.join(":")
        })
        .collect();
    if !found {
        bail!("no {user} entry in {}", path.display());
    }
    let text = out.join("\n") + "\n";
    // It can't be replaced by a rename, so save a complete copy first: if
    // the power goes during the in-place write, shadow-setup restores the
    // copy at boot.
    crate::files::write_private_atomic(&backup_path(path), text.as_bytes())?;
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// shadow -> shadow.bak, next to it.
fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".bak");
    path.with_file_name(name)
}

fn write_private(path: &Path, text: &str) -> Result<()> {
    crate::files::write_private_atomic(path, text.as_bytes())
}

pub fn random_hex(bytes: usize) -> Result<String> {
    let mut b = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Password hashing via the system's crypt(3) (libxcrypt on Debian): the same
/// code that checks console logins against /etc/shadow.
#[cfg(target_os = "linux")]
mod crypt {
    use anyhow::{bail, Result};
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
    use std::sync::Mutex;

    #[link(name = "crypt")]
    extern "C" {
        fn crypt(key: *const c_char, setting: *const c_char) -> *mut c_char;
        fn crypt_gensalt_rn(
            prefix: *const c_char,
            count: std::os::raw::c_ulong,
            rbytes: *const c_char,
            nrbytes: std::os::raw::c_int,
            output: *mut c_char,
            output_size: std::os::raw::c_int,
        ) -> *mut c_char;
    }

    /// yescrypt: what Debian uses for /etc/shadow.
    const PREFIX: &str = "$y$";

    // crypt() returns a pointer to a static buffer: one caller at a time.
    static LOCK: Mutex<()> = Mutex::new(());

    fn run(key: &str, setting: &str) -> Option<String> {
        let (k, s) = (CString::new(key).ok()?, CString::new(setting).ok()?);
        let _g = LOCK.lock().unwrap();
        // SAFETY: both arguments are NUL-terminated and live for the call;
        // LOCK makes us the only caller, so the static buffer it returns
        // isn't overwritten while we read it.
        let p = unsafe { crypt(k.as_ptr(), s.as_ptr()) };
        if p.is_null() {
            return None;
        }
        // SAFETY: non-null, NUL-terminated by crypt(), and still ours (LOCK
        // is held until after the copy).
        let out = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        (!out.starts_with('*')).then_some(out) // "*0"/"*1" mean failure
    }

    /// A new yescrypt hash of `password`, with a fresh random salt and
    /// libxcrypt's default cost.
    pub fn hash(password: &str) -> Result<String> {
        let mut salt = [0u8; 32];
        std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut salt)?;
        let prefix = CString::new(PREFIX)?;
        let mut setting = [0 as c_char; 128];
        // SAFETY: `prefix` is NUL-terminated, `salt` holds the 32 bytes
        // passed, and `setting` is a buffer we own of the size passed; the
        // result is written there (the _rn variant uses no static state).
        let p = unsafe {
            crypt_gensalt_rn(
                prefix.as_ptr(),
                0,
                salt.as_ptr() as *const c_char,
                salt.len() as _,
                setting.as_mut_ptr(),
                setting.len() as _,
            )
        };
        if p.is_null() {
            bail!(
                "crypt_gensalt() failed: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: non-null means libxcrypt wrote a NUL-terminated setting
        // into `setting`, which is still alive.
        let setting = unsafe { CStr::from_ptr(setting.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        match run(password, &setting) {
            Some(h) if h.starts_with(PREFIX) => Ok(h),
            _ => bail!("crypt() failed"),
        }
    }

    /// Stored the old way (SHA-512 crypt, or anything not yescrypt)?
    pub fn needs_upgrade(hash: &str) -> bool {
        !hash.starts_with(PREFIX)
    }

    pub fn verify(password: &str, hash: &str) -> bool {
        run(password, hash)
            .is_some_and(|h| crate::mgmt::constant_time_eq(h.as_bytes(), hash.as_bytes()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::mgmt::auth::Auth;

        #[test]
        fn yescrypt_hashes_and_old_ones_still_verify() {
            let h = hash("correct horse battery").unwrap();
            assert!(h.starts_with("$y$"), "{h}");
            assert!(verify("correct horse battery", &h));
            assert!(!verify("wrong horse battery", &h));
            assert_ne!(
                h,
                hash("correct horse battery").unwrap(),
                "a fresh salt each time"
            );
            let old = run("correct horse battery", "$6$abcdefgh$").unwrap();
            assert!(verify("correct horse battery", &old) && needs_upgrade(&old));
            assert!(!needs_upgrade(&h));
        }

        #[test]
        fn an_old_hash_is_upgraded_at_login_and_sessions_stay() {
            let dir = std::env::temp_dir().join(format!("eph-auth-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let old = run("correct horse battery", "$6$abcdefgh$").unwrap();
            std::fs::write(dir.join("admin.hash"), format!("{old}\n")).unwrap();
            std::fs::write(
                dir.join("shadow"),
                format!("root:{old}:19000:0:99999:7:::\n"),
            )
            .unwrap();
            let a = Auth::new(&dir);
            let session = a.new_session().unwrap();
            assert!(
                !a.check_password("wrong"),
                "a wrong password changes nothing"
            );
            assert_eq!(
                std::fs::read_to_string(dir.join("admin.hash"))
                    .unwrap()
                    .trim(),
                old
            );
            assert!(a.check_password("correct horse battery"));
            let new = std::fs::read_to_string(dir.join("admin.hash")).unwrap();
            assert!(new.starts_with("$y$"), "{new}");
            assert!(std::fs::read_to_string(dir.join("shadow"))
                .unwrap()
                .starts_with("root:$y$"));
            assert!(
                a.check_password("correct horse battery"),
                "still the same password"
            );
            assert!(a.session_valid(&session), "nobody logged out");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}

/// Elsewhere (developer machines): no logins.
#[cfg(not(target_os = "linux"))]
mod crypt {
    pub fn hash(_: &str) -> anyhow::Result<String> {
        anyhow::bail!("password hashing needs Linux")
    }
    pub fn verify(_: &str, _: &str) -> bool {
        false
    }
    pub fn needs_upgrade(_: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn easy_passwords_are_refused() {
        for weak in [
            "aaaaaaaaaaaa",
            "1234567890",
            "0987654321",
            "abcdefghijk",
            "qwertyuiop",
            "asdfghjkl;'",
            "1qaz2wsx3edc",
            "Password123!",
            "P@ssw0rd2026",
            "admin2026!!",
            "ephemeris1234",
            "adminadmin12",
            "!!Welcome2026",
            "iloveyou1234",
        ] {
            assert!(weak_password(weak).is_some(), "{weak} should be refused");
        }
        for fine in [
            "correct horse battery staple",
            "Tq9-xR4m-Lp2v-Wk7d",
            "my router lives in the attic",
            "passwordless-login-is-nice", // contains a common word, but isn't just it
            "qwertyuiop is not my password",
        ] {
            assert_eq!(weak_password(fine), None, "{fine} should be accepted");
        }
        let a = Auth::new(std::env::temp_dir());
        let e = a.set_password("Password123!").unwrap_err().to_string();
        assert!(e.contains("too easy to guess"), "{e}");
    }

    #[test]
    fn shadow_edit_keeps_other_entries() {
        let dir = std::env::temp_dir().join(format!("eph-shadow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("shadow");
        std::fs::write(
            &p,
            "root:*:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n",
        )
        .unwrap();
        set_shadow_hash(&p, "root", "$6$abc$def").unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "root:$6$abc$def:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("shadow.bak")).unwrap(),
            std::fs::read_to_string(&p).unwrap(),
            "a complete copy for crash recovery"
        );
        assert!(set_shadow_hash(&p, "nobody", "x").is_err());
    }

    #[test]
    fn repeated_wrong_passwords_lock_an_address_out() {
        let t = LoginThrottle::default();
        let (a, b): (IpAddr, IpAddr) = ("192.0.2.7".parse().unwrap(), "192.0.2.8".parse().unwrap());
        let now = Instant::now();
        for _ in 0..MAX_FAILURES - 1 {
            assert!(t.check_at(a, now).is_ok());
            assert!(!t.failed_at(a, now));
        }
        assert!(t.failed_at(a, now), "locked out");
        assert!(t.check_at(a, now).is_err());
        assert!(t.check_at(b, now).is_ok(), "others are unaffected");
        assert!(t.check_at(a, now + LOCKOUT).is_ok(), "the lockout ends");
        // A success clears the count.
        t.failed_at(b, now);
        t.succeeded(b);
        assert!(!t.state.lock().unwrap().by_ip.contains_key(&b));
    }

    #[test]
    fn many_addresses_guessing_pause_all_logins() {
        let t = LoginThrottle::default();
        let now = Instant::now();
        for i in 0..GLOBAL_FAILURES_PER_MINUTE {
            let ip = IpAddr::from([198, 51, 100, i as u8]);
            t.failed_at(ip, now);
        }
        let fresh = IpAddr::from([203, 0, 113, 1]);
        assert!(t.check_at(fresh, now).is_err());
        assert!(t.check_at(fresh, now + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn sessions_are_limited_and_end_with_a_password_change() {
        let a = Auth::new(std::env::temp_dir());
        let first = a.new_session().unwrap();
        for _ in 0..MAX_SESSIONS {
            a.new_session().unwrap();
        }
        assert!(!a.session_valid(&first), "oldest ended to make room");
        let t = a.new_session().unwrap();
        a.end_all_sessions();
        assert!(!a.session_valid(&t));
    }

    #[test]
    fn idle_sessions_expire() {
        let s = Session {
            created: Instant::now(),
            last_used: Instant::now(),
        };
        let later = Instant::now() + SESSION_IDLE;
        assert!(!s.live(later));
        assert!(s.live(Instant::now()));
    }

    #[test]
    fn sessions_expire_and_end() {
        let a = Auth::new(std::env::temp_dir());
        let t = a.new_session().unwrap();
        assert!(a.session_valid(&t));
        assert!(!a.session_valid("nope"));
        a.end_session(&t);
        assert!(!a.session_valid(&t));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn crypt_round_trip() {
        let h = crypt::hash("correct horse battery").unwrap();
        assert!(h.starts_with("$6$"));
        assert!(crypt::verify("correct horse battery", &h));
        assert!(!crypt::verify("wrong", &h));
    }
}
