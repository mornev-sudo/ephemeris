//! Logins: the admin password, web sessions, and limits on guessing.
//!
//! There's one administrator. Their password is stored as a SHA-512 crypt
//! hash (`$6$salt$hash`, the format /etc/shadow uses), so the same hash
//! serves console/SSH login as `root` and web login as `admin`. It lives in
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
        crypt::verify(password, stored)
    }

    /// Set a new admin password: the web login hash and root's /etc/shadow
    /// entry. Every web session ends: whoever knew the old password must not
    /// stay logged in.
    pub fn set_password(&self, password: &str) -> Result<()> {
        if password.chars().count() < MIN_PASSWORD_LEN {
            bail!("the password must be at least {MIN_PASSWORD_LEN} characters");
        }
        if password.len() > MAX_PASSWORD_LEN {
            bail!("the password must be at most {MAX_PASSWORD_LEN} bytes");
        }
        let hash = crypt::hash(password)?;
        write_private(&self.hash_path(), &format!("{hash}\n"))?;
        let shadow = self.state_dir.join("shadow");
        if shadow.exists() {
            set_shadow_hash(&shadow, "root", &hash)?;
        }
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
    }

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

    pub fn hash(password: &str) -> Result<String> {
        const ALPHABET: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut bytes = [0u8; 16];
        std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut bytes)?;
        let salt: String = bytes
            .iter()
            .map(|b| ALPHABET[(b % 64) as usize] as char)
            .collect();
        match run(password, &format!("$6${salt}$")) {
            Some(h) => Ok(h),
            None => bail!("crypt() failed"),
        }
    }

    pub fn verify(password: &str, hash: &str) -> bool {
        run(password, hash)
            .is_some_and(|h| crate::mgmt::constant_time_eq(h.as_bytes(), hash.as_bytes()))
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
