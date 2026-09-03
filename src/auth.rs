use chrono::Utc;
use ring::hmac;

pub struct Auth;

impl Auth {
    /// Generate an HMAC-SHA256 signature for a specific action, PID, start_time, and timestamp
    pub fn sign_action(
        secret: &str,
        action: &str,
        pid: u32,
        start_time: u64,
        timestamp: i64,
    ) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let msg = format!("{}:{}:{}:{}", action, pid, start_time, timestamp);
        let tag = hmac::sign(&key, msg.as_bytes());
        hex_encode(tag.as_ref())
    }

    /// Verify an HMAC-SHA256 signature and enforce max-age expiry (default 15 mins)
    pub fn verify_signature(
        secret: &str,
        action: &str,
        pid: u32,
        start_time: u64,
        timestamp: i64,
        signature: &str,
        max_age_secs: i64,
    ) -> bool {
        let now = Utc::now().timestamp();
        // Disallow signatures from the future (> 60s skew) or older than max_age_secs
        if timestamp > now + 60 || now - timestamp > max_age_secs {
            return false;
        }

        let sig_bytes = match hex_decode(signature) {
            Some(b) => b,
            None => return false,
        };

        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let msg = format!("{}:{}:{}:{}", action, pid, start_time, timestamp);
        hmac::verify(&key, msg.as_bytes(), &sig_bytes).is_ok()
    }

    /// Combined validator supporting both HMAC signed action tokens and static master auth token
    pub fn is_authorized(
        master_secret: &str,
        action: &str,
        pid: Option<u32>,
        start_time: Option<u64>,
        timestamp: Option<i64>,
        token: &str,
    ) -> bool {
        if token.is_empty() {
            return false;
        }

        // 1. Direct master token check (Constant-time equality)
        if constant_time_compare(master_secret.as_bytes(), token.as_bytes()) {
            return true;
        }

        // 2. HMAC Expiring Signature check
        if let (Some(p), Some(st), Some(ts)) = (pid, start_time, timestamp) {
            return Self::verify_signature(master_secret, action, p, st, ts, token, 7200);
            // 2 hours (aligned with alert cooldown)
        }

        false
    }
}

/// Constant time slice comparison to prevent timing attacks
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Fast hex encoder
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Hex decoder
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if (s.len() & 1) != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

/// HTML entity sanitizer to prevent Stored & Reflected XSS
pub fn escape_html(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(c),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sign_and_verify() {
        let secret = "ep-maniac-secret-token";
        let action = "kill";
        let pid = 12345;
        let st = 1779283000;
        let now = Utc::now().timestamp();

        let sig = Auth::sign_action(secret, action, pid, st, now);
        assert!(Auth::verify_signature(
            secret, action, pid, st, now, &sig, 7200
        ));

        // Wrong secret
        assert!(!Auth::verify_signature(
            "wrong-secret",
            action,
            pid,
            st,
            now,
            &sig,
            7200
        ));

        // Tampered PID
        assert!(!Auth::verify_signature(
            secret, action, 54321, st, now, &sig, 7200
        ));

        // Expired signature
        let old_ts = now - 7500; // 7500s ago (> 7200s)
        let old_sig = Auth::sign_action(secret, action, pid, st, old_ts);
        assert!(!Auth::verify_signature(
            secret, action, pid, st, old_ts, &old_sig, 7200
        ));
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(b"secret-token", b"secret-token"));
        assert!(!constant_time_compare(b"secret-token", b"secret-tokeX"));
        assert!(!constant_time_compare(b"secret-token", b"short"));
    }

    #[test]
    fn test_escape_html() {
        let xss = "<script>alert('XSS & \"injection\"')</script>";
        let escaped = escape_html(xss);
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&#39;XSS &amp; &quot;injection&quot;&#39;)&lt;/script&gt;"
        );
    }
}
