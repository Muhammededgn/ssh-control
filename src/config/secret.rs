use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A credential string that wipes its heap buffer when dropped.
///
/// Every copy of a password or key passphrase — the one deserialized out of the
/// vault, the one a form produces, the one a connect flow carries — goes
/// through this type, so no plaintext credential is left behind in freed heap
/// memory. Plain `String` deliberately does not appear anywhere in
/// `config::model` for this reason.
///
/// **The serialized form is a bare JSON string**, identical to what a plain
/// `String` field produced before this type existed. That is load-bearing:
/// changing it would make every already-written vault fail to deserialize
/// after decryption, and there is no backup copy of the vault.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// The bridge from a form buffer to a stored credential. Screens accumulate
/// keystrokes in a `Zeroizing<String>`, and this is how that buffer becomes the
/// `Secret` that goes into the vault.
///
/// Takes a reference rather than the value on purpose: `Zeroizing` has no
/// `into_inner`, so a by-value impl would have to copy the string out anyway —
/// it would buy ergonomics, not one fewer copy. Borrowing instead lets callers
/// keep their buffer and drops a `.clone()` at the call site.
impl From<&Zeroizing<String>> for Secret {
    fn from(s: &Zeroizing<String>) -> Self {
        Self(s.as_str().to_owned())
    }
}

impl Deref for Secret {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

/// Redacted, like the hand-written `Debug` impls in `config::model` — a
/// credential must never reach a log line or a panic message. There is
/// deliberately no `Display`: that would let a secret slip into a format
/// string without anyone writing `as_str`.
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(String::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_as_a_bare_string() {
        let secret = Secret::from("hunter2".to_string());
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"hunter2\"");
    }

    #[test]
    fn round_trips_through_json() {
        let json = "\"correct horse battery staple\"";
        let secret: Secret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.as_str(), "correct horse battery staple");
        assert_eq!(serde_json::to_string(&secret).unwrap(), json);
    }

    #[test]
    fn debug_output_is_redacted() {
        let secret = Secret::from("hunter2".to_string());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "<redacted>");
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn converts_from_a_zeroizing_form_buffer() {
        let buffer = Zeroizing::new("hunter2".to_string());
        let secret = Secret::from(&buffer);
        assert_eq!(secret.as_str(), "hunter2");
        // The caller keeps its buffer — that is the point of borrowing.
        assert_eq!(buffer.as_str(), "hunter2");
    }

    #[test]
    fn zeroize_clears_the_buffer() {
        let mut secret = Secret::from("hunter2".to_string());
        secret.zeroize();
        assert!(secret.is_empty());
    }
}
