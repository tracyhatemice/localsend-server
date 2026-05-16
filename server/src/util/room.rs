/// Validates a room code per the protocol rules:
/// - 4..=64 characters
/// - charset `[A-Za-z0-9_-]` (no whitespace, no trimming)
///
/// Returns `Ok(s)` on success, `Err(())` on any violation.
pub(crate) fn validate_room_code(s: &str) -> Result<&str, ()> {
    let len = s.len();
    if !(4..=64).contains(&len) {
        return Err(());
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_codes() {
        assert!(validate_room_code("abcd").is_ok());
        assert!(validate_room_code("ABC-123_xyz").is_ok());
        assert!(validate_room_code(&"a".repeat(64)).is_ok());
        assert!(validate_room_code("a-_0Z").is_ok());
    }

    #[test]
    fn rejects_too_short() {
        assert!(validate_room_code("").is_err());
        assert!(validate_room_code("abc").is_err());
    }

    #[test]
    fn rejects_too_long() {
        assert!(validate_room_code(&"a".repeat(65)).is_err());
    }

    #[test]
    fn rejects_invalid_chars() {
        assert!(validate_room_code("abc d").is_err());     // mid space
        assert!(validate_room_code(" abcd").is_err());     // leading space
        assert!(validate_room_code("abcd ").is_err());     // trailing space
        assert!(validate_room_code("abc.def").is_err());
        assert!(validate_room_code("abc/def").is_err());
        assert!(validate_room_code("abc:def").is_err());
        assert!(validate_room_code("abc=def").is_err());
        assert!(validate_room_code("abc\tdef").is_err());
    }
}
