use std::fs::File;
use std::io::Read;

pub fn generate() -> Result<String, String> {
    let mut buf = [0u8; 16];
    let mut f =
        File::open("/dev/urandom").map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
    f.read_exact(&mut buf)
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;

    let mut hex = String::with_capacity(32);
    for byte in &buf {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_32_char_hex_string() {
        let id = generate().expect("session ID generation failed");
        assert_eq!(id.len(), 32, "session ID should be 32 characters");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "session ID should contain only hex digits"
        );
    }

    #[test]
    fn generates_unique_ids() {
        let id1 = generate().expect("first session ID generation failed");
        let id2 = generate().expect("second session ID generation failed");
        assert_ne!(id1, id2, "generated session IDs should be unique");
    }
}
