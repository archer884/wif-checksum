//! Validate the checksum of a prospective WIF key.

use base58::FromBase58;
use sha2::{Digest, Sha256};

pub type Result<T, E = base58::FromBase58Error> = std::result::Result<T, E>;

pub trait HasBytes {
    fn as_bytes(&self) -> &[u8];
}

impl HasBytes for [u8] {
    fn as_bytes(&self) -> &[u8] {
        todo!()
    }
}

impl<T: AsRef<str>> HasBytes for T {
    fn as_bytes(&self) -> &[u8] {
        self.as_ref().as_bytes()
    }
}

pub fn validate_checksum(key: &impl HasBytes) -> Result<bool> {
    let key = key.as_bytes().from_base58()?;
    let (key, checksum) = key.split_at(key.len() - 4);
    let a = hash(key);
    let b = hash(&a);
    let candidate_checksum = &b[..4];
    Ok(checksum == candidate_checksum)
}

fn hash(bytes: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(bytes);
    let hash = digest.finalize();
    hash.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use crate::validate_checksum;

    #[test]
    fn validate_checksum_works() {
        // This is a real private key, but there is no money in it. Feel free to donate.
        let test_key = "L2v6wDTptVRhwDTbK9XaJGBQ8Dbv5npMJwD4mJ7KwGYqS2ZFJptE";
        assert!(validate_checksum(&test_key).unwrap_or_default());
    }
}
