use std::fmt;

use zeroize::Zeroize;

use crate::hardening;

pub struct SecureBuf {
    bytes: Vec<u8>,
}

impl SecureBuf {
    pub fn new(bytes: Vec<u8>) -> Self {
        let mut this = Self { bytes };
        this.secure_region();
        this
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn zeroize_now(&mut self) {
        self.bytes.zeroize();
    }

    fn secure_region(&mut self) {
        let _ = hardening::secure_region(self.bytes.as_mut_ptr(), self.bytes.len());
    }
}

impl Drop for SecureBuf {
    fn drop(&mut self) {
        self.zeroize_now();
        hardening::release_secure_region(self.bytes.as_mut_ptr(), self.bytes.len());
    }
}

impl fmt::Debug for SecureBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureBuf")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
