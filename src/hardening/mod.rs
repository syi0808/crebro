#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HardeningStatus {
    pub attempted: Vec<&'static str>,
    pub succeeded: Vec<&'static str>,
    pub unsupported: Vec<&'static str>,
    pub failed: Vec<HardeningFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardeningFailure {
    pub operation: &'static str,
    pub reason: String,
}

impl HardeningStatus {
    fn attempt(&mut self, operation: &'static str) {
        self.attempted.push(operation);
    }

    fn success(&mut self, operation: &'static str) {
        self.succeeded.push(operation);
    }

    fn unsupported(&mut self, operation: &'static str) {
        self.unsupported.push(operation);
    }

    fn failure(&mut self, operation: &'static str, reason: impl Into<String>) {
        self.failed.push(HardeningFailure {
            operation,
            reason: reason.into(),
        });
    }
}

pub fn harden_process() -> HardeningStatus {
    #[cfg(unix)]
    {
        return unix::harden_process();
    }

    #[cfg(windows)]
    {
        return windows::harden_process();
    }

    #[allow(unreachable_code)]
    {
        let mut status = HardeningStatus::default();
        status.unsupported("process_hardening");
        status
    }
}

pub fn secure_region(ptr: *mut u8, len: usize) -> HardeningStatus {
    #[cfg(unix)]
    {
        return unix::secure_region(ptr, len);
    }

    #[cfg(windows)]
    {
        return windows::secure_region(ptr, len);
    }

    #[allow(unreachable_code)]
    {
        let mut status = HardeningStatus::default();
        let _ = (ptr, len);
        status.unsupported("secure_region");
        status
    }
}

pub fn release_secure_region(ptr: *mut u8, len: usize) {
    #[cfg(unix)]
    unix::release_secure_region(ptr, len);

    #[cfg(windows)]
    windows::release_secure_region(ptr, len);

    #[cfg(not(any(unix, windows)))]
    let _ = (ptr, len);
}
