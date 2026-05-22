use super::HardeningStatus;

pub fn harden_process() -> HardeningStatus {
    let mut status = HardeningStatus::default();
    status.unsupported("setrlimit_core_zero");
    status.unsupported("prctl_set_dumpable_zero");
    status
}

pub fn secure_region(ptr: *mut u8, len: usize) -> HardeningStatus {
    let mut status = HardeningStatus::default();
    if ptr.is_null() || len == 0 {
        return status;
    }

    status.unsupported("virtual_lock");
    status
}

pub fn release_secure_region(_ptr: *mut u8, _len: usize) {}
