use super::HardeningStatus;

pub fn harden_process() -> HardeningStatus {
    let mut status = HardeningStatus::default();

    status.attempt("setrlimit_core_zero");
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc == 0 {
        status.success("setrlimit_core_zero");
    } else {
        status.failure(
            "setrlimit_core_zero",
            std::io::Error::last_os_error().to_string(),
        );
    }

    #[cfg(target_os = "linux")]
    {
        status.attempt("prctl_set_dumpable_zero");
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc == 0 {
            status.success("prctl_set_dumpable_zero");
        } else {
            status.failure(
                "prctl_set_dumpable_zero",
                std::io::Error::last_os_error().to_string(),
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    status.unsupported("prctl_set_dumpable_zero");

    status
}

pub fn secure_region(ptr: *mut u8, len: usize) -> HardeningStatus {
    let mut status = HardeningStatus::default();
    if ptr.is_null() || len == 0 {
        return status;
    }

    status.attempt("mlock");
    let rc = unsafe { libc::mlock(ptr.cast(), len) };
    if rc == 0 {
        status.success("mlock");
    } else {
        status.failure("mlock", std::io::Error::last_os_error().to_string());
    }

    #[cfg(target_os = "linux")]
    {
        status.attempt("madvise_dontdump");
        let rc = unsafe { libc::madvise(ptr.cast(), len, libc::MADV_DONTDUMP) };
        if rc == 0 {
            status.success("madvise_dontdump");
        } else {
            status.failure(
                "madvise_dontdump",
                std::io::Error::last_os_error().to_string(),
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    status.unsupported("madvise_dontdump");

    status
}

pub fn release_secure_region(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len != 0 {
        unsafe {
            libc::munlock(ptr.cast(), len);
        }
    }
}
