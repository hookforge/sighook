use libc::c_int;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigHookError {
    InvalidAddress,
    UnsupportedPlatform,
    UnsupportedArchitecture,
    UnsupportedOperation,
    PageSizeUnavailable,
    UnexpectedSignalContext,

    #[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
    ProtectWritableFailed {
        kr: libc::kern_return_t,
        errno: c_int,
    },
    #[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
    ProtectExecutableFailed {
        kr: libc::kern_return_t,
        errno: c_int,
    },
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    ProtectWritableFailed {
        errno: c_int,
    },
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    ProtectExecutableFailed {
        errno: c_int,
    },

    SigEmptySetFailed {
        signum: c_int,
        errno: c_int,
    },
    SigActionFailed {
        signum: c_int,
        errno: c_int,
    },
    InstrumentSlotsFull,
    BranchOutOfRange,
    DecodeFailed,
    AsmEmptyInput,
    AsmAssembleFailed,
    AsmSizeMismatch {
        expected: usize,
        actual: usize,
    },
    MmapFailed {
        errno: c_int,
    },
    TrampolineProtectFailed {
        errno: c_int,
    },
}

impl fmt::Display for SigHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            SigHookError::InvalidAddress => write!(f, "invalid address"),
            SigHookError::UnsupportedPlatform => write!(f, "unsupported platform"),
            SigHookError::UnsupportedArchitecture => write!(f, "unsupported architecture"),
            SigHookError::UnsupportedOperation => write!(f, "unsupported operation"),
            SigHookError::PageSizeUnavailable => write!(f, "page size unavailable"),
            SigHookError::UnexpectedSignalContext => write!(f, "unexpected signal context"),

            #[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
            SigHookError::ProtectWritableFailed { kr, errno } => {
                write!(
                    f,
                    "mach_vm_protect writable failed (kr={kr}, errno={errno})"
                )
            }
            #[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
            SigHookError::ProtectExecutableFailed { kr, errno } => {
                write!(
                    f,
                    "mach_vm_protect executable failed (kr={kr}, errno={errno})"
                )
            }

            #[cfg(all(
                any(target_os = "linux", target_os = "android"),
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            SigHookError::ProtectWritableFailed { errno } => {
                write!(f, "mprotect writable failed (errno={errno})")
            }
            #[cfg(all(
                any(target_os = "linux", target_os = "android"),
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            SigHookError::ProtectExecutableFailed { errno } => {
                write!(f, "mprotect executable failed (errno={errno})")
            }

            SigHookError::SigEmptySetFailed { signum, errno } => {
                write!(f, "sigemptyset failed (signum={signum}, errno={errno})")
            }
            SigHookError::SigActionFailed { signum, errno } => {
                write!(f, "sigaction failed (signum={signum}, errno={errno})")
            }
            SigHookError::InstrumentSlotsFull => write!(f, "instrument slots are full"),
            SigHookError::BranchOutOfRange => write!(f, "branch target out of range"),
            SigHookError::DecodeFailed => write!(f, "instruction decode failed"),
            SigHookError::AsmEmptyInput => write!(f, "assembly input is empty"),
            SigHookError::AsmAssembleFailed => write!(f, "assembly to machine code failed"),
            SigHookError::AsmSizeMismatch { expected, actual } => {
                write!(
                    f,
                    "assembled size mismatch (expected={expected}, actual={actual})"
                )
            }
            SigHookError::MmapFailed { errno } => write!(f, "mmap failed (errno={errno})"),
            SigHookError::TrampolineProtectFailed { errno } => {
                write!(f, "trampoline mprotect failed (errno={errno})")
            }
        }
    }
}

impl std::error::Error for SigHookError {}
