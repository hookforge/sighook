use crate::error::SigHookError;
use crate::platform::last_errno;
use libc::{c_int, c_void};
use std::fs;

#[derive(Copy, Clone)]
pub(crate) struct ProtectionRange {
    start: usize,
    len: usize,
    prot: c_int,
}

pub(crate) struct RestoreProtections {
    ranges: Vec<ProtectionRange>,
}

pub(crate) fn prepare_restore_protections(
    start: usize,
    len: usize,
) -> Result<RestoreProtections, SigHookError> {
    Ok(RestoreProtections {
        ranges: restore_protection_ranges(start, len)?,
    })
}

pub(crate) fn make_patch_range_writable(start: usize, len: usize) -> Result<(), SigHookError> {
    let result = unsafe {
        libc::mprotect(
            start as *mut c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    };

    if result != 0 {
        return Err(SigHookError::ProtectWritableFailed {
            errno: last_errno(),
        });
    }

    Ok(())
}

pub(crate) fn restore_patch_range_protection(
    _start: usize,
    _len: usize,
    restore: &RestoreProtections,
) -> Result<(), SigHookError> {
    for range in &restore.ranges {
        let result = unsafe { libc::mprotect(range.start as *mut c_void, range.len, range.prot) };
        if result != 0 {
            return Err(SigHookError::ProtectExecutableFailed {
                errno: last_errno(),
            });
        }
    }

    Ok(())
}

fn restore_protection_ranges(
    start: usize,
    len: usize,
) -> Result<Vec<ProtectionRange>, SigHookError> {
    let maps = fs::read_to_string("/proc/self/maps").map_err(|_| SigHookError::InvalidAddress)?;
    let end = start.checked_add(len).ok_or(SigHookError::InvalidAddress)?;
    let mut ranges = Vec::new();
    let mut covered_until = start;

    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let Some(range_field) = parts.next() else {
            continue;
        };
        let Some(perms) = parts.next() else {
            continue;
        };
        let Some((map_start, map_end)) = parse_proc_maps_range(range_field) else {
            continue;
        };
        if map_end <= start || map_start >= end {
            continue;
        }

        let overlap_start = map_start.max(start);
        let overlap_end = map_end.min(end);
        let prot = parse_proc_maps_perms(perms)?;

        if overlap_start > covered_until {
            return Err(SigHookError::InvalidAddress);
        }
        if overlap_end > covered_until {
            ranges.push(ProtectionRange {
                start: overlap_start,
                len: overlap_end - overlap_start,
                prot,
            });
            covered_until = overlap_end;
            if covered_until >= end {
                break;
            }
        }
    }

    if covered_until != end {
        return Err(SigHookError::InvalidAddress);
    }

    Ok(ranges)
}

fn parse_proc_maps_range(field: &str) -> Option<(usize, usize)> {
    let (start, end) = field.split_once('-')?;
    Some((
        usize::from_str_radix(start, 16).ok()?,
        usize::from_str_radix(end, 16).ok()?,
    ))
}

fn parse_proc_maps_perms(perms: &str) -> Result<c_int, SigHookError> {
    let bytes = perms.as_bytes();
    if bytes.len() < 3 {
        return Err(SigHookError::InvalidAddress);
    }

    let mut prot = 0;
    if bytes[0] == b'r' {
        prot |= libc::PROT_READ;
    }
    if bytes[1] == b'w' {
        prot |= libc::PROT_WRITE;
    }
    if bytes[2] == b'x' {
        prot |= libc::PROT_EXEC;
    }
    Ok(prot)
}
