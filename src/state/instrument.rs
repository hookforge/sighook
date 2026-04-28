use super::util::lock_or_recover;
use crate::constants::MAX_INSTRUMENTS;
use crate::context::InstrumentCallback;
use crate::error::SigHookError;
#[cfg(target_arch = "aarch64")]
use crate::replay::ReplayPlan;
use crate::trampoline;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

#[derive(Copy, Clone)]
pub(crate) struct InstrumentSlot {
    pub used: bool,
    pub armed: bool,
    pub address: u64,
    pub original_bytes: [u8; 16],
    pub original_len: u8,
    pub step_len: u8,
    pub callback: Option<InstrumentCallback>,
    pub execute_original: bool,
    pub return_to_caller: bool,
    pub runtime_patch_installed: bool,
    pub trampoline_pc: u64,
    // On AArch64, execute-original is no longer just a boolean choice between
    // "jump to trampoline" and "skip". We persist the fully decoded replay policy
    // here so the trap handler can stay decode-free.
    #[cfg(target_arch = "aarch64")]
    pub replay_plan: ReplayPlan,
}

impl InstrumentSlot {
    pub const EMPTY: Self = Self {
        used: false,
        armed: false,
        address: 0,
        original_bytes: [0u8; 16],
        original_len: 0,
        step_len: 0,
        callback: None,
        execute_original: false,
        return_to_caller: false,
        runtime_patch_installed: false,
        trampoline_pc: 0,
        #[cfg(target_arch = "aarch64")]
        replay_plan: ReplayPlan::Skip,
    };
}

type InstrumentSlotArray = [InstrumentSlot; MAX_INSTRUMENTS];

const EMPTY_INSTRUMENT_SLOTS: InstrumentSlotArray = [InstrumentSlot::EMPTY; MAX_INSTRUMENTS];

static SLOT_SNAPSHOT: AtomicPtr<InstrumentSlotArray> = AtomicPtr::new(ptr::null_mut());
static SLOT_WRITE_LOCK: Mutex<()> = Mutex::new(());
static SLOT_SNAPSHOT_READERS: AtomicUsize = AtomicUsize::new(0);
static RETIRED_SLOT_SNAPSHOTS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

struct SlotSnapshotReadGuard;

impl SlotSnapshotReadGuard {
    fn enter() -> Self {
        SLOT_SNAPSHOT_READERS.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

impl Drop for SlotSnapshotReadGuard {
    fn drop(&mut self) {
        SLOT_SNAPSHOT_READERS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn with_current_slot_snapshot<T>(f: impl FnOnce(&InstrumentSlotArray) -> T) -> T {
    let _guard = SlotSnapshotReadGuard::enter();
    let ptr = SLOT_SNAPSHOT.load(Ordering::Acquire);
    let slots = if ptr.is_null() {
        &EMPTY_INSTRUMENT_SLOTS
    } else {
        unsafe { &*ptr }
    };
    f(slots)
}

fn current_slot_snapshot_copy() -> InstrumentSlotArray {
    with_current_slot_snapshot(|slots| *slots)
}

fn publish_slot_snapshot(slots: InstrumentSlotArray) {
    let ptr = Box::into_raw(Box::new(slots));
    let old = SLOT_SNAPSHOT.swap(ptr, Ordering::AcqRel);
    retire_slot_snapshot(old as usize);
}

fn publish_prepared_slot_snapshot(slots: Box<InstrumentSlotArray>) -> usize {
    let ptr = Box::into_raw(slots);
    SLOT_SNAPSHOT.swap(ptr, Ordering::AcqRel) as usize
}

pub(crate) fn retire_slot_snapshot(ptr: usize) {
    if ptr == 0 {
        return;
    }

    let mut retired = lock_or_recover(&RETIRED_SLOT_SNAPSHOTS);
    retired.push(ptr);
    drop(retired);
    reclaim_retired_slot_snapshots();
}

pub(crate) fn reclaim_retired_slot_snapshots() {
    if SLOT_SNAPSHOT_READERS.load(Ordering::Acquire) != 0 {
        return;
    }

    let mut retired = lock_or_recover(&RETIRED_SLOT_SNAPSHOTS);
    if SLOT_SNAPSHOT_READERS.load(Ordering::Acquire) != 0 {
        return;
    }

    for ptr in retired.drain(..) {
        unsafe {
            drop(Box::from_raw(ptr as *mut InstrumentSlotArray));
        }
    }
}

fn find_slot_index_in(
    slots: &InstrumentSlotArray,
    address: u64,
    include_disarmed: bool,
) -> Option<usize> {
    let mut index = 0;
    while index < MAX_INSTRUMENTS {
        let slot = slots[index];
        if slot.used && slot.address == address && (include_disarmed || slot.armed) {
            return Some(index);
        }
        index += 1;
    }
    None
}

pub(crate) unsafe fn slot_by_address(address: u64) -> Option<InstrumentSlot> {
    with_current_slot_snapshot(|slots| {
        let index = find_slot_index_in(slots, address, false)?;
        Some(slots[index])
    })
}

pub(crate) unsafe fn trap_slot_by_address(address: u64) -> Option<InstrumentSlot> {
    with_current_slot_snapshot(|slots| {
        let index = find_slot_index_in(slots, address, false)?;
        Some(slots[index])
    })
}

pub(crate) unsafe fn retired_slot_by_address(address: u64) -> Option<InstrumentSlot> {
    with_current_slot_snapshot(|slots| {
        let index = find_slot_index_in(slots, address, true)?;
        let slot = slots[index];
        if slot.armed { None } else { Some(slot) }
    })
}

pub(crate) unsafe fn drop_slot(address: u64) -> Option<InstrumentSlot> {
    let _guard = lock_or_recover(&SLOT_WRITE_LOCK);
    let mut slots = current_slot_snapshot_copy();
    let index = find_slot_index_in(&slots, address, false)?;
    let slot = slots[index];
    slots[index] = InstrumentSlot::EMPTY;
    publish_slot_snapshot(slots);
    Some(slot)
}

pub(crate) struct PreparedSlotRemoval {
    slot: InstrumentSlot,
    slots: Box<InstrumentSlotArray>,
    _guard: MutexGuard<'static, ()>,
}

impl PreparedSlotRemoval {
    pub(crate) fn slot(&self) -> InstrumentSlot {
        self.slot
    }

    pub(crate) fn commit(self) -> usize {
        let Self {
            slots,
            _guard,
            slot: _,
        } = self;
        publish_prepared_slot_snapshot(slots)
    }
}

pub(crate) unsafe fn prepare_remove_slot(address: u64) -> Option<PreparedSlotRemoval> {
    let guard = lock_or_recover(&SLOT_WRITE_LOCK);
    let mut slots = current_slot_snapshot_copy();
    let index = find_slot_index_in(&slots, address, false)?;
    let slot = slots[index];
    slots[index].armed = false;
    slots[index].runtime_patch_installed = false;

    Some(PreparedSlotRemoval {
        slot,
        slots: Box::new(slots),
        _guard: guard,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn register_slot(
    address: u64,
    original_bytes: &[u8],
    step_len: u8,
    callback: InstrumentCallback,
    #[cfg(target_arch = "aarch64")] replay_plan: ReplayPlan,
    execute_original: bool,
    return_to_caller: bool,
    runtime_patch_installed: bool,
) -> Result<(), SigHookError> {
    if original_bytes.is_empty() || original_bytes.len() > 16 || step_len == 0 {
        return Err(SigHookError::InvalidAddress);
    }

    let mut stored_bytes = [0u8; 16];
    stored_bytes[..original_bytes.len()].copy_from_slice(original_bytes);

    let _guard = lock_or_recover(&SLOT_WRITE_LOCK);
    let mut slots = current_slot_snapshot_copy();

    if let Some(index) = find_slot_index_in(&slots, address, true) {
        let mut slot = slots[index];

        slot.used = true;
        slot.armed = true;
        slot.callback = Some(callback);
        #[cfg(target_arch = "aarch64")]
        {
            slot.replay_plan = replay_plan;
        }
        slot.execute_original = execute_original;
        slot.return_to_caller = return_to_caller;
        slot.runtime_patch_installed |= runtime_patch_installed;

        if slot.original_len == 0
            || slot.original_len as usize != original_bytes.len()
            || slot.step_len != step_len
            || slot.original_bytes[..original_bytes.len()] != stored_bytes[..original_bytes.len()]
        {
            slot.original_len = original_bytes.len() as u8;
            slot.original_bytes = stored_bytes;
            slot.step_len = step_len;
        }

        #[cfg(target_arch = "aarch64")]
        // Only the explicit trampoline fallback needs an executable out-of-line copy.
        // Direct replay plans mutate the saved context instead.
        let needs_trampoline = replay_plan.requires_trampoline();
        #[cfg(not(target_arch = "aarch64"))]
        let needs_trampoline = execute_original;

        if needs_trampoline && slot.trampoline_pc == 0 {
            slot.trampoline_pc = trampoline::create_original_trampoline(
                address,
                &slot.original_bytes[..slot.original_len as usize],
                slot.step_len,
            )?;
        }

        slots[index] = slot;
        publish_slot_snapshot(slots);

        return Ok(());
    }

    let mut index = 0;
    while index < MAX_INSTRUMENTS {
        if !slots[index].used {
            #[cfg(target_arch = "aarch64")]
            // The same rule applies for brand new slots: allocate trampoline memory
            // only when the replay planner could not provide a direct emulation path.
            let needs_trampoline = replay_plan.requires_trampoline();
            #[cfg(not(target_arch = "aarch64"))]
            let needs_trampoline = execute_original;

            let trampoline_pc = if needs_trampoline {
                trampoline::create_original_trampoline(address, original_bytes, step_len)?
            } else {
                0
            };

            slots[index] = InstrumentSlot {
                used: true,
                armed: true,
                address,
                original_bytes: stored_bytes,
                original_len: original_bytes.len() as u8,
                step_len,
                callback: Some(callback),
                execute_original,
                return_to_caller,
                runtime_patch_installed,
                trampoline_pc,
                #[cfg(target_arch = "aarch64")]
                replay_plan,
            };
            publish_slot_snapshot(slots);
            return Ok(());
        }
        index += 1;
    }

    let mut index = 0;
    while index < MAX_INSTRUMENTS {
        if !slots[index].armed {
            #[cfg(target_arch = "aarch64")]
            let needs_trampoline = replay_plan.requires_trampoline();
            #[cfg(not(target_arch = "aarch64"))]
            let needs_trampoline = execute_original;

            let trampoline_pc = if needs_trampoline {
                trampoline::create_original_trampoline(address, original_bytes, step_len)?
            } else {
                0
            };

            slots[index] = InstrumentSlot {
                used: true,
                armed: true,
                address,
                original_bytes: stored_bytes,
                original_len: original_bytes.len() as u8,
                step_len,
                callback: Some(callback),
                execute_original,
                return_to_caller,
                runtime_patch_installed,
                trampoline_pc,
                #[cfg(target_arch = "aarch64")]
                replay_plan,
            };
            publish_slot_snapshot(slots);
            return Ok(());
        }
        index += 1;
    }

    Err(SigHookError::InstrumentSlotsFull)
}

pub(crate) unsafe fn original_opcode_by_address(address: u64) -> Option<u32> {
    let slot = unsafe { slot_by_address(address) }?;
    if slot.original_len < 4 {
        return None;
    }

    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&slot.original_bytes[..4]);
    Some(u32::from_le_bytes(bytes))
}

pub(crate) unsafe fn original_bytes_by_address(address: u64) -> Option<([u8; 16], u8)> {
    let slot = unsafe { slot_by_address(address) }?;
    Some((slot.original_bytes, slot.original_len))
}
