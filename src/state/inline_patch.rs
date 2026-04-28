use super::util::lock_or_recover;
use crate::constants::MAX_INSTRUMENTS;
use crate::error::SigHookError;
use std::sync::Mutex;

#[derive(Copy, Clone)]
struct InlinePatchSlot {
    used: bool,
    address: u64,
    original_bytes: [u8; 16],
    original_len: u8,
}

impl InlinePatchSlot {
    const EMPTY: Self = Self {
        used: false,
        address: 0,
        original_bytes: [0u8; 16],
        original_len: 0,
    };
}

type InlinePatchSlotArray = [InlinePatchSlot; MAX_INSTRUMENTS];
static INLINE_PATCH_SLOTS: Mutex<InlinePatchSlotArray> =
    Mutex::new([InlinePatchSlot::EMPTY; MAX_INSTRUMENTS]);

fn find_inline_patch_slot_index_in(slots: &InlinePatchSlotArray, address: u64) -> Option<usize> {
    let mut index = 0;
    while index < MAX_INSTRUMENTS {
        let slot = slots[index];
        if slot.used && slot.address == address {
            return Some(index);
        }
        index += 1;
    }
    None
}

pub(crate) unsafe fn cache_inline_patch(
    address: u64,
    original_bytes: &[u8],
) -> Result<bool, SigHookError> {
    if original_bytes.is_empty() || original_bytes.len() > 16 {
        return Err(SigHookError::InvalidAddress);
    }

    let mut slots = lock_or_recover(&INLINE_PATCH_SLOTS);

    if find_inline_patch_slot_index_in(&slots, address).is_some() {
        return Ok(false);
    }

    let mut stored_bytes = [0u8; 16];
    stored_bytes[..original_bytes.len()].copy_from_slice(original_bytes);

    let mut index = 0;
    while index < MAX_INSTRUMENTS {
        if !slots[index].used {
            slots[index] = InlinePatchSlot {
                used: true,
                address,
                original_bytes: stored_bytes,
                original_len: original_bytes.len() as u8,
            };
            return Ok(true);
        }
        index += 1;
    }

    Err(SigHookError::InstrumentSlotsFull)
}

pub(crate) unsafe fn inline_patch_by_address(address: u64) -> Option<([u8; 16], u8)> {
    let slots = lock_or_recover(&INLINE_PATCH_SLOTS);
    let index = find_inline_patch_slot_index_in(&slots, address)?;
    let slot = slots[index];
    Some((slot.original_bytes, slot.original_len))
}

pub(crate) unsafe fn remove_inline_patch(address: u64) -> bool {
    let mut slots = lock_or_recover(&INLINE_PATCH_SLOTS);
    let index = match find_inline_patch_slot_index_in(&slots, address) {
        Some(index) => index,
        None => return false,
    };

    slots[index] = InlinePatchSlot::EMPTY;
    true
}
