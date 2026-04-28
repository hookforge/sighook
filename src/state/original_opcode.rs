use super::util::lock_or_recover;
use crate::constants::MAX_INSTRUMENTS;
use std::sync::Mutex;

#[derive(Copy, Clone)]
struct OriginalOpcodeSlot {
    used: bool,
    address: u64,
    opcode: u32,
}

impl OriginalOpcodeSlot {
    const EMPTY: Self = Self {
        used: false,
        address: 0,
        opcode: 0,
    };
}

#[derive(Copy, Clone)]
struct OriginalOpcodeState {
    slots: [OriginalOpcodeSlot; MAX_INSTRUMENTS],
    replace_index: usize,
}

impl OriginalOpcodeState {
    const EMPTY: Self = Self {
        slots: [OriginalOpcodeSlot::EMPTY; MAX_INSTRUMENTS],
        replace_index: 0,
    };
}

static ORIGINAL_OPCODE_STATE: Mutex<OriginalOpcodeState> = Mutex::new(OriginalOpcodeState::EMPTY);

fn find_original_opcode_slot_index(
    slots: &[OriginalOpcodeSlot; MAX_INSTRUMENTS],
    address: u64,
) -> Option<usize> {
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

pub(crate) unsafe fn cache_original_opcode(address: u64, opcode: u32) {
    let mut state = lock_or_recover(&ORIGINAL_OPCODE_STATE);

    if let Some(index) = find_original_opcode_slot_index(&state.slots, address) {
        state.slots[index].opcode = opcode;
        return;
    }

    let mut index = 0;
    while index < MAX_INSTRUMENTS {
        if !state.slots[index].used {
            state.slots[index] = OriginalOpcodeSlot {
                used: true,
                address,
                opcode,
            };
            return;
        }

        index += 1;
    }

    let replace_index = state.replace_index % MAX_INSTRUMENTS;
    state.slots[replace_index] = OriginalOpcodeSlot {
        used: true,
        address,
        opcode,
    };
    state.replace_index = (replace_index + 1) % MAX_INSTRUMENTS;
}

pub(crate) unsafe fn cached_original_opcode_by_address(address: u64) -> Option<u32> {
    let state = lock_or_recover(&ORIGINAL_OPCODE_STATE);
    let index = find_original_opcode_slot_index(&state.slots, address)?;
    Some(state.slots[index].opcode)
}

pub(crate) unsafe fn remove_cached_original_opcode(address: u64) -> bool {
    let mut state = lock_or_recover(&ORIGINAL_OPCODE_STATE);
    let index = match find_original_opcode_slot_index(&state.slots, address) {
        Some(index) => index,
        None => return false,
    };

    state.slots[index] = OriginalOpcodeSlot::EMPTY;
    true
}
