use crate::constants::MAX_INSTRUMENTS;
use crate::context::InstrumentCallback;
use crate::error::SigHookError;
use crate::trampoline;

#[derive(Copy, Clone)]
pub(crate) struct InstrumentSlot {
    pub used: bool,
    pub address: u64,
    pub original_bytes: [u8; 16],
    pub original_len: u8,
    pub step_len: u8,
    pub callback: Option<InstrumentCallback>,
    pub execute_original: bool,
    pub trampoline_pc: u64,
}

impl InstrumentSlot {
    pub const EMPTY: Self = Self {
        used: false,
        address: 0,
        original_bytes: [0u8; 16],
        original_len: 0,
        step_len: 0,
        callback: None,
        execute_original: false,
        trampoline_pc: 0,
    };
}

pub(crate) static mut HANDLERS_INSTALLED: bool = false;
pub(crate) static mut SLOTS: [InstrumentSlot; MAX_INSTRUMENTS] =
    [InstrumentSlot::EMPTY; MAX_INSTRUMENTS];

#[derive(Copy, Clone)]
pub(crate) struct OriginalOpcodeSlot {
    pub used: bool,
    pub address: u64,
    pub opcode: u32,
}

impl OriginalOpcodeSlot {
    pub const EMPTY: Self = Self {
        used: false,
        address: 0,
        opcode: 0,
    };
}

pub(crate) static mut ORIGINAL_OPCODE_SLOTS: [OriginalOpcodeSlot; MAX_INSTRUMENTS] =
    [OriginalOpcodeSlot::EMPTY; MAX_INSTRUMENTS];
pub(crate) static mut ORIGINAL_OPCODE_REPLACE_INDEX: usize = 0;

pub(crate) unsafe fn find_slot_index(address: u64) -> Option<usize> {
    let mut index = 0;
    while index < MAX_INSTRUMENTS {
        let slot = unsafe { SLOTS[index] };
        if slot.used && slot.address == address {
            return Some(index);
        }
        index += 1;
    }
    None
}

pub(crate) unsafe fn slot_by_address(address: u64) -> Option<InstrumentSlot> {
    let index = unsafe { find_slot_index(address) }?;
    Some(unsafe { SLOTS[index] })
}

pub(crate) unsafe fn register_slot(
    address: u64,
    original_bytes: &[u8],
    step_len: u8,
    callback: InstrumentCallback,
    execute_original: bool,
) -> Result<(), SigHookError> {
    if original_bytes.is_empty() || original_bytes.len() > 16 || step_len == 0 {
        return Err(SigHookError::InvalidAddress);
    }

    let mut stored_bytes = [0u8; 16];
    stored_bytes[..original_bytes.len()].copy_from_slice(original_bytes);

    if let Some(index) = unsafe { find_slot_index(address) } {
        let mut slot = unsafe { SLOTS[index] };

        slot.callback = Some(callback);
        slot.execute_original = execute_original;

        if slot.original_len == 0 {
            slot.original_len = original_bytes.len() as u8;
            slot.original_bytes = stored_bytes;
            slot.step_len = step_len;
        }

        if execute_original && slot.trampoline_pc == 0 {
            slot.trampoline_pc = trampoline::create_original_trampoline(
                address,
                &slot.original_bytes[..slot.original_len as usize],
                slot.step_len,
            )?;
        }

        unsafe {
            SLOTS[index] = slot;
        }

        return Ok(());
    }

    let mut index = 0;
    while index < MAX_INSTRUMENTS {
        if !(unsafe { SLOTS[index].used }) {
            let trampoline_pc = if execute_original {
                trampoline::create_original_trampoline(address, original_bytes, step_len)?
            } else {
                0
            };

            unsafe {
                SLOTS[index] = InstrumentSlot {
                    used: true,
                    address,
                    original_bytes: stored_bytes,
                    original_len: original_bytes.len() as u8,
                    step_len,
                    callback: Some(callback),
                    execute_original,
                    trampoline_pc,
                };
            }
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

unsafe fn find_original_opcode_slot_index(address: u64) -> Option<usize> {
    let mut index = 0;
    while index < MAX_INSTRUMENTS {
        let slot = unsafe { ORIGINAL_OPCODE_SLOTS[index] };
        if slot.used && slot.address == address {
            return Some(index);
        }
        index += 1;
    }

    None
}

pub(crate) unsafe fn cache_original_opcode(address: u64, opcode: u32) {
    if let Some(index) = unsafe { find_original_opcode_slot_index(address) } {
        unsafe {
            ORIGINAL_OPCODE_SLOTS[index].opcode = opcode;
        }
        return;
    }

    let mut index = 0;
    while index < MAX_INSTRUMENTS {
        if !(unsafe { ORIGINAL_OPCODE_SLOTS[index].used }) {
            unsafe {
                ORIGINAL_OPCODE_SLOTS[index] = OriginalOpcodeSlot {
                    used: true,
                    address,
                    opcode,
                };
            }
            return;
        }

        index += 1;
    }

    let replace_index = unsafe { ORIGINAL_OPCODE_REPLACE_INDEX % MAX_INSTRUMENTS };
    unsafe {
        ORIGINAL_OPCODE_SLOTS[replace_index] = OriginalOpcodeSlot {
            used: true,
            address,
            opcode,
        };
        ORIGINAL_OPCODE_REPLACE_INDEX = (replace_index + 1) % MAX_INSTRUMENTS;
    }
}

pub(crate) unsafe fn cached_original_opcode_by_address(address: u64) -> Option<u32> {
    let index = unsafe { find_original_opcode_slot_index(address) }?;
    Some(unsafe { ORIGINAL_OPCODE_SLOTS[index].opcode })
}
