mod inline_patch;
mod instrument;
mod original_opcode;
mod util;

pub(crate) use inline_patch::{cache_inline_patch, inline_patch_by_address, remove_inline_patch};
pub(crate) use instrument::{
    InstrumentSlot, PreparedSlotRemoval, drop_slot, original_bytes_by_address,
    original_opcode_by_address, prepare_remove_slot, reclaim_retired_slot_snapshots, register_slot,
    retire_slot_snapshot, retired_slot_by_address, trap_slot_by_address,
};
pub(crate) use original_opcode::{
    cache_original_opcode, cached_original_opcode_by_address, remove_cached_original_opcode,
};
