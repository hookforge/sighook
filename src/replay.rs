//! AArch64 execute-original replay support for displaced trap hooks.
//!
//! The core problem is that `instrument(...)` replaces the original instruction with
//! `brk`, then later needs some way to "run the instruction that used to be here".
//! A plain out-of-line trampoline is sufficient for many opcodes, but it breaks for
//! PC-relative instructions because those instructions derive their result from the
//! address where they execute.
//!
//! Example: when the original opcode is `adrp x10, symbol`, executing it from a
//! trampoline page computes a page base relative to the trampoline address, not the
//! original patch site. That silently produces the wrong pointer.
//!
//! This module solves the problem by splitting execute-original into two phases:
//!
//! 1. Install time:
//!    decode the displaced opcode once and store a compact `ReplayPlan` next to the
//!    hook slot.
//! 2. Trap time:
//!    if the callback leaves `ctx.pc` unchanged, execute the stored plan directly
//!    without decoding instruction bits again in the signal hot path.
//!
//! The design goal is deliberately conservative:
//! - support the common AArch64 PC-relative families that appear frequently in real
//!   code generation,
//! - keep the signal handler branchy but decode-free,
//! - fall back to the existing trampoline path for anything we do not explicitly
//!   understand.

use crate::context::HookContext;

/// Concrete execute-original strategy chosen for a displaced AArch64 instruction.
///
/// The plan is precomputed once at hook-install time. The trap handler then only
/// needs to dispatch on this enum:
/// - `Skip`: do not execute the original instruction at all
/// - `Trampoline`: jump to the out-of-line copy and let hardware execute it there
/// - everything else: emulate the visible architectural effect directly
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReplayPlan {
    /// Used by `instrument_no_original(...)` and `inline_hook(...)`.
    ///
    /// The callback is considered the complete replacement. If it does not redirect
    /// control flow, execution simply advances to the next instruction.
    Skip,

    /// Used for instructions that are not replayed directly.
    ///
    /// This preserves the old execute-original behavior: an out-of-line trampoline
    /// runs a copy of the displaced bytes and then returns to the original stream.
    Trampoline,

    /// `adr xd, label`
    ///
    /// Replay computes the exact absolute address the instruction would have written
    /// if it had executed in place at the original patch address.
    Adr { rd: u8, absolute: u64 },

    /// `adrp xd, label`
    ///
    /// Replay stores the resolved 4 KiB page base, not the page delta. That keeps
    /// the trap path simple and avoids recomputing anything from instruction bits.
    Adrp { rd: u8, page_base: u64 },

    /// `ldr wt, label`
    ///
    /// Replay reads 32 bits from the resolved literal address and applies the same
    /// architectural zero-extension into `xT` that hardware would perform.
    LdrLiteralW { rt: u8, literal_address: u64 },

    /// `ldr xt, label`
    LdrLiteralX { rt: u8, literal_address: u64 },

    /// `ldr st, label`
    ///
    /// AArch64 scalar `sT` is the low 32-bit view of vector register `vT`, and the
    /// upper 96 bits are architecturally cleared by a scalar load. Replay mirrors
    /// that exact behavior.
    LdrLiteralS { rt: u8, literal_address: u64 },

    /// `ldr dt, label`
    ///
    /// This writes the low 64 bits of `vT` and clears the high 64 bits.
    LdrLiteralD { rt: u8, literal_address: u64 },

    /// `ldr qt, label`
    LdrLiteralQ { rt: u8, literal_address: u64 },

    /// `ldrsw xt, label`
    ///
    /// Replay sign-extends the loaded 32-bit value to 64 bits before writing `xT`.
    LdrswLiteral { rt: u8, literal_address: u64 },

    /// `prfm <op>, label`
    ///
    /// `prfm` is only a hint. Architecturally it does not modify the visible
    /// register or memory state, so replay only needs to advance `pc`.
    PrfmLiteral { literal_address: u64 },

    /// `b label`
    Branch { target: u64 },

    /// `bl label`
    ///
    /// Replay must update `x30` (`lr`) to the sequential next instruction before
    /// transferring control to the branch target.
    BranchWithLink { target: u64 },

    /// `b.<cond> label`
    ///
    /// The condition code is stored as the raw 4-bit field from the instruction.
    /// Replay evaluates it against `ctx.cpsr`.
    ConditionalBranch { cond: u8, target: u64 },

    /// `cbz` / `cbnz`
    ///
    /// Replay stores whether the source register should be viewed as a 32-bit or
    /// 64-bit operand because `cbz wT` and `cbz xT` differ in how the source value
    /// is interpreted.
    CompareAndBranch {
        rt: u8,
        target: u64,
        branch_on_zero: bool,
        is_64bit: bool,
    },

    /// `tbz` / `tbnz`
    ///
    /// AArch64 encodes the tested bit index partly in the high `b5` bit and partly
    /// in the `b40` field. Replay stores the fully reconstructed bit number.
    TestBitAndBranch {
        rt: u8,
        bit_index: u8,
        target: u64,
        branch_on_zero: bool,
    },
}

impl ReplayPlan {
    /// Only the pure trampoline fallback needs executable memory allocation.
    ///
    /// Direct replay plans are self-contained and execute entirely by mutating the
    /// saved signal context.
    pub(crate) const fn requires_trampoline(self) -> bool {
        matches!(self, Self::Trampoline)
    }
}

const ADR_MASK: u32 = 0x9F00_0000;
const ADR_OPCODE: u32 = 0x1000_0000;
const ADRP_OPCODE: u32 = 0x9000_0000;

const LDR_LITERAL_W_OPCODE: u32 = 0x1800_0000;
const LDR_LITERAL_X_OPCODE: u32 = 0x5800_0000;
const LDR_LITERAL_S_OPCODE: u32 = 0x1C00_0000;
const LDR_LITERAL_D_OPCODE: u32 = 0x5C00_0000;
const LDR_LITERAL_Q_OPCODE: u32 = 0x9C00_0000;
const LDRSW_LITERAL_OPCODE: u32 = 0x9800_0000;
const PRFM_LITERAL_OPCODE: u32 = 0xD800_0000;

/// Chooses how the displaced instruction should be executed later.
///
/// This function is intentionally called during hook installation, not from the
/// signal handler. That keeps the hot path free from instruction decoding.
pub(crate) fn decode_replay_plan(address: u64, opcode: u32, execute_original: bool) -> ReplayPlan {
    if !execute_original {
        return ReplayPlan::Skip;
    }

    // If we recognize a PC-relative family, store enough pre-resolved information to
    // emulate it directly later. Otherwise preserve the older trampoline behavior.
    decode_pc_relative_plan(address, opcode).unwrap_or(ReplayPlan::Trampoline)
}

/// Applies a previously computed replay plan to the saved hook context.
///
/// The implementation works entirely on the in-memory `HookContext` produced from
/// the signal frame. No actual instruction is executed here; instead we reproduce
/// the architectural side effects that matter to user-visible program state.
pub(crate) fn apply_replay_plan(
    plan: ReplayPlan,
    ctx_ptr: *mut HookContext,
    address: u64,
    step_len: u8,
) -> bool {
    if ctx_ptr.is_null() || step_len == 0 {
        return false;
    }

    let next_pc = address.wrapping_add(step_len as u64);
    let ctx = unsafe { &mut *ctx_ptr };

    match plan {
        ReplayPlan::Skip => {
            // The hook fully replaces the displaced instruction.
            ctx.pc = next_pc;
            true
        }
        // `handle_trap_aarch64(...)` normally handles this case directly. Returning
        // `false` here makes accidental calls obviously invalid instead of silently
        // pretending the replay succeeded.
        ReplayPlan::Trampoline => false,
        ReplayPlan::Adr { rd, absolute } => {
            write_x(ctx, rd, absolute);
            ctx.pc = next_pc;
            true
        }
        ReplayPlan::Adrp { rd, page_base } => {
            write_x(ctx, rd, page_base);
            ctx.pc = next_pc;
            true
        }
        ReplayPlan::LdrLiteralW {
            rt,
            literal_address,
        } => {
            // A 32-bit integer literal load writes the architectural `wT` view, which
            // zero-extends into `xT`.
            let value = unsafe { read_u32(literal_address) };
            write_w(ctx, rt, value);
            ctx.pc = next_pc;
            true
        }
        ReplayPlan::LdrLiteralX {
            rt,
            literal_address,
        } => {
            let value = unsafe { read_u64(literal_address) };
            write_x(ctx, rt, value);
            ctx.pc = next_pc;
            true
        }
        ReplayPlan::LdrLiteralS {
            rt,
            literal_address,
        } => {
            // Scalar FP literal loads update the low element and clear the rest of
            // the vector register, matching hardware's scalar-register semantics.
            let value = unsafe { read_u32(literal_address) };
            write_s(ctx, rt, value);
            ctx.pc = next_pc;
            true
        }
        ReplayPlan::LdrLiteralD {
            rt,
            literal_address,
        } => {
            let value = unsafe { read_u64(literal_address) };
            write_d(ctx, rt, value);
            ctx.pc = next_pc;
            true
        }
        ReplayPlan::LdrLiteralQ {
            rt,
            literal_address,
        } => {
            let value = unsafe { read_u128_bytes(literal_address) };
            write_q(ctx, rt, value);
            ctx.pc = next_pc;
            true
        }
        ReplayPlan::LdrswLiteral {
            rt,
            literal_address,
        } => {
            let value = unsafe { read_i32(literal_address) };
            write_x(ctx, rt, value as i64 as u64);
            ctx.pc = next_pc;
            true
        }
        ReplayPlan::PrfmLiteral { literal_address } => {
            // We deliberately keep the resolved literal address in the plan because it
            // documents what the original instruction referenced and makes debugging
            // easier, even though replay does not dereference it.
            let _ = literal_address;
            ctx.pc = next_pc;
            true
        }
        ReplayPlan::Branch { target } => {
            ctx.pc = target;
            true
        }
        ReplayPlan::BranchWithLink { target } => {
            write_x(ctx, 30, next_pc);
            ctx.pc = target;
            true
        }
        ReplayPlan::ConditionalBranch { cond, target } => {
            // Condition evaluation uses the saved NZCV bits from `cpsr`. If a user
            // callback rewrote those flags before returning, replay intentionally
            // observes the modified flags, just like a normal in-place instruction
            // would observe the current machine state at execution time.
            ctx.pc = if condition_holds(ctx.cpsr, cond) {
                target
            } else {
                next_pc
            };
            true
        }
        ReplayPlan::CompareAndBranch {
            rt,
            target,
            branch_on_zero,
            is_64bit,
        } => {
            // `cbz wT` observes a zero-extended 32-bit value, while `cbz xT` observes
            // the full 64-bit register. The plan stores which view to use.
            let value = if is_64bit {
                read_x(ctx, rt)
            } else {
                read_w(ctx, rt) as u64
            };
            let is_zero = value == 0;
            ctx.pc = if is_zero == branch_on_zero {
                target
            } else {
                next_pc
            };
            true
        }
        ReplayPlan::TestBitAndBranch {
            rt,
            bit_index,
            target,
            branch_on_zero,
        } => {
            // For bit-test branches, the high bit of the encoded bit index also
            // implies whether the instruction conceptually uses `wT` or `xT`.
            // Bit indices 0..31 read the low 32-bit view; 32..63 require the full
            // 64-bit register.
            let value = if bit_index < 32 {
                read_w(ctx, rt) as u64
            } else {
                read_x(ctx, rt)
            };
            let bit_is_zero = ((value >> (bit_index & 63)) & 1) == 0;
            ctx.pc = if bit_is_zero == branch_on_zero {
                target
            } else {
                next_pc
            };
            true
        }
    }
}

/// Attempts to recognize PC-relative instruction families that cannot safely run
/// from the trampoline address.
///
/// The decoding style here is intentionally simple:
/// - first use coarse opcode masks to identify an instruction family,
/// - then extract only the fields needed for replay,
/// - finally pre-resolve absolute targets or addresses wherever possible.
///
/// This keeps the later trap path branchy but mechanically straightforward.
fn decode_pc_relative_plan(address: u64, opcode: u32) -> Option<ReplayPlan> {
    let op_major = opcode & 0xFF00_0000;

    match op_major {
        LDR_LITERAL_W_OPCODE => {
            return Some(ReplayPlan::LdrLiteralW {
                rt: (opcode & 0x1F) as u8,
                literal_address: literal_target(address, opcode),
            });
        }
        LDR_LITERAL_X_OPCODE => {
            return Some(ReplayPlan::LdrLiteralX {
                rt: (opcode & 0x1F) as u8,
                literal_address: literal_target(address, opcode),
            });
        }
        LDR_LITERAL_S_OPCODE => {
            return Some(ReplayPlan::LdrLiteralS {
                rt: (opcode & 0x1F) as u8,
                literal_address: literal_target(address, opcode),
            });
        }
        LDR_LITERAL_D_OPCODE => {
            return Some(ReplayPlan::LdrLiteralD {
                rt: (opcode & 0x1F) as u8,
                literal_address: literal_target(address, opcode),
            });
        }
        LDR_LITERAL_Q_OPCODE => {
            return Some(ReplayPlan::LdrLiteralQ {
                rt: (opcode & 0x1F) as u8,
                literal_address: literal_target(address, opcode),
            });
        }
        LDRSW_LITERAL_OPCODE => {
            return Some(ReplayPlan::LdrswLiteral {
                rt: (opcode & 0x1F) as u8,
                literal_address: literal_target(address, opcode),
            });
        }
        PRFM_LITERAL_OPCODE => {
            return Some(ReplayPlan::PrfmLiteral {
                literal_address: literal_target(address, opcode),
            });
        }
        _ => {}
    }

    // `adr` / `adrp` share the same immediate layout. The opcode bit decides whether
    // the immediate is added to the full instruction address or to the 4 KiB page
    // containing that address.
    if (opcode & ADR_MASK) == ADR_OPCODE {
        let immlo = (opcode >> 29) & 0x3;
        let immhi = (opcode >> 5) & 0x7_FFFF;
        let imm = sign_extend((immhi << 2) | immlo, 21);
        return Some(ReplayPlan::Adr {
            rd: (opcode & 0x1F) as u8,
            absolute: address.wrapping_add_signed(imm),
        });
    }

    if (opcode & ADR_MASK) == ADRP_OPCODE {
        let immlo = (opcode >> 29) & 0x3;
        let immhi = (opcode >> 5) & 0x7_FFFF;
        let imm_pages = sign_extend((immhi << 2) | immlo, 21);
        return Some(ReplayPlan::Adrp {
            rd: (opcode & 0x1F) as u8,
            page_base: (address & !0xFFF).wrapping_add_signed(imm_pages << 12),
        });
    }

    // `b` / `bl` use a signed 26-bit immediate measured in words. The low two bits
    // are implicit zeros, so replay shifts left by two after sign extension.
    if (opcode & 0xFC00_0000) == 0x1400_0000 {
        return Some(ReplayPlan::Branch {
            target: address.wrapping_add_signed(sign_extend(opcode & 0x03FF_FFFF, 26) << 2),
        });
    }

    if (opcode & 0xFC00_0000) == 0x9400_0000 {
        return Some(ReplayPlan::BranchWithLink {
            target: address.wrapping_add_signed(sign_extend(opcode & 0x03FF_FFFF, 26) << 2),
        });
    }

    // `b.<cond>` reuses the general Arm condition-code encoding. The least
    // significant condition bit is not part of the mask because it is data, not part
    // of the opcode identity.
    if (opcode & 0xFF00_0010) == 0x5400_0000 {
        return Some(ReplayPlan::ConditionalBranch {
            cond: (opcode & 0xF) as u8,
            target: address.wrapping_add_signed(sign_extend((opcode >> 5) & 0x7_FFFF, 19) << 2),
        });
    }

    // `cbz` / `cbnz` use a signed 19-bit immediate, again measured in words. Bit 31
    // selects the 32-bit versus 64-bit register view, and bit 24 selects zero-test
    // versus non-zero-test.
    if (opcode & 0x7E00_0000) == 0x3400_0000 {
        return Some(ReplayPlan::CompareAndBranch {
            rt: (opcode & 0x1F) as u8,
            target: address.wrapping_add_signed(sign_extend((opcode >> 5) & 0x7_FFFF, 19) << 2),
            branch_on_zero: ((opcode >> 24) & 0x1) == 0,
            is_64bit: ((opcode >> 31) & 0x1) != 0,
        });
    }

    // `tbz` / `tbnz` use a split bit index:
    // - bit 31 holds the high bit (`b5`)
    // - bits 23:19 hold the low five bits (`b40`)
    // The branch displacement is a signed 14-bit word offset.
    if (opcode & 0x7E00_0000) == 0x3600_0000 {
        return Some(ReplayPlan::TestBitAndBranch {
            rt: (opcode & 0x1F) as u8,
            bit_index: ((((opcode >> 31) & 0x1) << 5) | ((opcode >> 19) & 0x1F)) as u8,
            target: address.wrapping_add_signed(sign_extend((opcode >> 5) & 0x3FFF, 14) << 2),
            branch_on_zero: ((opcode >> 24) & 0x1) == 0,
        });
    }

    None
}

#[inline]
/// Resolves the absolute target address for AArch64 literal loads and `prfm`.
///
/// The instruction encodes a signed 19-bit word offset relative to the instruction
/// address, so replay sign-extends the field and then multiplies it by 4.
fn literal_target(address: u64, opcode: u32) -> u64 {
    address.wrapping_add_signed(sign_extend((opcode >> 5) & 0x7_FFFF, 19) << 2)
}

#[inline]
/// Generic sign extension helper for immediate fields extracted into the low bits of
/// a `u32`.
///
/// We intentionally return `i64` because all replay address arithmetic is ultimately
/// performed against 64-bit PCs and pointers.
fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

#[inline]
/// Reads a general-purpose register from the saved context.
///
/// Register number 31 is encoded in some AArch64 instructions as `xzr/wzr` or `sp`,
/// depending on the instruction class. None of the replayed families here use `sp`
/// in that role, so treating register 31 as the architectural zero register is the
/// correct behavior for this module.
fn read_x(ctx: &HookContext, reg: u8) -> u64 {
    if reg >= 31 {
        return 0;
    }

    unsafe { ctx.regs.x[reg as usize] }
}

#[inline]
/// Reads the architectural `wN` view of a register.
///
/// AArch64 defines `wN` as the low 32 bits of `xN`, so replay simply truncates.
fn read_w(ctx: &HookContext, reg: u8) -> u32 {
    read_x(ctx, reg) as u32
}

#[inline]
/// Writes a general-purpose register back to the saved context.
///
/// As above, writes to register 31 are discarded because the replayed instruction
/// families interpret it as the architectural zero register rather than a writable
/// destination.
fn write_x(ctx: &mut HookContext, reg: u8, value: u64) {
    if reg >= 31 {
        return;
    }

    unsafe {
        ctx.regs.x[reg as usize] = value;
    }
}

#[inline]
/// Writes the architectural `wN` view.
///
/// Hardware zero-extends `wN` writes into `xN`, so replay uses the same behavior.
fn write_w(ctx: &mut HookContext, reg: u8, value: u32) {
    write_x(ctx, reg, value as u64);
}

#[inline]
/// Writes a scalar `sN` result into `vN`.
///
/// Storing the 32-bit value as `u128` naturally leaves the upper 96 bits cleared,
/// which matches AArch64 scalar FP load semantics.
fn write_s(ctx: &mut HookContext, reg: u8, value: u32) {
    if (reg as usize) < ctx.fpregs.v.len() {
        ctx.fpregs.v[reg as usize] = value as u128;
    }
}

#[inline]
/// Writes a scalar `dN` result into `vN`, clearing the high 64 bits.
fn write_d(ctx: &mut HookContext, reg: u8, value: u64) {
    if (reg as usize) < ctx.fpregs.v.len() {
        ctx.fpregs.v[reg as usize] = value as u128;
    }
}

#[inline]
/// Writes a full 128-bit vector register from little-endian bytes.
///
/// `HookContext` stores vector registers as `u128`, so replay converts the raw bytes
/// into the host integer representation once at the boundary.
fn write_q(ctx: &mut HookContext, reg: u8, value: [u8; 16]) {
    if (reg as usize) < ctx.fpregs.v.len() {
        ctx.fpregs.v[reg as usize] = u128::from_le_bytes(value);
    }
}

#[inline]
/// Evaluates an Arm condition-code field against NZCV bits in `cpsr`.
///
/// This is the standard Arm condition mapping:
/// - `eq/ne` use Z
/// - `cs/cc` use C
/// - `mi/pl` use N
/// - `vs/vc` use V
/// - the ordered comparisons combine Z with `N == V`
fn condition_holds(cpsr: u32, cond: u8) -> bool {
    let n = ((cpsr >> 31) & 1) != 0;
    let z = ((cpsr >> 30) & 1) != 0;
    let c = ((cpsr >> 29) & 1) != 0;
    let v = ((cpsr >> 28) & 1) != 0;

    match cond & 0xF {
        0x0 => z,
        0x1 => !z,
        0x2 => c,
        0x3 => !c,
        0x4 => n,
        0x5 => !n,
        0x6 => v,
        0x7 => !v,
        0x8 => c && !z,
        0x9 => !c || z,
        0xA => n == v,
        0xB => n != v,
        0xC => !z && (n == v),
        0xD => z || (n != v),
        0xE => true,
        _ => false,
    }
}

#[inline]
/// Performs an unaligned 32-bit little-endian memory read from the traced process.
///
/// The hook runs in-process, so the literal address is directly readable from the
/// current address space.
unsafe fn read_u32(address: u64) -> u32 {
    u32::from_le_bytes(unsafe { std::ptr::read_unaligned(address as *const [u8; 4]) })
}

#[inline]
/// Performs an unaligned 32-bit little-endian memory read and interprets it as signed.
unsafe fn read_i32(address: u64) -> i32 {
    i32::from_le_bytes(unsafe { std::ptr::read_unaligned(address as *const [u8; 4]) })
}

#[inline]
/// Performs an unaligned 64-bit little-endian memory read.
unsafe fn read_u64(address: u64) -> u64 {
    u64::from_le_bytes(unsafe { std::ptr::read_unaligned(address as *const [u8; 8]) })
}

#[inline]
/// Performs an unaligned 128-bit memory read used by `ldr qT, label`.
unsafe fn read_u128_bytes(address: u64) -> [u8; 16] {
    unsafe { std::ptr::read_unaligned(address as *const [u8; 16]) }
}

#[cfg(test)]
mod tests {
    use super::{ReplayPlan, apply_replay_plan, decode_replay_plan};
    use crate::context::{FpRegisters, HookContext, XRegisters};

    fn empty_ctx() -> HookContext {
        HookContext {
            regs: XRegisters { x: [0; 31] },
            sp: 0,
            pc: 0,
            cpsr: 0,
            pad: 0,
            fpregs: FpRegisters {
                v: [0; 32],
                fpsr: 0,
                fpcr: 0,
            },
        }
    }

    #[test]
    fn decode_common_pc_relative_families() {
        assert_eq!(
            decode_replay_plan(0x1000, 0x1000_0200, true),
            ReplayPlan::Adr {
                rd: 0,
                absolute: 0x1040,
            }
        );
        assert_eq!(
            decode_replay_plan(0x1234, 0x9000_0001, true),
            ReplayPlan::Adrp {
                rd: 1,
                page_base: 0x1000,
            }
        );
        assert_eq!(
            decode_replay_plan(0x2000, 0x1800_01C2, true),
            ReplayPlan::LdrLiteralW {
                rt: 2,
                literal_address: 0x2038,
            }
        );
        assert_eq!(
            decode_replay_plan(0x2000, 0x5800_01A3, true),
            ReplayPlan::LdrLiteralX {
                rt: 3,
                literal_address: 0x2034,
            }
        );
        assert_eq!(
            decode_replay_plan(0x2000, 0x1C00_0184, true),
            ReplayPlan::LdrLiteralS {
                rt: 4,
                literal_address: 0x2030,
            }
        );
        assert_eq!(
            decode_replay_plan(0x2000, 0x5C00_0165, true),
            ReplayPlan::LdrLiteralD {
                rt: 5,
                literal_address: 0x202C,
            }
        );
        assert_eq!(
            decode_replay_plan(0x2000, 0x9C00_0146, true),
            ReplayPlan::LdrLiteralQ {
                rt: 6,
                literal_address: 0x2028,
            }
        );
        assert_eq!(
            decode_replay_plan(0x2000, 0x9800_0127, true),
            ReplayPlan::LdrswLiteral {
                rt: 7,
                literal_address: 0x2024,
            }
        );
        assert_eq!(
            decode_replay_plan(0x2000, 0xD800_0100, true),
            ReplayPlan::PrfmLiteral {
                literal_address: 0x2020,
            }
        );
        assert_eq!(
            decode_replay_plan(0x3000, 0x1400_0007, true),
            ReplayPlan::Branch { target: 0x301C }
        );
        assert_eq!(
            decode_replay_plan(0x3000, 0x9400_0006, true),
            ReplayPlan::BranchWithLink { target: 0x3018 }
        );
        assert_eq!(
            decode_replay_plan(0x3000, 0x5400_00A0, true),
            ReplayPlan::ConditionalBranch {
                cond: 0,
                target: 0x3014,
            }
        );
        assert_eq!(
            decode_replay_plan(0x3000, 0xB400_0088, true),
            ReplayPlan::CompareAndBranch {
                rt: 8,
                target: 0x3010,
                branch_on_zero: true,
                is_64bit: true,
            }
        );
        assert_eq!(
            decode_replay_plan(0x3000, 0x3500_0069, true),
            ReplayPlan::CompareAndBranch {
                rt: 9,
                target: 0x300C,
                branch_on_zero: false,
                is_64bit: false,
            }
        );
        assert_eq!(
            decode_replay_plan(0x3000, 0x3628_004A, true),
            ReplayPlan::TestBitAndBranch {
                rt: 10,
                bit_index: 5,
                target: 0x3008,
                branch_on_zero: true,
            }
        );
        assert_eq!(
            decode_replay_plan(0x3000, 0x3788_002B, true),
            ReplayPlan::TestBitAndBranch {
                rt: 11,
                bit_index: 17,
                target: 0x3004,
                branch_on_zero: false,
            }
        );
    }

    #[test]
    fn decode_skip_when_execute_original_is_disabled() {
        assert_eq!(
            decode_replay_plan(0x1000, 0x1000_0200, false),
            ReplayPlan::Skip
        );
    }

    #[test]
    fn decode_unsupported_falls_back_to_trampoline() {
        assert_eq!(
            decode_replay_plan(0x1000, 0xAA00_03E0, true),
            ReplayPlan::Trampoline
        );
    }

    #[test]
    fn apply_literal_replay_updates_integer_and_vector_registers() {
        let word = 0x1122_3344u32;
        let double = 0x5566_7788_99AA_BBCCu64;
        let quad = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];

        let mut ctx = empty_ctx();
        assert!(apply_replay_plan(
            ReplayPlan::LdrLiteralW {
                rt: 5,
                literal_address: (&word as *const u32) as u64,
            },
            &mut ctx,
            0x4000,
            4,
        ));
        assert_eq!(unsafe { ctx.regs.x[5] }, 0x1122_3344);
        assert_eq!(ctx.pc, 0x4004);

        assert!(apply_replay_plan(
            ReplayPlan::LdrLiteralD {
                rt: 6,
                literal_address: (&double as *const u64) as u64,
            },
            &mut ctx,
            0x5000,
            4,
        ));
        assert_eq!(ctx.fpregs.v[6], double as u128);
        assert_eq!(ctx.pc, 0x5004);

        assert!(apply_replay_plan(
            ReplayPlan::LdrLiteralQ {
                rt: 7,
                literal_address: quad.as_ptr() as u64,
            },
            &mut ctx,
            0x6000,
            4,
        ));
        assert_eq!(ctx.fpregs.v[7], u128::from_le_bytes(quad));
        assert_eq!(ctx.pc, 0x6004);
    }

    #[test]
    fn apply_branch_family_replay_updates_pc_and_lr() {
        let mut ctx = empty_ctx();
        assert!(apply_replay_plan(
            ReplayPlan::BranchWithLink { target: 0x9000 },
            &mut ctx,
            0x8000,
            4,
        ));
        assert_eq!(ctx.pc, 0x9000);
        assert_eq!(unsafe { ctx.regs.x[30] }, 0x8004);
    }

    #[test]
    fn apply_conditional_replay_uses_flags_and_register_contents() {
        let mut ctx = empty_ctx();
        ctx.cpsr = 1 << 30;
        assert!(apply_replay_plan(
            ReplayPlan::ConditionalBranch {
                cond: 0,
                target: 0xA000,
            },
            &mut ctx,
            0x9000,
            4,
        ));
        assert_eq!(ctx.pc, 0xA000);

        unsafe {
            ctx.regs.x[8] = 0;
            ctx.regs.x[10] = 1 << 5;
        }
        assert!(apply_replay_plan(
            ReplayPlan::CompareAndBranch {
                rt: 8,
                target: 0xB000,
                branch_on_zero: true,
                is_64bit: true,
            },
            &mut ctx,
            0x9000,
            4,
        ));
        assert_eq!(ctx.pc, 0xB000);

        assert!(apply_replay_plan(
            ReplayPlan::TestBitAndBranch {
                rt: 10,
                bit_index: 5,
                target: 0xC000,
                branch_on_zero: false,
            },
            &mut ctx,
            0x9000,
            4,
        ));
        assert_eq!(ctx.pc, 0xC000);
    }
}
