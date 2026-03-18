use crate::context::HookContext;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReplayPlan {
    Skip,
    Trampoline,
    Adr {
        rd: u8,
        absolute: u64,
    },
    Adrp {
        rd: u8,
        page_base: u64,
    },
    LdrLiteralW {
        rt: u8,
        literal_address: u64,
    },
    LdrLiteralX {
        rt: u8,
        literal_address: u64,
    },
    LdrLiteralS {
        rt: u8,
        literal_address: u64,
    },
    LdrLiteralD {
        rt: u8,
        literal_address: u64,
    },
    LdrLiteralQ {
        rt: u8,
        literal_address: u64,
    },
    LdrswLiteral {
        rt: u8,
        literal_address: u64,
    },
    PrfmLiteral {
        literal_address: u64,
    },
    Branch {
        target: u64,
    },
    BranchWithLink {
        target: u64,
    },
    ConditionalBranch {
        cond: u8,
        target: u64,
    },
    CompareAndBranch {
        rt: u8,
        target: u64,
        branch_on_zero: bool,
        is_64bit: bool,
    },
    TestBitAndBranch {
        rt: u8,
        bit_index: u8,
        target: u64,
        branch_on_zero: bool,
    },
}

impl ReplayPlan {
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

pub(crate) fn decode_replay_plan(address: u64, opcode: u32, execute_original: bool) -> ReplayPlan {
    if !execute_original {
        return ReplayPlan::Skip;
    }

    decode_pc_relative_plan(address, opcode).unwrap_or(ReplayPlan::Trampoline)
}

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
            ctx.pc = next_pc;
            true
        }
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

    if (opcode & 0xFF00_0010) == 0x5400_0000 {
        return Some(ReplayPlan::ConditionalBranch {
            cond: (opcode & 0xF) as u8,
            target: address.wrapping_add_signed(sign_extend((opcode >> 5) & 0x7_FFFF, 19) << 2),
        });
    }

    if (opcode & 0x7E00_0000) == 0x3400_0000 {
        return Some(ReplayPlan::CompareAndBranch {
            rt: (opcode & 0x1F) as u8,
            target: address.wrapping_add_signed(sign_extend((opcode >> 5) & 0x7_FFFF, 19) << 2),
            branch_on_zero: ((opcode >> 24) & 0x1) == 0,
            is_64bit: ((opcode >> 31) & 0x1) != 0,
        });
    }

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
fn literal_target(address: u64, opcode: u32) -> u64 {
    address.wrapping_add_signed(sign_extend((opcode >> 5) & 0x7_FFFF, 19) << 2)
}

#[inline]
fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

#[inline]
fn read_x(ctx: &HookContext, reg: u8) -> u64 {
    if reg >= 31 {
        return 0;
    }

    unsafe { ctx.regs.x[reg as usize] }
}

#[inline]
fn read_w(ctx: &HookContext, reg: u8) -> u32 {
    read_x(ctx, reg) as u32
}

#[inline]
fn write_x(ctx: &mut HookContext, reg: u8, value: u64) {
    if reg >= 31 {
        return;
    }

    unsafe {
        ctx.regs.x[reg as usize] = value;
    }
}

#[inline]
fn write_w(ctx: &mut HookContext, reg: u8, value: u32) {
    write_x(ctx, reg, value as u64);
}

#[inline]
fn write_s(ctx: &mut HookContext, reg: u8, value: u32) {
    if (reg as usize) < ctx.fpregs.v.len() {
        ctx.fpregs.v[reg as usize] = value as u128;
    }
}

#[inline]
fn write_d(ctx: &mut HookContext, reg: u8, value: u64) {
    if (reg as usize) < ctx.fpregs.v.len() {
        ctx.fpregs.v[reg as usize] = value as u128;
    }
}

#[inline]
fn write_q(ctx: &mut HookContext, reg: u8, value: [u8; 16]) {
    if (reg as usize) < ctx.fpregs.v.len() {
        ctx.fpregs.v[reg as usize] = u128::from_le_bytes(value);
    }
}

#[inline]
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
unsafe fn read_u32(address: u64) -> u32 {
    u32::from_le_bytes(unsafe { std::ptr::read_unaligned(address as *const [u8; 4]) })
}

#[inline]
unsafe fn read_i32(address: u64) -> i32 {
    i32::from_le_bytes(unsafe { std::ptr::read_unaligned(address as *const [u8; 4]) })
}

#[inline]
unsafe fn read_u64(address: u64) -> u64 {
    u64::from_le_bytes(unsafe { std::ptr::read_unaligned(address as *const [u8; 8]) })
}

#[inline]
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
