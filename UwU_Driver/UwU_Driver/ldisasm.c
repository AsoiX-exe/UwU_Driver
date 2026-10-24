#include "ldisasm.h"

// Minimal x64 instruction length disassembler.
// Handles common kernel prologue patterns correctly.
// Based on the x86/x64 instruction encoding specification.

static int modrm_extra(const UINT8 *p) {
    // p points to the byte AFTER ModRM.
    // Returns extra bytes used by SIB + displacement.
    // (ModRM byte itself is NOT included here.)
    // Caller already consumed the ModRM byte.
    // We need to look at the ModRM byte itself, so caller must pass the ORIGINAL byte.
    // -- This signature is called wrong; see modrm_bytes() below.
    (void)p;
    return 0;
}

// Given the ModRM byte and bytes following it, return total bytes consumed
// by [ModRM + SIB + displacement] (NOT including the opcode byte).
static int modrm_bytes(const UINT8 *after_opcode) {
    UINT8 modrm = after_opcode[0];
    int mod = (modrm >> 6) & 3;
    int rm  = modrm & 7;
    int n   = 1; // ModRM itself

    if (mod == 3) return n; // register direct - no SIB or disp

    // SIB byte?
    if (rm == 4) {
        n++; // SIB
        // SIB.base == 5 with mod==0 → 32-bit disp (no base reg)
        if (mod == 0 && (after_opcode[1] & 7) == 5) {
            n += 4;
            return n;
        }
    }

    // Displacement
    if (mod == 1) n += 1;
    else if (mod == 2) n += 4;
    else if (mod == 0 && rm == 5) n += 4; // RIP-relative disp32

    return n;
}

int ldisasm(const UINT8 *p) {
    int n = 0;
    UINT8 rex = 0;
    int pfx66 = 0;

    // Consume legacy prefixes + REX
    for (;;) {
        UINT8 b = p[n];
        if (b == 0x66) { pfx66 = 1; n++; }
        else if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                 b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
                 b == 0x64 || b == 0x65)
            n++;
        else if ((b & 0xF0) == 0x40) { rex = b; n++; } // REX
        else break;
    }

    UINT8 op = p[n++];
    int W = (rex >> 3) & 1; // REX.W
    (void)pfx66;

    // ---- Two-byte escape 0F ----
    if (op == 0x0F) {
        op = p[n++];

        // Jcc rel32
        if (op >= 0x80 && op <= 0x8F) return n + 4;

        // 2-byte ops with ModRM and no immediate
        if (op == 0x1F ||                               // NOP hint
            op == 0xA3 || op == 0xAB || op == 0xB3 || op == 0xBB || // BT/BTS/BTR/BTC
            op == 0xBC || op == 0xBD ||                 // BSF/BSR
            op == 0xAF ||                               // IMUL
            op == 0xB6 || op == 0xB7 ||                 // MOVZX 8/16
            op == 0xBE || op == 0xBF ||                 // MOVSX 8/16
            (op >= 0x40 && op <= 0x4F) ||               // CMOVcc
            (op >= 0x90 && op <= 0x9F) ||               // SETcc
            (op >= 0x10 && op <= 0x17) ||               // SSE MOV
            (op >= 0x28 && op <= 0x2F) ||               // SSE MOV
            op == 0x10 || op == 0x11 ||                 // MOVSS/MOVSD
            op == 0xB8 ||                               // POPCNT (need pfx F3, but length same)
            op == 0xB9 ||                               // UD1 (illegal, but 2+modrm)
            op == 0xAE ||                               // LDMXCSR/STMXCSR/SFENCE group (modrm)
            op == 0x00 || op == 0x01 ||                 // SLDT/SGDT etc. (modrm)
            op == 0x02 || op == 0x03)                   // LAR/LSL
        {
            return n + modrm_bytes(p + n);
        }

        // 2-byte ops with ModRM + imm8
        if (op == 0xC2 || op == 0xC4 || op == 0xC5 || op == 0xC6) // SSE CMP/PINSRW/PEXTRW
            return n + modrm_bytes(p + n) + 1;

        // 3-byte escape (0F 38 xx or 0F 3A xx)
        if (op == 0x38) { n++; return n + modrm_bytes(p + n); }
        if (op == 0x3A) { n++; return n + modrm_bytes(p + n) + 1; }

        // WRMSR/RDMSR/RDTSC etc (no operands)
        if (op == 0x30 || op == 0x31 || op == 0x32 || op == 0x33 ||
            op == 0x34 || op == 0x78 || op == 0x79 || op == 0x0D ||
            op == 0x77 || op == 0xA0 || op == 0xA1 || op == 0xA8 || op == 0xA9)
            return n;

        // SSE no-ModRM 0-operand
        if (op == 0xC8 || op == 0xC9 || op == 0xCA || op == 0xCB ||
            op == 0xCC || op == 0xCD || op == 0xCE || op == 0xCF) return n; // BSWAP
        if (op == 0x05 || op == 0x06 || op == 0x07 || op == 0x08 ||
            op == 0x09 || op == 0x0A || op == 0x0B) return n;

        return 0; // unrecognized 2-byte
    }

    // ---- One-byte opcodes ----

    // No operands (single byte)
    if ((op >= 0x50 && op <= 0x5F) || // PUSH/POP reg
        op == 0x90 || op == 0x91 || op == 0x92 || op == 0x93 ||  // NOP/XCHG
        op == 0x94 || op == 0x95 || op == 0x96 || op == 0x97 ||
        op == 0x98 || op == 0x99 || op == 0x9C || op == 0x9D ||   // CBW/CDQ/PUSHF/POPF
        op == 0x9E || op == 0x9F ||
        op == 0xA4 || op == 0xA5 || op == 0xA6 || op == 0xA7 ||   // MOVS/CMPS
        op == 0xAA || op == 0xAB || op == 0xAC || op == 0xAD ||   // STOS/LODS
        op == 0xAE || op == 0xAF ||                                // SCAS
        op == 0xC3 || op == 0xC9 || op == 0xCB ||                 // RET/LEAVE/RETF
        op == 0xF1 || op == 0xF4 || op == 0xF5 ||                 // INT1/HLT/CMC
        op == 0xF8 || op == 0xF9 || op == 0xFA || op == 0xFB ||   // CLC/STC/CLI/STI
        op == 0xFC || op == 0xFD || op == 0xCC)                   // CLD/STD/INT3
        return n;

    // IMM8 only
    if (op == 0x6A || op == 0x6B || op == 0xEB || op == 0xCD ||
        (op >= 0x70 && op <= 0x7F) ||                              // Jcc short
        op == 0xD4 || op == 0xD5 || op == 0xE0 || op == 0xE1 ||
        op == 0xE2 || op == 0xE3)
        return n + 1;

    // IMM16
    if (op == 0xC2 || op == 0xCA) return n + 2; // RET imm16

    // IMM32
    if (op == 0x68 || op == 0xE8 || op == 0xE9) return n + 4; // PUSH/CALL/JMP rel32

    // MOV reg, imm (B8..BF) - imm64 with REX.W, imm32 otherwise
    if (op >= 0xB8 && op <= 0xBF) return n + (W ? 8 : 4);
    // MOV reg8, imm8 (B0..B7)
    if (op >= 0xB0 && op <= 0xB7) return n + 1;

    // ModRM, no immediate
    if ((op >= 0x00 && op <= 0x03) || (op >= 0x08 && op <= 0x0B) ||
        (op >= 0x10 && op <= 0x13) || (op >= 0x18 && op <= 0x1B) ||
        (op >= 0x20 && op <= 0x23) || (op >= 0x28 && op <= 0x2B) ||
        (op >= 0x30 && op <= 0x33) || (op >= 0x38 && op <= 0x3B) ||
        (op >= 0x84 && op <= 0x8F) ||  // TEST, XCHG, MOV, LEA, POP r/m
        op == 0x62 || op == 0x63 ||    // EVEX / MOVSXD
        (op >= 0xD0 && op <= 0xD3) ||  // Shift (no extra imm for D0/D1)
        op == 0xFF || op == 0xFE ||    // INC/DEC/CALL/JMP/PUSH group
        op == 0xF6 || op == 0xF7)      // TEST(imm)/NOT/NEG/MUL/DIV group
    {
        int extra = modrm_bytes(p + n);
        // F6/F7 group: TEST (/0) has an immediate after ModRM
        if ((op == 0xF6 || op == 0xF7) && ((p[n] >> 3) & 7) == 0) {
            return n + extra + (op == 0xF6 ? 1 : (W ? 8 : 4));
        }
        return n + extra;
    }

    // ModRM + imm8
    if (op == 0x80 || op == 0x82 || op == 0x83 ||
        op == 0xC0 || op == 0xC1 ||    // Shift imm8
        op == 0xC6)                    // MOV r/m8, imm8
        return n + modrm_bytes(p + n) + 1;

    // ModRM + imm16/32 (sign-extended)
    if (op == 0x81 || op == 0xC7)      // Group1 imm32 / MOV r/m, imm32
        return n + modrm_bytes(p + n) + (W && op == 0xC7 ? 4 : 4);

    // IMUL reg, r/m, imm8
    if (op == 0x6B) return n + modrm_bytes(p + n) + 1;
    // IMUL reg, r/m, imm32
    if (op == 0x69) return n + modrm_bytes(p + n) + 4;

    // IN/OUT (no ModRM)
    if (op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7) return n + 1;
    if (op == 0xEC || op == 0xED || op == 0xEE || op == 0xEF) return n;

    // ENTER (special)
    if (op == 0xC8) return n + 3;

    // Far JMP/CALL
    if (op == 0xEA || op == 0x9A) return n + 6;

    // LES/LDS with ModRM
    if (op == 0xC4 || op == 0xC5) return n + modrm_bytes(p + n);

    // MOV AL/AX, moffs and vice versa (A0..A3)
    if (op >= 0xA0 && op <= 0xA3) return n + 8; // 64-bit address

    return 0; // unrecognized
}

int ldisasm_aligned(const UINT8 *p, int min_bytes) {
    int total = 0;
    while (total < min_bytes) {
        int len = ldisasm(p + total);
        if (len <= 0 || len > 15) return 0;
        total += len;
        if (total > 64) return 0; // safety
    }
    return total;
}
