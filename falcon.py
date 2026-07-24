# ----------------------------------------------------------------------
# NVIDIA Falcon processor module for IDA Pro
# Generated from objdump analysis of Falcon firmware
#
# Falcon is a proprietary RISC-like microcontroller embedded in NVIDIA GPUs.
# Instruction encoding reverse-engineered from g_c85b6_ga100.objdump
# Architecture reference: IDA Pro msp430.py processor module
#
# This module provides:
#  - instruction decoding and printing
#  - code cross-references
#  - stack pointer tracing
# ----------------------------------------------------------------------

import sys
import copy

from ida_bytes import *
from ida_ua import *
from ida_idp import *
from ida_auto import *
from ida_nalt import *
from ida_funcs import *
from ida_lines import *
from ida_problems import *
from ida_offset import *
from ida_segment import *
from ida_name import *
from ida_netnode import *
from ida_xref import *
from ida_idaapi import *
import ida_frame
import idc

if sys.version_info.major < 3:
    range = xrange


def BITS(val, high, low):
    return (val >> low) & ((1 << (high - low + 1)) - 1)


def BIT(val, bit):
    return (val >> bit) & 1


def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m


# ----------------------------------------------------------------------
# Instruction size modes (bits [7:6] of first byte)
SZ_BYTE = 0   # .b
SZ_HALF = 1   # .h
SZ_WORD = 2   # .w

# auxpref flags
AUX_SIZEMASK = 0x03
AUX_NOSUF    = 0x04  # no size suffix (for control/stack/misc)

# Subop codes for 0xbc/0xbb/0x3c/0x7c/0xb6 families
SOP_ADD  = 0
SOP_ADDC = 1
SOP_SUB  = 2
SOP_SUBC = 3
SOP_LSL  = 4
SOP_LSR  = 5
SOP_LDD  = 8
SOP_STD  = 9

# Subop codes for 0xf0/0xf1 families
F0_MULU  = 0
F0_MULS  = 1
F0_SEXT  = 2
F0_SETHI = 3
F0_AND   = 4
F0_OR    = 5
F0_XOR   = 6
F0_SETB  = 9
F0_SGETB = 12

# Branch subop codes (0xf4 byte2)
BROP_ADDSP  = 0x30
BROP_BRC    = 0x08
BROP_BREQ   = 0x0B
BROP_BRGT   = 0x0C
BROP_BRLTE  = 0x0D
BROP_BRNC   = 0x18
BROP_BRNE   = 0x1B
BROP_BRSGT  = 0x1C
BROP_BRSLTE = 0x1D
BROP_BRSLT  = 0x1E
BROP_BRSGTE = 0x1F

# SP register alias
IREG_SP = 15  # a15 is SP


class falcon_processor_t(processor_t):
    """Falcon processor module"""

    id = 0x8000 + 0xFA
    flag = PR_SEGS | PRN_HEX | PR_RNAMESOK | PR_WORD_INS | PR_USE32 | PR_DEFSEG32
    cnbits = 8
    dnbits = 8

    psnames = ['falcon']
    plnames = ['NVIDIA Falcon']

    segreg_size = 0

    codestart = ['\xd0\xc0\x5f\x00\x00']  # mvi a0, 0x5fc0 (typical init)
    retcodes  = ['\xf8\x00']               # ret

    # ------------------------------------------------------------------
    # Instruction table
    # ------------------------------------------------------------------
    instruc = [
        {'name': '',       'feature': 0},
        {'name': 'mvi',    'feature': CF_USE1 | CF_CHG1,       'cmt': "Move immediate to register"},
        {'name': 'add',    'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Add"},
        {'name': 'sub',    'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Subtract"},
        {'name': 'subc',   'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Subtract with carry"},
        {'name': 'addc',   'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Add with carry"},
        {'name': 'lsl',    'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Logical shift left"},
        {'name': 'lsr',    'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Logical shift right"},
        {'name': 'asr',    'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Arithmetic shift right"},
        {'name': 'lsrc',   'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Logical shift right with carry"},
        {'name': 'ldd',    'feature': CF_USE1 | CF_CHG1,         'cmt': "Load from data memory"},
        {'name': 'std',    'feature': CF_USE1 | CF_USE2,         'cmt': "Store to data memory"},
        {'name': 'lddsp',  'feature': CF_USE1 | CF_CHG1,         'cmt': "Load from data memory (SP-relative)"},
        {'name': 'stdsp',  'feature': CF_USE1 | CF_USE2,         'cmt': "Store to data memory (SP-relative)"},
        {'name': 'ldx',    'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': "Load from code memory"},
        {'name': 'ldxb',   'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': "Load byte from code memory"},
        {'name': 'mv',     'feature': CF_USE1 | CF_CHG1,         'cmt': "Move register"},
        {'name': 'cmp',    'feature': CF_USE1 | CF_USE2,         'cmt': "Compare"},
        {'name': 'clr',    'feature': CF_CHG1,                   'cmt': "Clear register"},
        {'name': 'cpl',    'feature': CF_USE1 | CF_CHG1,         'cmt': "Complement register"},
        {'name': 'neg',    'feature': CF_USE1 | CF_CHG1,         'cmt': "Negate register"},
        {'name': 'cmpbreq','feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP, 'cmt': "Compare and branch if equal"},
        {'name': 'cmpbrne','feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP, 'cmt': "Compare and branch if not equal"},
        {'name': 'jmp',    'feature': CF_USE1 | CF_STOP,         'cmt': "Unconditional jump"},
        {'name': 'call',   'feature': CF_USE1 | CF_CALL,         'cmt': "Call subroutine"},
        {'name': 'brc',    'feature': CF_USE1 | CF_JUMP,         'cmt': "Branch if carry"},
        {'name': 'breq',   'feature': CF_USE1 | CF_JUMP,         'cmt': "Branch if equal"},
        {'name': 'brne',   'feature': CF_USE1 | CF_JUMP,         'cmt': "Branch if not equal"},
        {'name': 'brgt',   'feature': CF_USE1 | CF_JUMP,         'cmt': "Branch if greater than (unsigned)"},
        {'name': 'brlte',  'feature': CF_USE1 | CF_JUMP,         'cmt': "Branch if less than or equal (unsigned)"},
        {'name': 'brnc',   'feature': CF_USE1 | CF_JUMP,         'cmt': "Branch if not carry"},
        {'name': 'brsgt',  'feature': CF_USE1 | CF_JUMP,         'cmt': "Branch if signed greater than"},
        {'name': 'brslte', 'feature': CF_USE1 | CF_JUMP,         'cmt': "Branch if signed less than or equal"},
        {'name': 'brslt',  'feature': CF_USE1 | CF_JUMP,         'cmt': "Branch if signed less than"},
        {'name': 'brsgte', 'feature': CF_USE1 | CF_JUMP,         'cmt': "Branch if signed greater than or equal"},
        {'name': 'ret',    'feature': CF_STOP,                   'cmt': "Return from subroutine"},
        {'name': 'reti',   'feature': CF_STOP,                   'cmt': "Return from interrupt"},
        {'name': 'halt',   'feature': CF_STOP,                   'cmt': "Halt processor"},
        {'name': 'trap0',  'feature': CF_STOP,                   'cmt': "Trap 0"},
        {'name': 'trap1',  'feature': CF_STOP,                   'cmt': "Trap 1"},
        {'name': 'wait',   'feature': CF_USE1 | CF_JUMP,         'cmt': "Wait"},
        {'name': 'push',   'feature': CF_USE1,                   'cmt': "Push register onto stack"},
        {'name': 'pushm',  'feature': CF_USE1,                   'cmt': "Push multiple registers"},
        {'name': 'pop',    'feature': CF_CHG1,                   'cmt': "Pop register from stack"},
        {'name': 'popm',   'feature': CF_CHG1,                   'cmt': "Pop multiple registers"},
        {'name': 'popma',  'feature': CF_CHG1,                   'cmt': "Pop multiple registers with adjust"},
        {'name': 'popmb',  'feature': CF_CHG1,                   'cmt': "Pop multiple registers (byte)"},
        {'name': 'addsp',  'feature': CF_USE1 | CF_CHG1,         'cmt': "Add to stack pointer"},
        {'name': 'and',    'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': "Bitwise AND"},
        {'name': 'or',     'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': "Bitwise OR"},
        {'name': 'xor',    'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': "Bitwise XOR"},
        {'name': 'sethi',  'feature': CF_CHG1,                   'cmt': "Set high bits"},
        {'name': 'mulu',   'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Multiply unsigned"},
        {'name': 'muls',   'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Multiply signed"},
        {'name': 'sext',   'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': "Sign extend"},
        {'name': 'uxtr',   'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Unsigned extract"},
        {'name': 'sxtr',   'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Signed extract"},
        {'name': 'wspr',   'feature': CF_USE1,                   'cmt': "Write SPR"},
        {'name': 'rspr',   'feature': CF_CHG1,                   'cmt': "Read SPR"},
        {'name': 'udiv',   'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Unsigned divide"},
        {'name': 'umod',   'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Unsigned modulo"},
        {'name': 'mrg',    'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'cmt': "Merge"},
        {'name': 'dmread', 'feature': CF_USE1 | CF_CHG1,         'cmt': "Read from data memory"},
        {'name': 'dmwrite','feature': CF_USE1 | CF_USE2,         'cmt': "Write to data memory"},
        {'name': 'imread', 'feature': CF_USE1 | CF_CHG1,         'cmt': "Read from instruction memory"},
        {'name': 'dminv',  'feature': CF_USE1,                   'cmt': "Invalidate data memory"},
        {'name': 'iminv',  'feature': CF_USE1,                   'cmt': "Invalidate instruction memory"},
        {'name': 'dmwait', 'feature': CF_USE1,                   'cmt': "Wait for data memory operation"},
        {'name': 'imwait', 'feature': CF_USE1,                   'cmt': "Wait for instruction memory operation"},
        {'name': 'dmtag',  'feature': CF_USE1 | CF_USE2,         'cmt': "Data memory tag operation"},
        {'name': 'imtag',  'feature': CF_USE1 | CF_USE2,         'cmt': "Instruction memory tag operation"},
        {'name': 'imblk',  'feature': CF_USE1 | CF_USE2,         'cmt': "Instruction memory block operation"},
        {'name': 'dmblk',  'feature': CF_USE1 | CF_USE2,         'cmt': "Data memory block operation"},
        {'name': 'setdtag','feature': CF_USE1 | CF_USE2,         'cmt': "Set data tag"},
        {'name': 'stx',    'feature': CF_USE1 | CF_USE2,         'cmt': "Store to code memory"},
        {'name': 'stxb',   'feature': CF_USE1 | CF_USE2,         'cmt': "Store byte to code memory"},
        {'name': 'setb',   'feature': CF_USE1 | CF_CHG1,         'cmt': "Set bit"},
        {'name': 'sclrb',  'feature': CF_USE1 | CF_CHG1,         'cmt': "Set and clear bit"},
        {'name': 'sgetb',  'feature': CF_USE1 | CF_CHG1,         'cmt': "Set and get bit"},
        {'name': 'ssetb',  'feature': CF_USE1 | CF_USE2,         'cmt': "Set bit in memory"},
        {'name': 'cci',    'feature': 0,                          'cmt': "Cache coherence invalidate"},
    ]

    instruc_start = 0
    instruc_end = len(instruc) + 1

    assembler = {
        'flag': ASH_HEXF0 | ASD_DECF0 | ASO_OCTF5 | ASB_BINF0 | AS_N2CHR,
        'uflag': 0,
        'name': "Generic Falcon assembler",
        'header': [".falcon"],
        'origin': ".org",
        'end': ".end",
        'cmnt': ";",
        'ascsep': "\"",
        'accsep': "'",
        'esccodes': "\"'",
        'a_ascii': ".char",
        'a_byte': ".byte",
        'a_word': ".short",
        'a_dword': ".long",
        'a_qword': ".quad",
        'a_float': ".float",
        'a_double': ".double",
        'a_bss': ".space %s",
        'a_equ': ".equ",
        'a_seg': "seg",
        'a_curip': "$",
        'a_public': ".def",
        'a_weak': "",
        'a_extrn': ".ref",
        'a_comdef': "",
        'a_align': ".align",
        'lbrace': "(",
        'rbrace': ")",
        'a_mod': "%",
        'a_band': "&",
        'a_bor': "|",
        'a_xor': "^",
        'a_bnot': "~",
        'a_shl': "<<",
        'a_shr': ">>",
        'a_sizeof_fmt': "size %s",
        'flag2': 0,
        'a_include_fmt': '.include "%s"',
    }

    def __init__(self):
        processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

    def init_instructions(self):
        i = 0
        for x in self.instruc:
            if x['name'] != '':
                setattr(self, 'itype_' + x['name'], i)
            else:
                setattr(self, 'itype_null', i)
            i += 1
        self.instruc_end = len(self.instruc)
        self.icode_return = self.itype_ret

    # SPR ID to register name mapping (indices 18+)
    SPR_NAMES = {0: 'IV0', 1: 'IV1', 3: 'EV', 4: 'SP', 7: 'DMB', 8: 'CSW', 0xB: 'CTX', 0xC: 'EXCI', 0xF: 'DMB1'}

    def spr_name(self, spr_id):
        return self.SPR_NAMES.get(spr_id, 'spr%d' % spr_id)

    def init_registers(self):
        self.reg_names = [
            "a0",  "a1",  "a2",  "a3",
            "a4",  "a5",  "a6",  "a7",
            "a8",  "a9",  "a10", "a11",
            "a12", "a13", "a14", "a15",
            "CS", "DS",
        ]
        # Add SPR registers (indices 18+)
        for spr_id in range(16):
            if spr_id in self.SPR_NAMES:
                self.reg_names.append(self.SPR_NAMES[spr_id])
            else:
                self.reg_names.append('spr%d' % spr_id)

        for i in range(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i], i)

        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg  = self.ireg_DS
        self.reg_code_sreg  = self.ireg_CS
        self.reg_data_sreg  = self.ireg_DS
        self.ireg_SP_spr = 18 + 4  # SP as SPR (index 22)

    # ------------------------------------------------------------------
    # Byte reading helpers (Falcon instruction can start at odd address)
    # ------------------------------------------------------------------
    @staticmethod
    def rd_byte(ea, off):
        return get_wide_byte(ea + off)

    @staticmethod
    def rd_word_le(ea, off):
        lo = get_wide_byte(ea + off)
        hi = get_wide_byte(ea + off + 1)
        return (hi << 8) | lo

    @staticmethod
    def sz_from_b0(b0):
        return BITS(b0, 7, 6)

    @staticmethod
    def dtype_from_sz(sz):
        if sz == SZ_BYTE:
            return dt_byte
        elif sz == SZ_HALF:
            return dt_word
        else:
            return dt_dword

    # ------------------------------------------------------------------
    # Fill two operands from reg_byte = (src << 4 | dst)
    # ------------------------------------------------------------------
    def fill_2reg(self, insn, reg_byte, op_dst, op_src, dtyp):
        src = BITS(reg_byte, 7, 4)
        dst = BITS(reg_byte, 3, 0)
        op_dst.type = o_reg
        op_dst.reg  = dst
        op_dst.dtype = dtyp
        op_src.type = o_reg
        op_src.reg  = src
        op_src.dtype = dtyp

    # ------------------------------------------------------------------
    # Fill three operands from 3-reg encoding
    #   b2 = (src1 << 4 | src2),  b3 = (dst << 4 | subop)
    # ------------------------------------------------------------------
    def fill_3reg(self, insn, b2, b3, op_dst, op_src1, op_src2, dtyp):
        src1 = BITS(b2, 7, 4)
        src2 = BITS(b2, 3, 0)
        dst  = BITS(b3, 7, 4)
        op_dst.type = o_reg
        op_dst.reg  = dst
        op_dst.dtype = dtyp
        op_src1.type = o_reg
        op_src1.reg  = src1
        op_src1.dtype = dtyp
        op_src2.type = o_reg
        op_src2.reg  = src2
        op_src2.dtype = dtyp

    # ------------------------------------------------------------------
    # ev_get_autocmt
    # ------------------------------------------------------------------
    def ev_get_autocmt(self, insn):
        if insn.itype < len(self.instruc):
            if 'cmt' in self.instruc[insn.itype]:
                return self.instruc[insn.itype]['cmt']
        return ""

    # ------------------------------------------------------------------
    # ev_is_sane_insn
    # ------------------------------------------------------------------
    def ev_is_sane_insn(self, insn, no_crefs):
        w = get_wide_word(insn.ea)
        if w == 0 or w == 0xFFFF:
            return -1
        return 1

    # ==================================================================
    #  DECODE FUNCTIONS
    # ==================================================================

    # -- mvi: move immediate --------------------------------------------
    #   bits[7:6] = immediate size: 00=imm8, 01=imm16, 10=imm24, 11=imm32
    #   bits[5:4] = 00 for imm8/imm16/imm24, 01 for imm32 (i.e. 0xD_)
    #   bits[3:0] = destination register
    #   MSB of immediate determines sign: 1=negative, 0=positive
    # ------------------------------------------------------------------
    def decode_mvi(self, insn, ea):
        b0 = self.rd_byte(ea, 0)
        ilen = 1 + BITS(b0, 7, 6)  # 1, 2, 3, or 4 bytes of immediate
        dst_reg = BITS(b0, 3, 0)

        imm = 0
        for i in range(ilen):
            imm |= self.rd_byte(ea, 1 + i) << (i * 8)

        if imm & (1 << (ilen * 8 - 1)):
            imm = SIGNEXT(imm, ilen * 8)

        insn.itype = self.itype_mvi
        insn.Op1.type = o_reg
        insn.Op1.reg  = dst_reg
        insn.Op1.dtype = dt_dword
        insn.Op2.type = o_imm
        insn.Op2.dtype = dt_dword
        insn.Op2.value = imm
        insn.auxpref = AUX_NOSUF
        insn.size = 1 + ilen
        return True

    # -- Two-byte instructions -------------------------------------------
    def decode_2byte(self, insn, ea, b0, b1):
        sz = self.sz_from_b0(b0)
        dtyp = self.dtype_from_sz(sz)
        opl = b0 & 0x3F

        if opl in (0x20, 0x60, 0xA0):
            # std: src in bits[7:4], base in bits[3:0]
            insn.itype = self.itype_std
            src = BITS(b1, 7, 4)
            base = BITS(b1, 3, 0)
            insn.Op1.type = o_reg; insn.Op1.reg = src; insn.Op1.dtype = dtyp
            insn.Op2.type = o_displ; insn.Op2.reg = base; insn.Op2.dtype = dtyp
            insn.Op2.addr = 0
        elif opl in (0x26, 0x66, 0xA6):
            insn.itype = self.itype_cmp
            self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
        elif opl in (0x32, 0x72, 0xB2):
            insn.itype = self.itype_mv
            self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
        elif opl in (0x3D, 0x7D, 0xBD):
            # clr (subop=4) vs cpl (subop=0) vs neg (subop=5)
            reg = BITS(b1, 7, 4)
            sub = BITS(b1, 3, 0)
            if sub == 4:
                insn.itype = self.itype_clr
                insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dtyp
            elif sub == 5:
                insn.itype = self.itype_neg
                insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dtyp
            else:
                insn.itype = self.itype_cpl
                insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dtyp
        elif opl in (0x3F, 0x7F, 0xBF):
            insn.itype = self.itype_ldd
            base = BITS(b1, 7, 4)
            dst  = BITS(b1, 3, 0)
            insn.Op1.type = o_reg; insn.Op1.reg = dst; insn.Op1.dtype = dtyp
            insn.Op2.type = o_displ; insn.Op2.reg = base; insn.Op2.dtype = dtyp
            insn.Op2.addr = 0
        else:
            return False
        insn.auxpref = sz
        insn.size = 2
        return True

    # -- 3-byte instructions with imm8 -----------------------------------
    def decode_3byte_imm8(self, insn, ea, b0, b1):
        sz = self.sz_from_b0(b0)
        dtyp = self.dtype_from_sz(sz)
        opl = b0 & 0x3F
        imm8 = self.rd_byte(ea, 2)

        if opl in (0x10, 0x50, 0x90):
            insn.itype = self.itype_add
            self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
            insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm8
        elif opl in (0x11, 0x51, 0x91):
            insn.itype = self.itype_addc
            self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
            insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm8
        elif opl in (0x12, 0x52, 0x92):
            insn.itype = self.itype_sub
            self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
            insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm8
        elif opl in (0x13, 0x53, 0x93):
            insn.itype = self.itype_subc
            self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
            insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm8
        elif opl in (0x14, 0x54, 0x94):
            insn.itype = self.itype_lsl
            self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
            insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm8
        elif opl in (0x15, 0x55, 0x95):
            insn.itype = self.itype_lsr
            self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
            insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm8
        elif opl in (0x17, 0x57, 0x97):
            insn.itype = self.itype_asr
            self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
            insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm8
        elif opl in (0x1D, 0x5D, 0x9D):
            insn.itype = self.itype_lsrc
            self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
            insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm8
        elif opl in (0x18, 0x58, 0x98):
            # ldd: base in bits[7:4], dst in bits[3:0], imm8 offset
            insn.itype = self.itype_ldd
            base = BITS(b1, 7, 4)
            dst  = BITS(b1, 3, 0)
            insn.Op1.type = o_reg; insn.Op1.reg = dst; insn.Op1.dtype = dtyp
            insn.Op2.type = o_displ; insn.Op2.reg = base; insn.Op2.dtype = dtyp
            insn.Op2.addr = imm8 << sz
        elif opl in (0x30, 0x70, 0xB0):
            # cmp (byte2[3:0]==6) or stdsp (byte2[3:0]==1)
            if BITS(b1, 3, 0) == 6:
                insn.itype = self.itype_cmp
                insn.Op1.type = o_reg; insn.Op1.reg = BITS(b1, 7, 4); insn.Op1.dtype = dtyp
                insn.Op2.type = o_imm; insn.Op2.dtype = dtyp; insn.Op2.value = imm8
            else:
                insn.itype = self.itype_stdsp
                src = BITS(b1, 7, 4)
                insn.Op1.type = o_reg; insn.Op1.reg = src; insn.Op1.dtype = dtyp
                insn.Op2.type = o_displ; insn.Op2.reg = IREG_SP
                insn.Op2.dtype = dtyp; insn.Op2.addr = imm8 << sz
        elif opl in (0x34, 0x74, 0xB4):
            insn.itype = self.itype_lddsp
            dst = BITS(b1, 7, 4)
            insn.Op1.type = o_reg; insn.Op1.reg = dst; insn.Op1.dtype = dtyp
            insn.Op2.type = o_displ; insn.Op2.reg = IREG_SP
            insn.Op2.dtype = dtyp; insn.Op2.addr = imm8 << sz
        elif opl in (0x35, 0x75, 0xB5):
            # std with imm8 offset
            insn.itype = self.itype_std
            src = BITS(b1, 7, 4)
            base = BITS(b1, 3, 0)
            insn.Op1.type = o_reg; insn.Op1.reg = src; insn.Op1.dtype = dtyp
            insn.Op2.type = o_displ; insn.Op2.reg = base
            insn.Op2.dtype = dtyp; insn.Op2.addr = imm8 << sz
        elif opl in (0x36, 0x76, 0xB6):
            # lsl (subop=4), lsr (subop=5), asr (subop=7)
            sub = BITS(b1, 3, 0)
            if sub == SOP_LSR:
                insn.itype = self.itype_lsr
            elif sub == 7:
                insn.itype = self.itype_asr
            else:
                insn.itype = self.itype_lsl
            insn.Op1.type = o_reg; insn.Op1.reg = BITS(b1, 7, 4); insn.Op1.dtype = dtyp
            insn.Op2.type = o_imm; insn.Op2.dtype = dtyp; insn.Op2.value = imm8
        elif opl in (0x3B, 0x7B):
            insn.itype = self.itype_sub
            self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
            insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm8
        elif opl in (0x19, 0x39):
            # cpl / neg with imm8 (2-reg + imm8)
            # b0=0x19 (byte), 0x79 (half), 0xB9 (word) — all have opl=0x19 or 0x39
            src = BITS(b1, 7, 4)
            dst = BITS(b1, 3, 0)
            if imm8 == 0x01:
                insn.itype = self.itype_neg
            else:
                insn.itype = self.itype_cpl
            insn.Op1.type = o_reg; insn.Op1.reg = dst; insn.Op1.dtype = dtyp
            insn.Op2.type = o_reg; insn.Op2.reg = src; insn.Op2.dtype = dtyp
            insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm8
        else:
            return False
        insn.auxpref = sz
        insn.size = 3
        return True

    # -- 4-byte cmp (0x31/0x71/0xB1) -----------------------------------
    def decode_cmp_imm16(self, insn, ea, b0, b1):
        sz = self.sz_from_b0(b0)
        dtyp = self.dtype_from_sz(sz)
        imm16 = self.rd_word_le(ea, 2)
        insn.itype = self.itype_cmp
        self.fill_2reg(insn, b1, insn.Op1, insn.Op2, dtyp)
        insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm16
        insn.auxpref = sz
        insn.size = 4
        return True

    # -- cmpbreq / cmpbrne (0x33/0x73/0xB3) -----------------------------
    def decode_cmpbr(self, insn, ea, b0, b1):
        sz = self.sz_from_b0(b0)
        dtyp = self.dtype_from_sz(sz)
        reg   = BITS(b1, 7, 4)
        subop = BITS(b1, 3, 0)

        # subop & 8: offset is 16-bit; else offset is 8-bit
        # (subop & 3) == 3: immediate is 16-bit (only when offset is 16-bit)
        # subop & 4: 0=cmpbreq, 1=cmpbrne
        if subop & 8:
            if (subop & 3) == 3:
                imm = self.rd_word_le(ea, 2)
                off = SIGNEXT(self.rd_word_le(ea, 4), 16)
                insn.size = 6
            elif (subop & 3) == 2:
                imm = self.rd_word_le(ea, 2)
                off = SIGNEXT(self.rd_byte(ea, 4), 8)
                insn.size = 5
            else:
                imm = self.rd_byte(ea, 2)
                off = SIGNEXT(self.rd_word_le(ea, 3), 16)
                insn.size = 5
        else:
            imm = self.rd_byte(ea, 2)
            off = SIGNEXT(self.rd_byte(ea, 3), 8)
            insn.size = 4

        target = (ea + off) & 0xFFFFFFFF

        if subop & 4:
            insn.itype = self.itype_cmpbrne
        else:
            insn.itype = self.itype_cmpbreq

        insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dtyp
        insn.Op2.type = o_imm; insn.Op2.dtype = dtyp; insn.Op2.value = imm
        insn.Op3.type = o_near; insn.Op3.dtype = dt_code; insn.Op3.addr = target
        insn.auxpref = sz
        return True

    # -- jmp: 0x3E, 4 bytes (24-bit absolute address, LE, at ea+1) ------
    def decode_jmp(self, insn, ea):
        addr = self.rd_byte(ea, 1) | (self.rd_byte(ea, 2) << 8) | (self.rd_byte(ea, 3) << 16)
        insn.itype = self.itype_jmp
        insn.Op1.type = o_near; insn.Op1.dtype = dt_code; insn.Op1.addr = addr
        insn.auxpref = AUX_NOSUF
        insn.size = 4
        return True

    # -- call: 0x7E, 4 bytes (24-bit absolute address, LE, at ea+1) -----
    def decode_call(self, insn, ea):
        addr = self.rd_byte(ea, 1) | (self.rd_byte(ea, 2) << 8) | (self.rd_byte(ea, 3) << 16)
        insn.itype = self.itype_call
        insn.Op1.type = o_near; insn.Op1.dtype = dt_code; insn.Op1.addr = addr
        insn.auxpref = AUX_NOSUF
        insn.size = 4
        return True

    # -- 0xbc family: 3-operand ALU (3 bytes) ---------------------------
    def decode_bc(self, insn, ea, b1):
        b2 = self.rd_byte(ea, 2)
        subop = BITS(b2, 3, 0)
        M = {SOP_ADD: self.itype_add, SOP_ADDC: self.itype_addc,
             SOP_SUB: self.itype_sub, SOP_SUBC: self.itype_subc,
             SOP_LSL: self.itype_lsl, SOP_LSR: self.itype_lsr,
             SOP_LDD: self.itype_ldd, SOP_STD: self.itype_std}
        insn.itype = M.get(subop, self.itype_add)
        self.fill_3reg(insn, b1, b2, insn.Op1, insn.Op2, insn.Op3, dt_dword)
        insn.auxpref = SZ_WORD
        insn.size = 3
        return True

    # -- 0xbb family: 3-operand ALU extended (3 bytes) ------------------
    def decode_bb(self, insn, ea, b1):
        b2 = self.rd_byte(ea, 2)
        subop = BITS(b2, 3, 0)
        M = {SOP_ADD: self.itype_add, SOP_SUB: self.itype_sub,
             SOP_SUBC: self.itype_subc, SOP_LSL: self.itype_lsl,
             SOP_LSR: self.itype_lsr}
        insn.itype = M.get(subop, self.itype_add)
        self.fill_3reg(insn, b1, b2, insn.Op1, insn.Op2, insn.Op3, dt_dword)
        insn.auxpref = SZ_WORD
        insn.size = 3
        return True

    # -- 0x3c / 0x7c / 0xb6: extended 3-operand (3 bytes) ----------------
    def decode_3op_ext(self, insn, ea, b0, b1):
        b2 = self.rd_byte(ea, 2)
        subop = BITS(b2, 3, 0)
        sz = self.sz_from_b0(b0)
        dtyp = self.dtype_from_sz(sz)

        M = {SOP_ADD: self.itype_add, SOP_SUB: self.itype_sub,
             SOP_LSL: self.itype_lsl, SOP_LSR: self.itype_lsr,
             SOP_LDD: self.itype_ldd, SOP_STD: self.itype_std}
        insn.itype = M.get(subop, self.itype_add)

        self.fill_3reg(insn, b1, b2, insn.Op1, insn.Op2, insn.Op3, dtyp)
        insn.auxpref = sz
        insn.size = 3
        return True

    # -- 0xb8: 5-byte ALU with imm16 ------------------------------------
    # -- 0x38/0x78/0xB8: 2-reg + imm16 (5 bytes) ------------------------
    #   byte4[1:0]: 0=add, 2=sub
    def decode_38_78_b8(self, insn, ea, b0, b1):
        sz = self.sz_from_b0(b0)
        dtyp = self.dtype_from_sz(sz)
        imm = self.rd_word_le(ea, 2)
        subop = self.rd_byte(ea, 4)

        insn.itype = self.itype_sub if (subop & 3) == 2 else self.itype_add

        src = BITS(b1, 7, 4)
        dst = BITS(b1, 3, 0)
        insn.Op1.type = o_reg; insn.Op1.reg = dst; insn.Op1.dtype = dtyp
        insn.Op2.type = o_reg; insn.Op2.reg = src; insn.Op2.dtype = dtyp
        insn.Op3.type = o_imm; insn.Op3.dtype = dtyp; insn.Op3.value = imm
        insn.auxpref = sz
        insn.size = 5
        return True

    # -- 0xf0: 1-reg + imm8 (3 bytes) -----------------------------------
    def decode_f0(self, insn, ea, b1):
        reg   = BITS(b1, 7, 4)
        subop = BITS(b1, 3, 0)
        imm8  = self.rd_byte(ea, 2)

        M = {F0_MULU: self.itype_mulu, F0_SEXT: self.itype_sext,
             F0_SETHI: self.itype_sethi, F0_AND: self.itype_and,
             F0_OR: self.itype_or, F0_XOR: self.itype_xor,
             F0_SETB: self.itype_setb, F0_SGETB: self.itype_sgetb}
        insn.itype = M.get(subop, self.itype_and)

        insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dt_dword
        insn.Op2.type = o_imm; insn.Op2.dtype = dt_dword; insn.Op2.value = imm8
        insn.auxpref = AUX_NOSUF
        insn.size = 3
        return True

    # -- 0xf1: 1-reg + imm16 (4 bytes) ----------------------------------
    def decode_f1(self, insn, ea, b1):
        reg   = BITS(b1, 7, 4)
        subop = BITS(b1, 3, 0)
        imm16 = self.rd_word_le(ea, 2)

        M = {F0_MULU: self.itype_mulu, F0_MULS: self.itype_muls,
             F0_SETHI: self.itype_sethi, F0_AND: self.itype_and,
             F0_OR: self.itype_or, F0_XOR: self.itype_xor}
        insn.itype = M.get(subop, self.itype_and)

        insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dt_dword
        insn.Op2.type = o_imm; insn.Op2.dtype = dt_dword; insn.Op2.value = imm16
        insn.auxpref = AUX_NOSUF
        insn.size = 4
        return True

    # -- 0xf4: branches / addsp / cci / wait (3 bytes) --------------------
    def decode_f4(self, insn, ea, b1):
        off8 = self.rd_byte(ea, 2)

        if b1 == BROP_ADDSP:
            insn.itype = self.itype_addsp
            insn.Op1.type = o_imm; insn.Op1.dtype = dt_dword
            insn.Op1.value = SIGNEXT(off8, 8)
        elif b1 == 0x28:
            # wait
            insn.itype = self.itype_wait
            insn.Op1.type = o_imm; insn.Op1.dtype = dt_byte
            insn.Op1.value = off8
        elif b1 == 0x3C:
            # cci
            insn.itype = self.itype_cci
            insn.Op1.type = o_imm; insn.Op1.dtype = dt_byte
            insn.Op1.value = off8
        elif b1 == 0x31:
            # ssetb: set bit in memory
            insn.itype = self.itype_ssetb
            insn.Op1.type = o_imm; insn.Op1.dtype = dt_byte
            insn.Op1.value = off8
        elif b1 == 0x32:
            # sclrb: clear bit in memory
            insn.itype = self.itype_sclrb
            insn.Op1.type = o_imm; insn.Op1.dtype = dt_byte
            insn.Op1.value = off8
        else:
            BR = {BROP_BRC: self.itype_brc, BROP_BREQ: self.itype_breq,
                  BROP_BRGT: self.itype_brgt, BROP_BRLTE: self.itype_brlte,
                  BROP_BRNC: self.itype_brnc, BROP_BRNE: self.itype_brne,
                  BROP_BRSGT: self.itype_brsgt, BROP_BRSLTE: self.itype_brslte,
                  BROP_BRSLT: self.itype_brslt, BROP_BRSGTE: self.itype_brsgte}
            insn.itype = BR.get(b1, self.itype_brc)
            target = (ea + SIGNEXT(off8, 8)) & 0xFFFFFFFF
            insn.Op1.type = o_near; insn.Op1.dtype = dt_code; insn.Op1.addr = target
        insn.auxpref = AUX_NOSUF
        insn.size = 3
        return True

    # -- 0xf5: branches / addsp / cci (4 bytes, imm16 offset) -------------
    def decode_f5(self, insn, ea, b1):
        off16 = self.rd_word_le(ea, 2)

        if b1 == BROP_ADDSP:
            insn.itype = self.itype_addsp
            insn.Op1.type = o_imm; insn.Op1.dtype = dt_dword
            insn.Op1.value = SIGNEXT(off16, 16)
        elif b1 == 0x3C:
            # cci with imm16
            insn.itype = self.itype_cci
            insn.Op1.type = o_imm; insn.Op1.dtype = dt_word
            insn.Op1.value = off16
        else:
            BR = {BROP_BRC: self.itype_brc, BROP_BREQ: self.itype_breq,
                  BROP_BRGT: self.itype_brgt, BROP_BRLTE: self.itype_brlte,
                  BROP_BRNC: self.itype_brnc, BROP_BRNE: self.itype_brne,
                  BROP_BRSGT: self.itype_brsgt, BROP_BRSLTE: self.itype_brslte,
                  BROP_BRSLT: self.itype_brslt, BROP_BRSGTE: self.itype_brsgte}
            insn.itype = BR.get(b1, self.itype_brc)
            target = (ea + SIGNEXT(off16, 16)) & 0xFFFFFFFF
            insn.Op1.type = o_near; insn.Op1.dtype = dt_code; insn.Op1.addr = target
        insn.auxpref = AUX_NOSUF
        insn.size = 4
        return True

    # -- 0xf6 / 0xf7: stx / stxb (3 bytes) ------------------------------
    def decode_stx(self, insn, ea, b0, b1):
        offset = self.rd_byte(ea, 2)
        insn.itype = self.itype_stxb if b0 == 0xF7 else self.itype_stx
        src  = BITS(b1, 3, 0)
        base = BITS(b1, 7, 4)
        insn.Op1.type = o_reg; insn.Op1.reg = src; insn.Op1.dtype = dt_dword
        insn.Op2.type = o_displ; insn.Op2.reg = base
        insn.Op2.dtype = dt_dword; insn.Op2.addr = offset
        insn.auxpref = AUX_NOSUF
        insn.size = 3
        return True

    # -- 0xf8: control (2 bytes) ----------------------------------------
    def decode_f8(self, insn, b1):
        M = {0x00: self.itype_ret, 0x01: self.itype_reti,
             0x02: self.itype_halt, 0x03: self.itype_dmwait,
             0x07: self.itype_imwait,
             0x08: self.itype_trap0, 0x09: self.itype_trap1}
        insn.itype = M.get(b1, self.itype_null)
        insn.auxpref = AUX_NOSUF
        insn.size = 2
        return insn.itype != self.itype_null

    # -- 0xf9: push / pushm / dminv / iminv / call (2 bytes) -------------
    def decode_f9(self, insn, b1):
        reg   = BITS(b1, 7, 4)
        subop = BITS(b1, 3, 0)

        if subop == 0x5:
            # indirect call (call reg)
            insn.itype = self.itype_call
        else:
            M = {0x0: self.itype_push, 0x2: self.itype_pushm,
                 0x3: self.itype_dminv, 0x8: self.itype_iminv}
            insn.itype = M.get(subop, self.itype_push)

        insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dt_dword
        insn.auxpref = AUX_NOSUF
        insn.size = 2
        return True

    # -- 0xfa: IO / memory (3 bytes) -------------------------------------
    def decode_fa(self, insn, ea, b1):
        op   = self.rd_byte(ea, 2)

        M = {0x00: self.itype_stx,     0x04: self.itype_imread,
             0x05: self.itype_dmread,   0x06: self.itype_dmwrite,
             0x07: self.itype_setdtag}
        insn.itype = M.get(op, self.itype_dmread)

        if op == 0x00:
            # stx: src in bits[3:0], base in bits[7:4]
            src  = BITS(b1, 3, 0)
            base = BITS(b1, 7, 4)
            insn.Op1.type = o_reg; insn.Op1.reg = src; insn.Op1.dtype = dt_dword
            insn.Op2.type = o_displ; insn.Op2.reg = base
            insn.Op2.dtype = dt_dword; insn.Op2.addr = 0
        else:
            reg1 = BITS(b1, 7, 4)
            reg2 = BITS(b1, 3, 0)
            insn.Op1.type = o_reg; insn.Op1.reg = reg1; insn.Op1.dtype = dt_dword
            insn.Op2.type = o_reg; insn.Op2.reg = reg2; insn.Op2.dtype = dt_dword
        insn.auxpref = AUX_NOSUF
        insn.size = 3
        return True

    # -- 0xfb: popm / popma / popmb (2, 3, or 4 bytes) ----------------
    def decode_fb(self, insn, ea, b1):
        reg   = BITS(b1, 7, 4)
        subop = BITS(b1, 3, 0)

        if subop in (0, 1, 2):
            # popm: 2 bytes, count = subop
            insn.itype = self.itype_popm
            insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dt_dword
            insn.Op2.type = o_imm; insn.Op2.dtype = dt_byte; insn.Op2.value = subop
            insn.size = 2
        elif subop == 3:
            # popmb: 4 bytes, count=1, imm16
            imm16 = self.rd_word_le(ea, 2)
            insn.itype = self.itype_popmb
            insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dt_dword
            insn.Op2.type = o_imm; insn.Op2.dtype = dt_byte; insn.Op2.value = 1
            insn.Op3.type = o_imm; insn.Op3.dtype = dt_dword; insn.Op3.value = imm16
            insn.size = 4
        elif subop in (4, 5, 6, 7):
            # popma: 3 bytes, count=1, imm8
            adj = self.rd_byte(ea, 2)
            insn.itype = self.itype_popma
            insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dt_dword
            insn.Op2.type = o_imm; insn.Op2.dtype = dt_byte; insn.Op2.value = 1
            insn.Op3.type = o_imm; insn.Op3.dtype = dt_byte; insn.Op3.value = adj
            insn.size = 3
        else:
            insn.itype = self.itype_popm
            insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dt_dword
            insn.size = 2
        insn.auxpref = AUX_NOSUF
        return True

    # -- 0xfc: pop (2 bytes) ---------------------------------------------
    def decode_fc(self, insn, b1):
        reg = BITS(b1, 7, 4)
        insn.itype = self.itype_pop
        insn.Op1.type = o_reg; insn.Op1.reg = reg; insn.Op1.dtype = dt_dword
        insn.auxpref = AUX_NOSUF
        insn.size = 2
        return True

    # -- 0xfe: wspr/rspr/imblk/imtag/dmblk/dmtag (3 bytes) --------------
    #   byte2[7:4] = second operand, byte2[3:0] = first operand
    #   byte3: 0x00=wspr, 0x01=rspr, 0x02=imblk, 0x03=imtag, 0x04=dmblk, 0x05=dmtag
    def decode_fe(self, insn, ea, b1):
        first_arg  = BITS(b1, 3, 0)
        second_arg = BITS(b1, 7, 4)
        b2   = self.rd_byte(ea, 2)

        if b2 == 0x00:
            # wspr SPR, src_reg
            insn.itype = self.itype_wspr
            insn.Op1.type = o_reg; insn.Op1.reg = 18 + first_arg
            insn.Op1.dtype = dt_dword
            insn.Op2.type = o_reg; insn.Op2.reg = second_arg
            insn.Op2.dtype = dt_dword
        elif b2 == 0x01:
            # rspr dst_reg, SPR
            insn.itype = self.itype_rspr
            insn.Op1.type = o_reg; insn.Op1.reg = first_arg
            insn.Op1.dtype = dt_dword
            insn.Op2.type = o_reg; insn.Op2.reg = 18 + second_arg
            insn.Op2.dtype = dt_dword
        elif b2 == 0x02:
            # imblk reg, reg
            insn.itype = self.itype_imblk
            insn.Op1.type = o_reg; insn.Op1.reg = first_arg; insn.Op1.dtype = dt_dword
            insn.Op2.type = o_reg; insn.Op2.reg = second_arg; insn.Op2.dtype = dt_dword
        elif b2 == 0x03:
            # imtag reg, reg
            insn.itype = self.itype_imtag
            insn.Op1.type = o_reg; insn.Op1.reg = first_arg; insn.Op1.dtype = dt_dword
            insn.Op2.type = o_reg; insn.Op2.reg = second_arg; insn.Op2.dtype = dt_dword
        elif b2 == 0x04:
            # dmblk reg, reg
            insn.itype = self.itype_dmblk
            insn.Op1.type = o_reg; insn.Op1.reg = first_arg; insn.Op1.dtype = dt_dword
            insn.Op2.type = o_reg; insn.Op2.reg = second_arg; insn.Op2.dtype = dt_dword
        elif b2 == 0x05:
            # dmtag reg, reg
            insn.itype = self.itype_dmtag
            insn.Op1.type = o_reg; insn.Op1.reg = first_arg; insn.Op1.dtype = dt_dword
            insn.Op2.type = o_reg; insn.Op2.reg = second_arg; insn.Op2.dtype = dt_dword
        else:
            insn.itype = self.itype_null
            return False
        insn.auxpref = AUX_NOSUF
        insn.size = 3
        return True

    # -- 0xcf: ldx (3 bytes) ---------------------------------------------
    def decode_cf(self, insn, ea, b1):
        offset = self.rd_byte(ea, 2)
        insn.itype = self.itype_ldx
        base = BITS(b1, 7, 4)
        dst  = BITS(b1, 3, 0)
        insn.Op1.type = o_reg; insn.Op1.reg = dst; insn.Op1.dtype = dt_dword
        insn.Op2.type = o_displ; insn.Op2.reg = base
        insn.Op2.dtype = dt_dword; insn.Op2.addr = offset
        insn.auxpref = AUX_NOSUF
        insn.size = 3
        return True

    # -- 0xce: ldxb (3 bytes, same format as 0xcf but byte access) -----
    def decode_ce(self, insn, ea, b1):
        offset = self.rd_byte(ea, 2)
        insn.itype = self.itype_ldxb
        base = BITS(b1, 7, 4)
        dst  = BITS(b1, 3, 0)
        insn.Op1.type = o_reg; insn.Op1.reg = dst; insn.Op1.dtype = dt_dword
        insn.Op2.type = o_displ; insn.Op2.reg = base
        insn.Op2.dtype = dt_dword; insn.Op2.addr = offset
        insn.auxpref = AUX_NOSUF
        insn.size = 3
        return True

    # -- 0xcX: 2-reg + imm8 (3 bytes) -----------------------------------
    #   All 0xc0..0xcd share the same format:
    #     dst in b1[3:0], src in b1[7:4], imm8 in byte2
    #   (0xcf = ldxb, handled separately)
    def decode_cX_3byte(self, insn, ea, b0, b1):
        imm8 = self.rd_byte(ea, 2)
        M = {0xC0: self.itype_mulu, 0xC2: self.itype_sext,
             0xC4: self.itype_and, 0xC5: self.itype_or,
             0xC6: self.itype_xor, 0xC7: self.itype_uxtr,
             0xCB: self.itype_mrg, 0xCC: self.itype_udiv,
             0xCD: self.itype_umod}
        if b0 not in M:
            return False
        insn.itype = M[b0]
        dst  = BITS(b1, 3, 0)
        src1 = BITS(b1, 7, 4)
        insn.Op1.type = o_reg; insn.Op1.reg = dst; insn.Op1.dtype = dt_dword
        insn.Op2.type = o_reg; insn.Op2.reg = src1; insn.Op2.dtype = dt_dword
        insn.Op3.type = o_imm; insn.Op3.dtype = dt_dword; insn.Op3.value = imm8
        insn.auxpref = AUX_NOSUF
        insn.size = 3
        return True

    # -- 0xeX: 2-reg + imm16 (4 bytes) -----------------------------------
    #   All 0xe0..0xed share the same format:
    #     dst in b1[3:0], src in b1[7:4], imm16 in bytes 2-3 (LE)
    def decode_eX_4byte(self, insn, ea, b0, b1):
        imm16 = self.rd_word_le(ea, 2)
        M = {0xE0: self.itype_mulu, 0xE3: self.itype_sxtr,
             0xE4: self.itype_and, 0xE5: self.itype_or,
             0xE6: self.itype_xor, 0xE7: self.itype_uxtr,
             0xEB: self.itype_mrg, 0xEC: self.itype_udiv,
             0xED: self.itype_umod}
        if b0 not in M:
            return False
        insn.itype = M[b0]
        dst  = BITS(b1, 3, 0)
        src1 = BITS(b1, 7, 4)
        insn.Op1.type = o_reg; insn.Op1.reg = dst; insn.Op1.dtype = dt_dword
        insn.Op2.type = o_reg; insn.Op2.reg = src1; insn.Op2.dtype = dt_dword
        insn.Op3.type = o_imm; insn.Op3.dtype = dt_dword; insn.Op3.value = imm16
        insn.auxpref = AUX_NOSUF
        insn.size = 4
        return True

    # -- 0xfd: 2-reg with subop (3 bytes) ---------------------------------
    #   byte2 = (dst << 4 | src), byte3 = (0 << 4 | subop)
    def decode_fd(self, insn, ea, b1):
        dst   = BITS(b1, 7, 4)
        src   = BITS(b1, 3, 0)
        byte3 = self.rd_byte(ea, 2)
        subop = BITS(byte3, 3, 0)

        # subop: 0=mulu, 1=muls, 4=and, 5=or, 6=xor
        M = {0: self.itype_mulu, 1: self.itype_muls,
             4: self.itype_and, 5: self.itype_or, 6: self.itype_xor}
        insn.itype = M.get(subop, self.itype_and)

        insn.Op1.type = o_reg; insn.Op1.reg = dst; insn.Op1.dtype = dt_dword
        insn.Op2.type = o_reg; insn.Op2.reg = src; insn.Op2.dtype = dt_dword
        insn.auxpref = AUX_NOSUF
        insn.size = 3
        return True

    # -- 0xff: 3-reg with subop (3 bytes) ----------------------------------
    #   byte2 = (src1 << 4 | src2), byte3 = (dst << 4 | subop)
    def decode_ff(self, insn, ea, b1):
        src1 = BITS(b1, 7, 4)
        src2 = BITS(b1, 3, 0)
        byte3 = self.rd_byte(ea, 2)
        dst  = BITS(byte3, 7, 4)
        subop = BITS(byte3, 3, 0)

        # subop: 0=mulu, 1=muls, 4=and, 5=or, 6=xor, 0xc=udiv, 0xd=umod
        M = {0: self.itype_mulu, 1: self.itype_muls,
             4: self.itype_and, 5: self.itype_or, 6: self.itype_xor,
             0xC: self.itype_udiv, 0xD: self.itype_umod}
        insn.itype = M.get(subop, self.itype_and)

        insn.Op1.type = o_reg; insn.Op1.reg = dst; insn.Op1.dtype = dt_dword
        insn.Op2.type = o_reg; insn.Op2.reg = src1; insn.Op2.dtype = dt_dword
        insn.Op3.type = o_reg; insn.Op3.reg = src2; insn.Op3.dtype = dt_dword
        insn.auxpref = AUX_NOSUF
        insn.size = 3
        return True

    # ==================================================================
    #  ev_ana_insn: MAIN DECODE ENTRY POINT
    # ==================================================================
    def ev_ana_insn(self, insn):
        ea = insn.ea

        # Falcon instructions CAN start at odd addresses
        b0 = self.rd_byte(ea, 0)
        b1 = self.rd_byte(ea, 1)

        # --- mvi: 0x00-0x0F, 0x40-0x4F, 0x80-0x8F, 0xD0-0xDF ---
        # Must precede the 00 00 / FF FF invalid-opcode check because
        # mvi a0, 0x0 encodes as 00 00.
        hi_nib = b0 & 0xF0
        if hi_nib == 0x00 or hi_nib == 0x40 or hi_nib == 0x80 or hi_nib == 0xD0:
            return self.decode_mvi(insn, ea)

        # Check for obviously invalid opcodes
        if b0 == 0x00 and b1 == 0x00:
            return 0
        if b0 == 0xFF and b1 == 0xFF:
            return 0

        # --- 0xbc: 3-operand ALU ---
        if b0 == 0xBC:
            return self.decode_bc(insn, ea, b1)

        # --- 0xbb: 3-operand ALU extended ---
        if b0 == 0xBB:
            return self.decode_bb(insn, ea, b1)

        # --- 0x38/0x78/0xB8: 5-byte ALU with imm16 ---
        if b0 in (0x38, 0x78, 0xB8):
            return self.decode_38_78_b8(insn, ea, b0, b1)

        # --- 0x3c / 0x7c: extended 3-operand ---
        # 0xB6 is 2-reg+imm8 (lsl/lsr/asr), handled in decode_3byte_imm8
        if b0 in (0x3C, 0x7C, 0xBC):
            return self.decode_3op_ext(insn, ea, b0, b1)

        # --- 0xf0: 1-reg + imm8 ---
        if b0 == 0xF0:
            return self.decode_f0(insn, ea, b1)

        # --- 0xf1: 1-reg + imm16 ---
        if b0 == 0xF1:
            return self.decode_f1(insn, ea, b1)

        # --- 0xf4: branches / addsp (3 bytes) ---
        if b0 == 0xF4:
            return self.decode_f4(insn, ea, b1)

        # --- 0xf5: branches / addsp (4 bytes, 16-bit offset) ---
        if b0 == 0xF5:
            return self.decode_f5(insn, ea, b1)

        # --- 0xf6 / 0xf7: stx / stxb ---
        if b0 in (0xF6, 0xF7):
            return self.decode_stx(insn, ea, b0, b1)

        # --- 0xf8: control ---
        if b0 == 0xF8:
            return self.decode_f8(insn, b1)

        # --- 0xf9: push / pushm / inv ---
        if b0 == 0xF9:
            return self.decode_f9(insn, b1)

        # --- 0xfa: IO / memory ---
        if b0 == 0xFA:
            return self.decode_fa(insn, ea, b1)

        # --- 0xfb: popm / popma / popmb ---
        if b0 == 0xFB:
            return self.decode_fb(insn, ea, b1)

        # --- 0xfc: pop ---
        if b0 == 0xFC:
            return self.decode_fc(insn, b1)

        # --- 0xfe: wspr / rspr / dmtag / imtag ---
        if b0 == 0xFE:
            return self.decode_fe(insn, ea, b1)

        # --- 0xfd: 2-reg with subop (3 bytes) ---
        if b0 == 0xFD:
            return self.decode_fd(insn, ea, b1)

        # --- 0xff: 3-reg with subop (3 bytes) ---
        if b0 == 0xFF:
            return self.decode_ff(insn, ea, b1)

        # --- 0xce: ldxb ---
        if b0 == 0xCE:
            return self.decode_ce(insn, ea, b1)

        # --- 0xcf: ldx ---
        if b0 == 0xCF:
            return self.decode_cf(insn, ea, b1)

        # --- 0xcX: various 3-byte ---
        if b0 in (0xC0, 0xC2, 0xC4, 0xC5, 0xC6, 0xC7, 0xCB, 0xCC, 0xCD):
            return self.decode_cX_3byte(insn, ea, b0, b1)

        # --- 0xeX: various 4-byte ---
        if b0 in (0xE0, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xEB, 0xEC, 0xED):
            return self.decode_eX_4byte(insn, ea, b0, b1)

        # --- 0x31/0x71/0xB1: 4-byte cmp ---
        if b0 in (0x31, 0x71, 0xB1):
            return self.decode_cmp_imm16(insn, ea, b0, b1)

        # --- 0x33/0x73/0xB3: cmpbreq / cmpbrne ---
        if b0 in (0x33, 0x73, 0xB3):
            return self.decode_cmpbr(insn, ea, b0, b1)

        # --- 0x3E: jmp ---
        if b0 == 0x3E:
            return self.decode_jmp(insn, ea)

        # --- 0x7E: call ---
        if b0 == 0x7E:
            return self.decode_call(insn, ea)

        # --- 2-byte instructions ---
        # 0x39/0x79/0xB9 are always 3-byte (cpl/neg with imm8), never 2-byte
        if b0 in (0x20, 0x26, 0x32, 0x3D, 0x3F,
                  0x60, 0x66, 0x72, 0x7D, 0x7F,
                  0xA0, 0xA6, 0xB2, 0xBD, 0xBF):
            return self.decode_2byte(insn, ea, b0, b1)

        # --- 3-byte instructions with imm8 ---
        if b0 in (0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x17, 0x18, 0x19, 0x1D,
                  0x30, 0x34, 0x35, 0x36, 0x3B,
                  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x57, 0x58,
                  0x70, 0x74, 0x75, 0x76, 0x79, 0x7B,
                  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x97, 0x98, 0x9D,
                  0xB0, 0xB4, 0xB5, 0xB6, 0xB9):
            return self.decode_3byte_imm8(insn, ea, b0, b1)

        return False

    # ==================================================================
    #  EMULATION & OUTPUT
    # ==================================================================

    # ------------------------------------------------------------------
    def handle_operand(self, insn, op, isRead):
        flags   = get_flags(insn.ea)
        is_offs = is_off(flags, op.n)
        def_arg = is_defarg(flags, op.n)
        optype  = op.type
        itype   = insn.itype

        if optype == o_imm:
            makeoff = False
            if itype == self.itype_call:
                insn.add_cref(op.value, op.offb, fl_CN)
                makeoff = True
            elif itype == self.itype_jmp:
                insn.add_cref(op.value, op.offb, fl_JN)
                makeoff = True
            if makeoff and not def_arg:
                op_plain_offset(insn.ea, op.n, insn.cs)
                is_offs = True
            if is_offs:
                insn.add_off_drefs(op, dr_O, 0)
        elif optype == o_near:
            if itype == self.itype_call:
                insn.add_cref(op.addr, op.offb, fl_CN)
            else:
                insn.add_cref(op.addr, op.offb, fl_JN)

    # ------------------------------------------------------------------
    def trace_sp(self, insn):
        pfn = get_func(insn.ea)
        if not pfn:
            return
        spofs = 0
        if insn.itype == self.itype_addsp:
            spofs = insn.Op1.value
        elif insn.itype in (self.itype_push, self.itype_pushm):
            spofs = -4
        elif insn.itype == self.itype_pop:
            spofs = 4
        elif insn.itype == self.itype_popm:
            spofs = 4 * (insn.Op2.value if insn.Op2.type == o_imm else 1)

        if spofs != 0:
            end = insn.ea + insn.size
            if not (get_aflags(end) & AFL_FIXEDSPD):
                ida_frame.add_auto_stkpnt(pfn, end, spofs)

    # ------------------------------------------------------------------
    def ev_emu_insn(self, insn):
        Feature = insn.get_canon_feature()

        if Feature & CF_USE1:
            self.handle_operand(insn, insn.Op1, 1)
        if Feature & CF_CHG1:
            self.handle_operand(insn, insn.Op1, 0)
        if Feature & CF_USE2:
            self.handle_operand(insn, insn.Op2, 1)
        if Feature & CF_CHG2:
            self.handle_operand(insn, insn.Op2, 0)
        if Feature & CF_USE3:
            self.handle_operand(insn, insn.Op3, 1)
        if Feature & CF_CHG3:
            self.handle_operand(insn, insn.Op3, 0)
        if Feature & CF_JUMP:
            remember_problem(PR_JUMP, insn.ea)

        uncond = insn.itype in (self.itype_jmp, self.itype_ret,
                                self.itype_reti, self.itype_halt,
                                self.itype_trap0, self.itype_trap1)
        flow = (Feature & CF_STOP == 0) and not uncond

        if flow:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        if may_trace_sp():
            if flow:
                self.trace_sp(insn)
            else:
                idc.recalc_spd(insn.ea)

        return True

    # ------------------------------------------------------------------
    def ev_out_operand(self, ctx, op):
        optype = op.type

        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif optype == o_imm:
            ctx.out_symbol('#')
            ctx.out_value(op, OOFW_IMM)
        elif optype == o_near:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)
        elif optype == o_displ:
            ctx.out_value(op, OOF_ADDR)
            ctx.out_symbol('(')
            ctx.out_register(self.reg_names[op.reg])
            ctx.out_symbol(')')
        elif optype == o_mem:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)
        else:
            return False
        return True

    # ------------------------------------------------------------------
    def ev_out_mnem(self, ctx):
        postfix = ""
        sz = ctx.insn.auxpref & AUX_SIZEMASK
        if not (ctx.insn.auxpref & AUX_NOSUF):
            if sz == SZ_BYTE:
                postfix = ".b"
            elif sz == SZ_HALF:
                postfix = ".h"
            elif sz == SZ_WORD:
                postfix = ".w"
        ctx.out_mnem(8, postfix)
        return 1

    # ------------------------------------------------------------------
    def ev_out_insn(self, ctx):
        ctx.out_mnemonic()

        if ctx.insn.Op1.type != o_void:
            ctx.out_one_operand(0)

        for i in range(1, 4):
            if ctx.insn[i].type == o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    # ------------------------------------------------------------------
    def ev_is_ret_insn(self, insn, strict):
        # ret/reti/halt end a function
        if insn.itype in (self.itype_ret, self.itype_reti, self.itype_halt):
            return True
        return False

    def ev_get_frame_retsize(self, frsize, pfn):
        ida_pro.int_pointer.frompointer(frsize).assign(4)
        return 1


# ----------------------------------------------------------------------
def PROCESSOR_ENTRY():
    return falcon_processor_t()
