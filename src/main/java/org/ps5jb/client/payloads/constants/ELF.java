package org.ps5jb.client.payloads.constants;

public class ELF {
    /** Elf header starts with 0x7F + 'E' + 'L' + 'F' */
    public static byte[] elfMagic = {0x7F, 0x45, 0x4C, 0x46};

    // ELF types
    /** No file type (Unknown/Unspecified) */
    public static final short ET_NONE = 0;
    /** Relocatable file (.o object files) */
    public static final short ET_REL = 1;
    /** Executable file (compiled binary) */
    public static final short ET_EXEC = 2;
    /** Shared object file (.so libraries) */
    public static final short ET_DYN = 3;

    // ELF program types
    /** Loadable segment type */
    public static final short PT_LOAD = 1;
    /** Segment for dynamic linking */
    public static final short PT_DYNAMIC = 2;

    // ELF section header types
    /** Section header type: Relocation with Addend */
    public static final short SHT_RELA = 4;
    /** Section header type: Relocation without Addend */
    public static final short SHT_REL = 9;

    // Relocation types
    /** No relocation required. */
    public static final int R_X86_64_NONE = 0;
    /** 64-bit absolute relocation. */
    public static final int R_X86_64_64 = 1;
    /** 32-bit relative relocation (PC-relative). */
    public static final int R_X86_64_PC32 = 2;
    /** 32-bit GOT entry relocation. */
    public static final int R_X86_64_GOT32 = 3;
    /** 32-bit PLT entry relocation. */
    public static final int R_X86_64_PLT32 = 4;
    /** Copy data relocation. */
    public static final int R_X86_64_COPY = 5;
    /** Global data relocation (for functions/variables). */
    public static final int R_X86_64_GLOB_DAT = 6;
    /** PLT entry relocation for shared library linking. */
    public static final int R_X86_64_JUMP_SLOT = 7;
    /** Position-independent code (PIC) relative relocation. */
    public static final int R_X86_64_RELATIVE = 8;
    /** Thread-local storage module relocation (DTP). */
    public static final int R_X86_64_TLS_DTPMOD64 = 9;
    /** Thread-local storage data offset relocation. */
    public static final int R_X86_64_TLS_DTPOFF64 = 10;
    /** Thread-local storage thread pointer offset relocation. */
    public static final int R_X86_64_TLS_TPOFF64 = 11;

    // ELF p_flags
    /** p_flags: All access denied */
    public static final short PF_NONE = 0;
    /** p_flags: Execute only. May have Read memory permission too */
    public static final short PF_X    = 1;
    /** p_flags: Write only. May have Read, Execute memory permission too */
    public static final short PF_W    = 2;
    /** p_flags: Write, Execute. May have Read memory permission too */
    public static final short PF_WX   = 3;
    /** p_flags: Read only. May have Execute memory permission too */
    public static final short PF_R    = 4;
    /** p_flags: Read, Execute */
    public static final short PF_RX   = 5;
    /** p_flags: Read, Write. May have Execute memory permission too */
    public static final short PF_RW   = 6;
    /** p_flags: Read, Write, Execute */
    public static final short PF_RWX  = 7;
}
