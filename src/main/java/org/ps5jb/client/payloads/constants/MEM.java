package org.ps5jb.client.payloads.constants;

public class MEM {

    /** The size of a memory page, defined as 0x4000 (16,384 bytes or 16 KB). */
    public static final short PAGE_SIZE = 0x4000;

    // Memory protection
    /** Memory protection: All access denied */
    public static final byte PROT_NONE  = 0;
    /** Memory protection: Read only */
    public static final byte PROT_READ  = 1;
    /** Memory protection: Write only */
    public static final byte PROT_WRITE = 2;
    /** Memory protection: Read, Write */
    public static final byte PROT_RW    = 3;
    /** Memory protection: Execute only */
    public static final byte PROT_EXEC  = 4;
    /** Memory protection: Read, Execute */
    public static final byte PROT_RX    = 5;
    // FreeBSD doesn't allow PROT_WRITE and PROT_EXEC simultaneously
    /** Memory protection: Write, Execute. Not supported! */
    public static final byte PROT_WX    = 6;
    /** Memory protection: Read, Write, Execute. Not supported! */
    public static final byte PROT_RWX   = 7;

    // mmap
    /** mmap_flag: Share changes */
    public static final short MAP_SHARED    = 0x1;
    /** mmap_flag: Changes are private (copy-on-write) */
    public static final short MAP_PRIVATE   = 0x2;
    /** mmap_flag: Interpret addr exactly */
    public static final short MAP_FIXED     = 0x10;
    /** mmap_flag: Assign a region with rename semantics (OBSOLETE) */
    public static final short MAP_RENAME    = 0x20;
    /** mmap_flag: Do not reserve swap space */
    public static final short MAP_NORESERVE = 0x40;
    /** mmap_flag: Region is retained after exec */
    public static final short MAP_INHERIT   = 0x80;
    /** mmap_flag: Region grows downward, suitable for stack */
    public static final short MAP_STACK     = 0x100;
    /** mmap_flag: Do not flush modifications to file */
    public static final short MAP_NOSYNC    = 0x800;
    /** mmap_flag: Anonymous memory (not backed by a file) */
    public static final short MAP_ANONYMOUS = 0x1000;
    /** mmap_flag: Reserved mapping (no memory allocated) */
    public static final short MAP_GUARD     = 0x2000;
    /** mmap_flag: Fail if the address is already mapped */
    public static final short MAP_EXCL      = 0x4000;
    /** mmap_flag: Exclude from core dump */
    public static final int MAP_NOCORE      = 0x8000;

    /**
     * Truncates the given address to the start of its containing memory page.
     *
     * @param addr The memory address to truncate.
     * @return The starting address of the page containing {@code addr}.
     */
    public static long truncatePage(long addr) {
        return addr & -PAGE_SIZE;
    }

    /**
     * Rounds the given address up to the start of the next memory page if it is not already page-aligned.
     *
     * @param addr The memory address to round up.
     * @return The starting address of the next page if {@code addr} is not already aligned,
     *         otherwise returns {@code addr} unchanged.
     */
    public static long roundPage(long addr) {
        return (addr + (PAGE_SIZE - 1)) & -PAGE_SIZE;
    }

    /**
     * Translates ELF segment protection flags into memory protection flags.
     *
     * @param flags The ELF protection flags, typically a combination of {@code ELF.PF_X},
     *              {@code ELF.PF_R}, and {@code ELF.PF_W}.
     * @return A byte representing the corresponding memory protection flags, combining
     *         {@code PROT_EXEC}, {@code PROT_READ}, and {@code PROT_WRITE} as needed.
     */
    public static byte translateProtection(int flags) {
        byte memFlags = 0;
        if ((flags & ELF.PF_X) == ELF.PF_X) {
            memFlags |= PROT_EXEC;
        }
        if ((flags & ELF.PF_R) == ELF.PF_R) {
            memFlags |= PROT_READ;
        }
        if ((flags & ELF.PF_W) == ELF.PF_W) {
            memFlags |= PROT_WRITE;
        }
        return memFlags;
    }
}
