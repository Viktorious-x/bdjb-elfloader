package org.ps5jb.client.payloads.parser;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ElfRelocation {
    private final long r_offset;  // Address of relocation
    private final long r_info;    // Encoded relocation type and symbol index
    private final long r_addend;

    public ElfRelocation(long r_offset, long r_info, long r_addend) {
        this.r_offset = r_offset;
        this.r_info = r_info;
        this.r_addend = r_addend;
    }

    public long getOffset() {
        return r_offset;
    }

    public long getAddend() {
        return r_addend;
    }

    // Extracts symbol index from r_info (upper 32 bits)
    public int getSymbolIndex() {
        return (int) (r_info >> 32);
    }

    // Extracts relocation type from r_info (lower 32 bits)
    public int getType() {
        return (int) (r_info & 0xFFFFFFFFL);
    }

    // Static method to parse an Elf64_Rela entry from a byte array
    public static ElfRelocation fromByteBuffer(ByteBuffer buffer) {
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        long offset = buffer.getLong();  // Read 8-byte r_offset
        long info = buffer.getLong();    // Read 8-byte r_info
        long addend = buffer.getLong();  // Read 8-byte r_addend

        return new ElfRelocation(offset, info, addend);
    }
}

