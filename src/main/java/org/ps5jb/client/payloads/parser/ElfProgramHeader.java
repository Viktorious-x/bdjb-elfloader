package org.ps5jb.client.payloads.parser;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ElfProgramHeader {
    private final int p_type;
    private final int p_flags;
    private final long p_offset;
    private final long p_vaddr;
    private final long p_paddr;
    private final long p_filesz;
    private final long p_memsz;
    private final long p_align;

    public ElfProgramHeader(byte[] data, long offset) {
        ByteBuffer buffer = ByteBuffer.wrap(data, (int) offset, data.length - (int) offset);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        p_type = buffer.getInt();
        p_flags = buffer.getInt();
        p_offset = buffer.getLong();
        p_vaddr = buffer.getLong();
        p_paddr = buffer.getLong();
        p_filesz = buffer.getLong();
        p_memsz = buffer.getLong();
        p_align = buffer.getLong();
    }

    public int getType() {
        return p_type;
    }

    public int getFlags() {
        return p_flags;
    }

    public long getOffset() {
        return p_offset;
    }

    public long getVaddr() {
        return p_vaddr;
    }

    public long getPaddr() {
        return p_paddr;
    }

    public long getFilesz() {
        return p_filesz;
    }

    public long getMemsz() {
        return p_memsz;
    }

    public long getAlign() {
        return p_align;
    }
}

