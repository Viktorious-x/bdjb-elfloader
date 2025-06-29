package org.ps5jb.client.payloads.parser;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ElfHeader {
    public static final int EI_NIDENT = 16;

    private final byte[] e_ident = new byte[EI_NIDENT];
    private final short e_type;
    private final short e_machine;
    private final int e_version;
    private final long e_entry;
    private final long e_phoff;
    private final long e_shoff;
    private final int e_flags;
    private final short e_ehsize;
    private final short e_phentsize;
    private final short e_phnum;
    private final short e_shentsize;
    private final short e_shnum;
    private final short e_shstrndx;

    public ElfHeader(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        buffer.get(e_ident);
        e_type = buffer.getShort();
        e_machine = buffer.getShort();
        e_version = buffer.getInt();
        e_entry = buffer.getLong();
        e_phoff = buffer.getLong();
        e_shoff = buffer.getLong();
        e_flags = buffer.getInt();
        e_ehsize = buffer.getShort();
        e_phentsize = buffer.getShort();
        e_phnum = buffer.getShort();
        e_shentsize = buffer.getShort();
        e_shnum = buffer.getShort();
        e_shstrndx = buffer.getShort();
    }

    public byte[] getIdent() {
        return e_ident;
    }

    public short getType() {
        return e_type;
    }

    public short getMachine() {
        return e_machine;
    }

    public int getVersion() {
        return e_version;
    }

    public long getEntry() {
        return e_entry;
    }

    public long getPhOffset() {
        return e_phoff;
    }

    public long getShOffset() {
        return e_shoff;
    }

    public int getFlags() {
        return e_flags;
    }

    public short getEhSize() {
        return e_ehsize;
    }

    public short getPhEntitySize() {
        return e_phentsize;
    }

    public short getPhNumber() {
        return e_phnum;
    }

    public short getShEntitySize() {
        return e_shentsize;
    }

    public short getShNumber() {
        return e_shnum;
    }

    public short getShStringIndex() {
        return e_shstrndx;
    }
}
