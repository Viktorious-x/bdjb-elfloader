package org.ps5jb.client.payloads.parser;

import org.ps5jb.client.payloads.constants.ELF;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ElfSectionHeader {
    private String name = "";
    private final int sh_name;       // Section name (index into string table)
    private final int sh_type;       // Section type
    private final long sh_flags;     // Section flags
    private final long sh_addr;      // Virtual address in memory
    private final long sh_offset;    // Offset in file
    private final long sh_size;      // Size of section
    private final int sh_link;       // Link to another section
    private final int sh_info;       // Additional section information
    private final long sh_addralign; // Address alignment
    private final long sh_entsize;   // Size of entries if section has a table
    private ElfRelocation[] relocations;

    public ElfSectionHeader(byte[] data, long offset) {
        ByteBuffer buffer = ByteBuffer.wrap(data, (int) offset, data.length - (int) offset);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        sh_name = buffer.getInt();
        sh_type = buffer.getInt();
        sh_flags = buffer.getLong();
        sh_addr = buffer.getLong();
        sh_offset = buffer.getLong();
        sh_size = buffer.getLong();
        sh_link = buffer.getInt();
        sh_info = buffer.getInt();
        sh_addralign = buffer.getLong();
        sh_entsize = buffer.getLong();

        if (sh_type == ELF.SHT_RELA) {
            buffer.position( (int) sh_offset );
            int entries = (int) (sh_size / sh_entsize);
            relocations = new ElfRelocation[entries];
            int i = 0;
            while (buffer.position() < sh_offset + sh_size) {
                relocations[i] = ElfRelocation.fromByteBuffer(buffer);
                i++;
            }
        }
    }

    public String getName() {
        return name;
    }

    public int getNameOffset() {
        return sh_name;
    }

    public int getType() {
        return sh_type;
    }

    public long getFlags() {
        return sh_flags;
    }

    public long getAddr() {
        return sh_addr;
    }

    public long getOffset() {
        return sh_offset;
    }

    public long getSize() {
        return sh_size;
    }

    public int getLink() {
        return sh_link;
    }

    public int getInfo() {
        return sh_info;
    }

    public long getAddrAlign() {
        return sh_addralign;
    }

    public long getEntSize() {
        return sh_entsize;
    }

    public ElfRelocation[] getRelocations() {
        return relocations;
    }

    public void setName(String name) {
        this.name = name;
    }
}
