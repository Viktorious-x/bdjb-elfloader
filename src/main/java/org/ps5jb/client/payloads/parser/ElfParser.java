package org.ps5jb.client.payloads.parser;

import org.ps5jb.client.payloads.constants.ELF;
import org.ps5jb.client.payloads.constants.MEM;
import org.ps5jb.loader.Status;

public class ElfParser {
    private final byte[] data;
    private final ElfHeader header;
    private final ElfProgramHeader[] programHeaders;
    private final ElfSectionHeader[] sectionHeaders;
    private final long minVaddr;
    private final long maxVaddr;
    private final long elfSize;

    public ElfParser(byte[] data) {
        this.data = data;
        header = new ElfHeader(data);
        programHeaders = parseProgramHeaders();
        sectionHeaders = parseSectionHeaders();
        minVaddr = minVaddr();
        maxVaddr = maxVaddr();
        elfSize = maxVaddr - minVaddr;
    }

    private ElfProgramHeader[] parseProgramHeaders() {
        ElfProgramHeader[] headers = new ElfProgramHeader[header.getPhNumber()];
        for (short i = 0; i < header.getPhNumber(); i++) {
            long offset = header.getPhOffset() + i * header.getPhEntitySize();
            headers[i] = new ElfProgramHeader(data, offset);
        }
        return headers;
    }

    private ElfSectionHeader[] parseSectionHeaders() {
        ElfSectionHeader[] headers = new ElfSectionHeader[header.getShNumber()];
        for (short i = 0; i < header.getShNumber(); i++) {
            long offset = header.getShOffset() + i * header.getShEntitySize();
            headers[i] = new ElfSectionHeader(data, offset);
        }
        // resolve names
        short indexOfStrTable = header.getShStringIndex();
        long strTableOffset = headers[indexOfStrTable].getOffset();
        for (ElfSectionHeader h : headers) {
            String name = getNullTerminatedString(data, (int) strTableOffset + h.getNameOffset());
            h.setName(name);
        }
        return headers;
    }

    public String getNullTerminatedString(byte[] data, int offset) {
        int end = offset;
        while (end < data.length && data[end] != 0) {
            end++;
        }
        return new String(data, offset, end - offset);
    }

    private long minVaddr() {
        long minVaddr = -1;
        for (ElfProgramHeader header : programHeaders) {
            if (header.getVaddr() < minVaddr) {
                minVaddr = header.getVaddr();
            }
        }
        return MEM.truncatePage(minVaddr);
    }

    private long maxVaddr() {
        long maxVaddr = 0;
        for (ElfProgramHeader header : programHeaders) {
            if (maxVaddr < header.getVaddr() + header.getMemsz()) {
                maxVaddr = header.getVaddr() + header.getMemsz();
            }
        }
        return MEM.roundPage(maxVaddr);
    }

    public long getElfType() {
        return header.getType();
    }

    public long getElfSize() {
        return elfSize;
    }

    public long getElfEntry() {
        return header.getEntry();
    }

    public long getMinVaddr() {
        return minVaddr;
    }

    public ElfProgramHeader[] getProgramHeadersByType(short programHeaderType) {
        short arraySize = 0;
        for (ElfProgramHeader header : programHeaders) {
            if (header.getType() == programHeaderType) {
                arraySize++;
            }
        }
        ElfProgramHeader[] headers = new ElfProgramHeader[arraySize];
        short i = 0;
        for (ElfProgramHeader header : programHeaders) {
            if (header.getType() == programHeaderType) {
                headers[i] = header;
                i++;
            }
        }
        return headers;
    }

    public ElfSectionHeader[] getSectionHeadersByType(short sectionHeaderType) {
        short arraySize = 0;
        for (ElfSectionHeader header : sectionHeaders) {
            if (header.getType() == sectionHeaderType) {
                arraySize++;
            }
        }
        ElfSectionHeader[] headers = new ElfSectionHeader[arraySize];
        short i = 0;
        for (ElfSectionHeader header : sectionHeaders) {
            if (header.getType() == sectionHeaderType) {
                headers[i] = header;
                i++;
            }
        }
        return headers;
    }
}
