package org.ps5jb.client.payloads.lib;

import org.ps5jb.loader.Status;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.include.sys.mman.ProtectionFlag;
import org.ps5jb.sdk.include.sys.proc.Process;
import org.ps5jb.sdk.lib.LibKernel;

import java.util.Arrays;

public class LibKernelExtended extends LibKernel {
    /** Offset to the vm_map structure inside vmspace of a process */
    private final short OFFSET_VMROOT;

    public LibKernelExtended() {
        OFFSET_VMROOT = getOffsetVmRoot();
    }

    // Offsets from PS5 payload sdk (credits @sb)
    private short getOffsetVmRoot() {
        short offset;
        switch (getSystemSoftwareVersion()) {
            case 0x0100:
            case 0x0101:
            case 0x0102:
            case 0x0105:
            case 0x0110:
            case 0x0111:
            case 0x0112:
            case 0x0113:
            case 0x0114: {
                Status.println("[+] FW 1.xx detected");
                offset = 0x1C0;
                break;
            }
            case 0x0220:
            case 0x0225:
            case 0x0226:
            case 0x0230:
            case 0x0250:
            case 0x0270: {
                Status.println("[+] FW 2.xx detected");
                offset = 0x1C8;
                break;
            }
            case 0x0300:
            case 0x0310:
            case 0x0320:
            case 0x0321: {
                Status.println("[+] FW 3.xx detected");
                offset = 0x1C8;
                break;
            }
            case 0x0400:
            case 0x0402:
            case 0x0403:
            case 0x0450:
            case 0x0451: {
                Status.println("[+] FW 4.xx detected");
                offset = 0x1C8;
                break;
            }
            case 0x0500:
            case 0x0502:
            case 0x0510:
            case 0x0550: {
                Status.println("[+] FW 5.xx detected");
                offset = 0x1C8;
                break;
            }
            case 0x0600:
            case 0x0602:
            case 0x0650: {
                Status.println("[+] FW 6.xx detected");
                offset = 0x1D0;
                break;
            }
            case 0x0700:
            case 0x0701:
            case 0x0720:
            case 0x0740:
            case 0x0760:
            case 0x0761: {
                Status.println("[+] FW 7.xx detected");
                offset = 0x1D0;
                break;
            }
            default: {
                Status.println("[!] FW not supported");
                offset = 0;
            }
        }
        return offset;
    }

    /**
     * Modifies the memory protection attributes of a specified address in a process's virtual memory map.
     *
     * <p>This method traverses the process's VM map entries, searching for the region that contains
     * the specified address. If found, it updates the protection attributes.</p>
     *
     * @param proc The process whose memory protections are being modified.
     * @param addr The memory address whose protection needs to be changed.
     * @param prot The new protection flags to apply (e.g., read, write, execute permissions).
     */
    public void kMprotect(Process proc, Pointer addr, byte prot) {
        KernelPointer vmMapEntry = proc.getVmSpace().getPointer().pptr(OFFSET_VMROOT);
        while (!KernelPointer.NULL.equals(vmMapEntry)) {
            long start = vmMapEntry.read8(0x20);
            long end = vmMapEntry.read8(0x28);
            if (addr.addr() < start) {
                // go left in tree
                vmMapEntry = vmMapEntry.pptr(0x10);
            } else if (addr.addr() >= end) {
                // go right in tree
                vmMapEntry = vmMapEntry.pptr(0x18);
            } else {
                // protection
                vmMapEntry.write1(0x64, prot);
                // max protection
                vmMapEntry.write1(0x65, prot);
                return;
            }
        }
    }
}
