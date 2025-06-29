package org.ps5jb.client.payloads;

import org.ps5jb.client.payloads.constants.ELF;
import org.ps5jb.client.payloads.constants.MEM;
import org.ps5jb.client.payloads.lib.LibKernelExtended;
import org.ps5jb.client.payloads.parser.ElfParser;
import org.ps5jb.client.payloads.parser.ElfProgramHeader;
import org.ps5jb.client.payloads.parser.ElfRelocation;
import org.ps5jb.client.payloads.parser.ElfSectionHeader;
import org.ps5jb.client.utils.init.KernelReadWriteUnavailableException;
import org.ps5jb.client.utils.init.SdkInit;
import org.ps5jb.client.utils.process.ProcessUtils;
import org.ps5jb.loader.KernelAccessor;
import org.ps5jb.loader.KernelReadWrite;
import org.ps5jb.loader.Status;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.SdkSoftwareVersionUnsupportedException;
import org.ps5jb.sdk.core.kernel.KernelAccessorIPv6;
import org.ps5jb.sdk.core.kernel.KernelOffsets;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.include.sys.proc.Process;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ElfLoader implements Runnable {

    private final LibKernelExtended libKernel = new LibKernelExtended();
    private ProcessUtils procUtils;
    private SdkInit sdk;

    String elfName = "elfldr.elf";

    private boolean init() {
        try {
            sdk = SdkInit.init(true, false);
            procUtils = new ProcessUtils(libKernel);
        } catch (KernelReadWriteUnavailableException e) {
            println("Kernel R/W is not available, aborting");
            libKernel.closeLibrary();
            return false;
        } catch (SdkSoftwareVersionUnsupportedException e) {
            Status.printStackTrace("Unsupported firmware version: ", e);
            libKernel.closeLibrary();
            return false;
        }

        return true;
    }

    @Override
    public void run() {
        if (!init()) {
            return;
        }

        byte[] elfBytes;
        try {
            // Read the ELF file from Jar
            InputStream inputStream = this.getClass().getResourceAsStream("/" + elfName);
            if (inputStream != null) {
                elfBytes = new byte[inputStream.available()];
                DataInputStream dataInputStream = new DataInputStream(inputStream);
                dataInputStream.readFully(elfBytes);

                for (int i = 0; i < 4; i++) {
                    if (elfBytes[i] != ELF.elfMagic[i]) {
                        println("[!] " + elfName + " not a valid ELF file. Aborting.");
                        return;
                    }
                }
            } else {
                println("[!] " + elfName + " not found in JAR");
                return;
            }
        } catch (IOException e) {
            Status.printStackTrace("Error while reading " + elfName, e);
            libKernel.closeLibrary();
            return;
        }

        // Apply patch to bdj process
        Process curProc = new Process(KernelPointer.valueOf(sdk.curProcAddress));
        patchProcess(curProc);
        println("[+] Patch applied to " + curProc.getName());

        // Enable debug settings
        if (enableDebug()) {
            println("[+] Debug settings enabled");
        } else {
            println("[-] Debug settings already enabled");
        }

        //
        // ELF loading
        //

        // Allocate memory for ELF
        int elfStoreSize = elfBytes.length;
        Pointer elfStore = Pointer.malloc(elfStoreSize);

        // Store ELF into memory
        for (int i = 0; i < elfStoreSize; i++) {
            elfStore.write1(i, elfBytes[i]);
        }

        println("[+] Stored " + elfName + " (" + elfBytes.length + " bytes)");
        println("Prepare ELF execution...");

        // Parse ELF file
        ElfParser elf = new ElfParser(elfBytes);

        //
        // Memory mapping
        //

        short flags = MEM.MAP_PRIVATE | MEM.MAP_ANONYMOUS;
        byte prot = MEM.PROT_READ | MEM.PROT_WRITE;
        long baseAddr;
        if (elf.getElfType() == ELF.ET_DYN) {
            baseAddr = 0;
        } else if (elf.getElfType() == ELF.ET_EXEC) {
            baseAddr = elf.getMinVaddr();
            flags |= MEM.MAP_FIXED;
        } else {
            println("  [!] ELF type not supported");
            return;
        }

        // Map memory for ELF segments
        Pointer mmapMemoryLocation = libKernel.mmap(Pointer.valueOf(baseAddr), elf.getElfSize(), prot, flags, -1, 0);

        if (mmapMemoryLocation.addr() == -1) {
            println("  [!] Could not map anonymous memory");
            return;
        } else {
            println("  [+] Mapped memory for ELF segments");
        }

        // Copy loadable segments
        Pointer elfDestination = mmapMemoryLocation;
        ElfProgramHeader[] pHeaders = elf.getProgramHeadersByType(ELF.PT_LOAD);
        for (ElfProgramHeader ph : pHeaders) {
            Pointer dest = elfDestination.inc(ph.getVaddr());
            copySegment(elfStore, dest, ph.getMemsz(), ph.getFilesz(), ph.getOffset());

            println("  [+] ELF segment copied into memory");
        }

        //
        // Relocations
        //

        int countRel = 0;

        // Apply relocations
        ElfSectionHeader[] sHeaders = elf.getSectionHeadersByType(ELF.SHT_RELA);
        for (ElfSectionHeader sh : sHeaders) {
            for (ElfRelocation r : sh.getRelocations()) {
                if (r.getType() == ELF.R_X86_64_RELATIVE) {
                    Pointer relocAddr = elfDestination.inc(r.getOffset());
                    long relocVal = elfDestination.addr() + r.getAddend();
                    relocAddr.write8(relocVal);
                    countRel++;
                }
            }
        }

        println("  [+] Applied relocations: " + countRel);

        //
        // Memory protection
        //

        // Set protection of segments
        for (ElfProgramHeader ph : pHeaders) {
            if (ph.getMemsz() > 0) {
                Pointer segmentAddr = elfDestination.inc(ph.getVaddr());
                long segmentSize = MEM.roundPage(ph.getMemsz());
                if ((ph.getFlags() & ELF.PF_X) == ELF.PF_X) {
                    byte memProt = MEM.translateProtection(ph.getFlags());
                    libKernel.kMprotect(curProc, segmentAddr, memProt);
                } else {
                    byte memProt = MEM.translateProtection(ph.getFlags());
                    libKernel.mprotect(segmentAddr, segmentSize, memProt);
                }
            }
        }

        println("  [+] Set memory protection flags");

        //
        // ELF arguments
        //

        Pointer rwSocketPair = Pointer.malloc(8);
        Pointer payloadOut = Pointer.malloc(8);
        Pointer args = Pointer.malloc(48); // 8 * 6

        // Get IPv6 Accessor for pipe and socket
        KernelAccessorIPv6 ipv6;
        KernelAccessor ka = KernelReadWrite.getAccessor(getClass().getClassLoader());
        if (ka instanceof KernelAccessorIPv6) {
            ipv6 = (KernelAccessorIPv6) ka;
        } else {
            sdk.restoreNonAgcKernelReadWrite();
            ipv6 = (KernelAccessorIPv6) KernelReadWrite.getAccessor(getClass().getClassLoader());
        }

        // Pipe
        Pointer rwPipe = Pointer.malloc(8);
        rwPipe.write4(ipv6.getPipeReadFd());
        rwPipe.write4(4, ipv6.getPipeWriteFd());

        // Pass master/victim pair to payload so it can do read/write
        rwSocketPair.write4(ipv6.getMasterSock());
        rwSocketPair.write4(4, ipv6.getVictimSock());

        // We need getpid, sceKernelDlsym does not work on higher FWs
        Pointer dlsym = libKernel.addrOf("getpid");
//        Pointer dlsym = libKernel.addrOf("sceKernelDlsym");
        long kdataAddress = sdk.kernelDataAddress;

        args.inc(0x00).write8(dlsym.addr());                 // arg1 = dlsym_t* dlsym
        args.inc(0x08).write8(rwPipe.addr());                // arg2 = int *rwpipe[2]
        args.inc(0x10).write8(rwSocketPair.addr());          // arg3 = int *rwpair[2]
        args.inc(0x18).write8(ipv6.getPipeAddress().addr()); // arg4 = uint64_t kpipe_addr
        args.inc(0x20).write8(kdataAddress);                 // arg5 = uint64_t kdata_base_addr
        args.inc(0x28).write8(payloadOut.addr());            // arg6 = int *payloadout

        println("  [+] Prepared ELF arguments");

        //
        // ELF execution
        //

        Pointer elfEntryPoint = Pointer.valueOf(elfDestination.addr() + elf.getElfEntry());

        println("Execution...");
        println("  [+] Starting " + elfName);

        // Run in Java thread
        ElfRunner runner = new ElfRunner(elfEntryPoint, args);
        Thread t = new Thread(runner);
        t.start();
        try {
            t.join();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        int retVal = runner.getReturnValue();

        println("  [+] Finished");
        println("Done.");

        // Cleanup
        payloadOut.free();
        rwPipe.free();
        rwSocketPair.free();
        args.free();
        elfStore.free();
        libKernel.munmap(elfDestination, elf.getElfSize());
    }

    private void patchProcess(Process process) {
        // Patch ucred
        procUtils.setUserGroup(process, new int[]{
                0, // cr_uid
                0, // cr_ruid
                0, // cr_svuid
                1, // cr_ngroups
                0  // cr_rgid
        });

        final long SYSTEM_AUTHID   = 0x4800000000010003l;
        final long COREDUMP_AUTHID = 0x4800000000000006l;
        final long DEVICE_AUTHID   = 0x4801000000000013l;
        final long currentAuthId   = procUtils.getPrivs(process)[0];

        // Escalate sony privs
        procUtils.setPrivs(process, new long[]{
                DEVICE_AUTHID,       // cr_sceAuthId
                0xFFFFFFFFFFFFFFFFL, // cr_sceCaps[0]
                0xFFFFFFFFFFFFFFFFL, // cr_sceCaps[1]
                0x80                 // cr_sceAttr[0]
        });

        // Remove dynlib restriction
        KernelPointer dynlibAddr = process.getDynLib();
        dynlibAddr.write4(0x118, 0);
        dynlibAddr.write8(0x18, 1);

        // Bypass libkernel address range check (credit @cheburek3000)
        dynlibAddr.write8(0xf0, 0);
        dynlibAddr.write8(0xf8, -1);
    }

    private boolean enableDebug() {
        boolean appliedPatch = false;
        KernelOffsets offsets = sdk.kernelOffsets;
        KernelPointer kdata = KernelPointer.valueOf(sdk.kernelDataAddress, false);

        // enable direct memory access
        sdk.switchToAgcKernelReadWrite(true);

        // Security flags
        KernelPointer secFlagsPtr = kdata.inc(offsets.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS);
        int secFlagsVal = secFlagsPtr.read4();
        if ((secFlagsVal & 0x14) != 0x14) {
            secFlagsPtr.write4(secFlagsVal | 0x14);
            appliedPatch = true;
        }

        // target ID
        KernelPointer targetIdPtr = kdata.inc(offsets.OFFSET_KERNEL_DATA_BASE_TARGET_ID);
        byte targetId = targetIdPtr.read1();
        if (targetId != (byte) 0x82) {
            targetIdPtr.write1((byte) 0x82);
            appliedPatch = true;
        }

        // QA flags
        KernelPointer qaFlagsPtr = kdata.inc(offsets.OFFSET_KERNEL_DATA_BASE_QA_FLAGS);
        long qaFlagsVal = qaFlagsPtr.read8();
        final long QA_MASK = 0x0000000000010300L;
        if ((qaFlagsVal & QA_MASK) != QA_MASK) {
            qaFlagsPtr.write8(qaFlagsVal | QA_MASK);
            appliedPatch = true;
        }

        // Utoken flag
        KernelPointer uTokenFlagsPtr = kdata.inc(offsets.OFFSET_KERNEL_DATA_BASE_UTOKEN_FLAGS);
        byte uTokenFlagsVal = uTokenFlagsPtr.read1();
        if ((uTokenFlagsVal & 0x1) != 0x1) {
            uTokenFlagsPtr.write1((byte) (uTokenFlagsVal | 0x1));
            appliedPatch = true;
        }

        // Notification: debug settings enabled
        if (appliedPatch) {
            libKernel.sceKernelSendNotificationRequest("Debug Settings enabled");
        }

        // disable DMA
        sdk.restoreNonAgcKernelReadWrite();

        return appliedPatch;
    }

    private void println(String message) {
        Status.println(message);
    }

    private void copySegment(Pointer src, Pointer dest, long memSize, long fileSize, long offset) {
        for (long i = 0; i < memSize; i += 8) {
            long qword = (i >= fileSize) ? 0 : src.read8(offset + i);
            dest.write8(i, qword);
        }
    }
}