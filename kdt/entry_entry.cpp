#include <ntifs.h>

#define DN L"\\Device\\kdt"
#define SN L"\\DosDevices\\kdt"

#define IOCTL_REGISTER_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_LOAD_DATA  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_DUMP_DIRECTORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DRIVER_TAG 'mndr'
#define DUMP_DIRECTORY_CHARS 512

typedef struct _DRIVER_LOAD_INFO {
    WCHAR FilePath[512];
    WCHAR DumpDirectory[DUMP_DIRECTORY_CHARS];
} DRIVER_LOAD_INFO, *PDRIVER_LOAD_INFO;
static_assert(sizeof(DRIVER_LOAD_INFO) == 2048, "Keep the kernel IOCTL layout in sync with dt.exe.");

typedef struct _QUEUE_ENTRY {
    LIST_ENTRY ListEntry;
    DRIVER_LOAD_INFO Info;
} QUEUE_ENTRY, *PQUEUE_ENTRY;

typedef struct _WORK_ITEM_CONTEXT {
    PIO_WORKITEM WorkItem;
    UNICODE_STRING FilePath;
    UNICODE_STRING DumpDirectory;
    WCHAR DumpDirectoryBuffer[DUMP_DIRECTORY_CHARS];
} WORK_ITEM_CONTEXT, *PWORK_ITEM_CONTEXT;

PDEVICE_OBJECT g_DeviceObject = NULL;
PKEVENT g_UserEvent = NULL;
LIST_ENTRY g_QueueHead;
KSPIN_LOCK g_QueueLock;
KSPIN_LOCK g_DumpDirectoryLock;
WCHAR g_DumpDirectory[DUMP_DIRECTORY_CHARS];
USHORT g_DumpDirectoryLength = 0;

VOID SnapshotDumpDirectory(PWCHAR destination, USHORT destinationBytes, PUSHORT lengthBytes) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DumpDirectoryLock, &oldIrql);
    USHORT bytesToCopy = destinationBytes < sizeof(g_DumpDirectory)
        ? destinationBytes : sizeof(g_DumpDirectory);
    RtlZeroMemory(destination, destinationBytes);
    RtlCopyMemory(destination, g_DumpDirectory, bytesToCopy);
    *lengthBytes = g_DumpDirectoryLength;
    KeReleaseSpinLock(&g_DumpDirectoryLock, oldIrql);
    UNREFERENCED_PARAMETER(destinationBytes);
}

VOID ClearQueue() {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_QueueLock, &oldIrql);
    while (!IsListEmpty(&g_QueueHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_QueueHead);
        PQUEUE_ENTRY qEntry = CONTAINING_RECORD(entry, QUEUE_ENTRY, ListEntry);
        ExFreePoolWithTag(qEntry, DRIVER_TAG);
    }
    KeReleaseSpinLock(&g_QueueLock, oldIrql);
}

NTSTATUS CopyFileInKernel(PUNICODE_STRING SourcePath, PUNICODE_STRING DestPath) {
    HANDLE hSource = NULL;
    HANDLE hDest = NULL;
    OBJECT_ATTRIBUTES objAttrSource, objAttrDest;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    InitializeObjectAttributes(&objAttrSource, SourcePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(&hSource,
        GENERIC_READ | SYNCHRONIZE,
        &objAttrSource,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (!NT_SUCCESS(status)) { return status; }

    InitializeObjectAttributes(&objAttrDest, DestPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(&hDest,
        GENERIC_WRITE | SYNCHRONIZE,
        &objAttrDest,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_SUPERSEDE,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (!NT_SUCCESS(status)) {
        ZwClose(hSource);
        return status;
    }

    ULONG bufferSize = 4096;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, DRIVER_TAG);
    if (buffer == NULL) {
        ZwClose(hSource);
        ZwClose(hDest);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;
    while (TRUE) {
        status = ZwReadFile(hSource, NULL, NULL, NULL, &ioStatus, buffer, bufferSize, &byteOffset, NULL);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_END_OF_FILE) { status = STATUS_SUCCESS; }
            break;
        }
        ULONG bytesRead = (ULONG)ioStatus.Information;
        if (bytesRead == 0) break;
        status = ZwWriteFile(hDest, NULL, NULL, NULL, &ioStatus, buffer, bytesRead, &byteOffset, NULL);
        if (!NT_SUCCESS(status)) break;
        byteOffset.QuadPart += bytesRead;
    }

    ExFreePoolWithTag(buffer, DRIVER_TAG);
    ZwClose(hSource);
    ZwClose(hDest);
    return status;
}

VOID FileCopyWorkItemRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    if (Context == NULL) return;

    PWORK_ITEM_CONTEXT context = (PWORK_ITEM_CONTEXT)Context;
    if (context->FilePath.Length == 0 || context->FilePath.Buffer == NULL) {
        IoFreeWorkItem(context->WorkItem);
        ExFreePoolWithTag(context, DRIVER_TAG);
        return;
    }

    USHORT lastSlash = 0;
    BOOLEAN foundSlash = FALSE;
    for (USHORT i = 0; i < context->FilePath.Length / sizeof(WCHAR); i++) {
        if (context->FilePath.Buffer[i] == L'\\') {
            lastSlash = i;
            foundSlash = TRUE;
        }
    }

    UNICODE_STRING fileName;
    if (foundSlash && (lastSlash + 1) * sizeof(WCHAR) < context->FilePath.Length) {
        fileName.Buffer = &context->FilePath.Buffer[lastSlash + 1];
        fileName.Length = context->FilePath.Length - (lastSlash + 1) * sizeof(WCHAR);
    }
    else {
        fileName = context->FilePath;
    }
    fileName.MaximumLength = fileName.Length;

    if (fileName.Length > 0) {
        UNICODE_STRING destPath;
        UNICODE_STRING ntPrefix = RTL_CONSTANT_STRING(L"\\??\\");
        ULONG destinationBytes = ntPrefix.Length + context->DumpDirectory.Length + fileName.Length + sizeof(WCHAR);
        if (destinationBytes > MAXUSHORT) {
            IoFreeWorkItem(context->WorkItem);
            ExFreePoolWithTag(context->FilePath.Buffer, DRIVER_TAG);
            ExFreePoolWithTag(context, DRIVER_TAG);
            return;
        }

        destPath.MaximumLength = (USHORT)destinationBytes;
        destPath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, destPath.MaximumLength, DRIVER_TAG);

        if (destPath.Buffer != NULL) {
            destPath.Length = 0;
            RtlCopyUnicodeString(&destPath, &ntPrefix);
            RtlAppendUnicodeStringToString(&destPath, &context->DumpDirectory);
            RtlAppendUnicodeStringToString(&destPath, &fileName);
            CopyFileInKernel(&context->FilePath, &destPath);
            ExFreePoolWithTag(destPath.Buffer, DRIVER_TAG);
        }
    }

    IoFreeWorkItem(context->WorkItem);
    ExFreePoolWithTag(context->FilePath.Buffer, DRIVER_TAG);
    ExFreePoolWithTag(context, DRIVER_TAG);
}

void imcb(PUNICODE_STRING path, HANDLE pid, PIMAGE_INFO im) {
    UNREFERENCED_PARAMETER(im);

    if (path == NULL || path->Buffer == NULL || path->Length == 0 || pid != 0) {
        return;
    }

    WCHAR dumpDirectorySnapshot[DUMP_DIRECTORY_CHARS]{};
    USHORT dumpDirectoryLength = 0;
    SnapshotDumpDirectory(dumpDirectorySnapshot, sizeof(dumpDirectorySnapshot), &dumpDirectoryLength);

    auto context = (PWORK_ITEM_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(WORK_ITEM_CONTEXT), DRIVER_TAG);
    if (context != NULL) {
        RtlZeroMemory(context, sizeof(WORK_ITEM_CONTEXT));
        context->FilePath.Length = 0;
        context->DumpDirectory.Buffer = context->DumpDirectoryBuffer;
        context->DumpDirectory.MaximumLength = sizeof(context->DumpDirectoryBuffer);
        RtlCopyMemory(context->DumpDirectoryBuffer, dumpDirectorySnapshot, sizeof(dumpDirectorySnapshot));
        context->DumpDirectory.Length = dumpDirectoryLength;
        if (path->Length > MAXUSHORT - sizeof(WCHAR)) {
            ExFreePoolWithTag(context, DRIVER_TAG);
            context = NULL;
        }
    }
    if (context != NULL) {
        context->FilePath.MaximumLength = path->Length + sizeof(WCHAR);
        context->FilePath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, context->FilePath.MaximumLength, DRIVER_TAG);
        if (context->FilePath.Buffer != NULL) {
            RtlCopyUnicodeString(&context->FilePath, path);
            context->WorkItem = IoAllocateWorkItem(g_DeviceObject);
            if (context->WorkItem != NULL) {
                IoQueueWorkItem(context->WorkItem, FileCopyWorkItemRoutine, DelayedWorkQueue, context);
            }
            else {
                ExFreePoolWithTag(context->FilePath.Buffer, DRIVER_TAG);
                ExFreePoolWithTag(context, DRIVER_TAG);
            }
        }
        else {
            ExFreePoolWithTag(context, DRIVER_TAG);
        }
    }

    auto qEntry = (PQUEUE_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(QUEUE_ENTRY), DRIVER_TAG);
    if (qEntry != NULL) {
        RtlZeroMemory(&qEntry->Info, sizeof(DRIVER_LOAD_INFO));

        USHORT directoryLength = dumpDirectoryLength;
        RtlCopyMemory(qEntry->Info.DumpDirectory, dumpDirectorySnapshot,
            sizeof(qEntry->Info.DumpDirectory));
        if (directoryLength > sizeof(qEntry->Info.DumpDirectory) - sizeof(WCHAR)) {
            directoryLength = sizeof(qEntry->Info.DumpDirectory) - sizeof(WCHAR);
        }
        qEntry->Info.DumpDirectory[directoryLength / sizeof(WCHAR)] = UNICODE_NULL;

        USHORT copyLength = path->Length;
        if (copyLength > sizeof(qEntry->Info.FilePath) - sizeof(WCHAR)) {
            copyLength = sizeof(qEntry->Info.FilePath) - sizeof(WCHAR);
        }
        RtlCopyMemory(qEntry->Info.FilePath, path->Buffer, copyLength);

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_QueueLock, &oldIrql);
        InsertTailList(&g_QueueHead, &qEntry->ListEntry);
        if (g_UserEvent != NULL) {
            KeSetEvent(g_UserEvent, IO_NO_INCREMENT, FALSE);
        }
        KeReleaseSpinLock(&g_QueueLock, oldIrql);
    }
}

void unl(PDRIVER_OBJECT d) {
    PsRemoveLoadImageNotifyRoutine(imcb);

    PKEVENT oldEvent = NULL;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_QueueLock, &oldIrql);
    oldEvent = g_UserEvent;
    g_UserEvent = NULL;
    KeReleaseSpinLock(&g_QueueLock, oldIrql);

    if (oldEvent != NULL) {
        ObDereferenceObject(oldEvent);
    }

    ClearQueue();

    if (d && d->DeviceObject) {
        UNICODE_STRING symbolicLinkName{};
        RtlInitUnicodeString(&symbolicLinkName, SN);
        IoDeleteSymbolicLink(&symbolicLinkName);
        IoDeleteDevice(d->DeviceObject);
        g_DeviceObject = NULL;
    }
}

NTSTATUS ioc(PDEVICE_OBJECT d, PIRP i) {
    UNREFERENCED_PARAMETER(d);
    auto status = STATUS_INVALID_DEVICE_REQUEST;
    auto stack = IoGetCurrentIrpStackLocation(i);
    auto code = stack->Parameters.DeviceIoControl.IoControlCode;
    auto in = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG_PTR information = 0;

    switch (code) {
    case IOCTL_REGISTER_EVENT: {
        if (in >= sizeof(HANDLE)) {
            PHANDLE pHandle = (PHANDLE)i->AssociatedIrp.SystemBuffer;
            if (pHandle != NULL) {
                PKEVENT newEvent = NULL;
                status = ObReferenceObjectByHandle(*pHandle,
                    SYNCHRONIZE | EVENT_MODIFY_STATE,
                    *ExEventObjectType,
                    i->RequestorMode,
                    (PVOID*)&newEvent,
                    NULL);
                if (NT_SUCCESS(status)) {
                    PKEVENT oldEvent = NULL;
                    KIRQL oldIrql;

                    KeAcquireSpinLock(&g_QueueLock, &oldIrql);
                    oldEvent = g_UserEvent;
                    g_UserEvent = newEvent;
                    if (!IsListEmpty(&g_QueueHead)) {
                        KeSetEvent(g_UserEvent, IO_NO_INCREMENT, FALSE);
                    }
                    KeReleaseSpinLock(&g_QueueLock, oldIrql);

                    if (oldEvent != NULL) {
                        ObDereferenceObject(oldEvent);
                    }
                    information = 0;
                }
            }
            else {
                status = STATUS_INVALID_PARAMETER;
            }
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    }
    case IOCTL_GET_LOAD_DATA: {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(DRIVER_LOAD_INFO)) {
            KIRQL oldIrql;
            PQUEUE_ENTRY qEntry = NULL;

            KeAcquireSpinLock(&g_QueueLock, &oldIrql);
            if (!IsListEmpty(&g_QueueHead)) {
                auto entry = RemoveHeadList(&g_QueueHead);
                qEntry = CONTAINING_RECORD(entry, QUEUE_ENTRY, ListEntry);
            }
            KeReleaseSpinLock(&g_QueueLock, oldIrql);

            if (qEntry != NULL) {
                auto pOutInfo = (PDRIVER_LOAD_INFO)i->AssociatedIrp.SystemBuffer;
                if (pOutInfo != NULL) {
                    RtlCopyMemory(pOutInfo, &qEntry->Info, sizeof(DRIVER_LOAD_INFO));
                    ExFreePoolWithTag(qEntry, DRIVER_TAG);

                    status = STATUS_SUCCESS;
                    information = sizeof(DRIVER_LOAD_INFO);
                }
                else {
                    KeAcquireSpinLock(&g_QueueLock, &oldIrql);
                    InsertHeadList(&g_QueueHead, &qEntry->ListEntry);
                    KeReleaseSpinLock(&g_QueueLock, oldIrql);
                    status = STATUS_INVALID_PARAMETER;
                }
            }
            else {
                status = STATUS_SUCCESS;
                information = 0;
            }
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    }
    case IOCTL_SET_DUMP_DIRECTORY: {
        if (i->AssociatedIrp.SystemBuffer == NULL ||
            in < 4 * sizeof(WCHAR) ||
            in > sizeof(g_DumpDirectory) ||
            (in % sizeof(WCHAR)) != 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        auto inputDirectory = (PWCHAR)i->AssociatedIrp.SystemBuffer;
        USHORT inputCharacters = (USHORT)(in / sizeof(WCHAR));
        USHORT pathCharacters = inputCharacters - 1;
        if (inputDirectory[pathCharacters] != UNICODE_NULL ||
            pathCharacters < 3 ||
            !(((inputDirectory[0] >= L'A' && inputDirectory[0] <= L'Z') ||
               (inputDirectory[0] >= L'a' && inputDirectory[0] <= L'z'))) ||
            inputDirectory[1] != L':' ||
            inputDirectory[2] != L'\\' ||
            inputDirectory[pathCharacters - 1] != L'\\') {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        BOOLEAN valid = TRUE;
        for (USHORT index = 0; index < pathCharacters; ++index) {
            if (inputDirectory[index] == UNICODE_NULL ||
                inputDirectory[index] == L'/' ||
                inputDirectory[index] == L'*' ||
                inputDirectory[index] == L'?' ||
                inputDirectory[index] == L'"' ||
                (index != 1 && inputDirectory[index] == L':')) {
                valid = FALSE;
                break;
            }
        }
        if (!valid) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_DumpDirectoryLock, &oldIrql);
        RtlZeroMemory(g_DumpDirectory, sizeof(g_DumpDirectory));
        RtlCopyMemory(g_DumpDirectory, inputDirectory, in);
        g_DumpDirectoryLength = (USHORT)(pathCharacters * sizeof(WCHAR));
        KeReleaseSpinLock(&g_DumpDirectoryLock, oldIrql);
        status = STATUS_SUCCESS;
        information = 0;
        break;
    }
    default:
        break;
    }

    i->IoStatus.Status = status;
    i->IoStatus.Information = information;
    IoCompleteRequest(i, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT d, PIRP i) {
    UNREFERENCED_PARAMETER(d);
    i->IoStatus.Status = STATUS_SUCCESS;
    i->IoStatus.Information = 0;
    IoCompleteRequest(i, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT d, PIRP i) {
    UNREFERENCED_PARAMETER(d);

    PKEVENT oldEvent = NULL;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_QueueLock, &oldIrql);
    oldEvent = g_UserEvent;
    g_UserEvent = NULL;
    KeReleaseSpinLock(&g_QueueLock, oldIrql);

    if (oldEvent != NULL) {
        ObDereferenceObject(oldEvent);
    }

    ClearQueue();

    i->IoStatus.Status = STATUS_SUCCESS;
    i->IoStatus.Information = 0;
    IoCompleteRequest(i, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT drvobj, PUNICODE_STRING path)
{
    UNREFERENCED_PARAMETER(path);
    NTSTATUS status;

    InitializeListHead(&g_QueueHead);
    KeInitializeSpinLock(&g_QueueLock);
    KeInitializeSpinLock(&g_DumpDirectoryLock);
    RtlZeroMemory(g_DumpDirectory, sizeof(g_DumpDirectory));
    RtlCopyMemory(g_DumpDirectory, L"C:\\DriverDump\\", sizeof(L"C:\\DriverDump\\"));
    g_DumpDirectoryLength = (USHORT)(sizeof(L"C:\\DriverDump\\") - sizeof(WCHAR));

    drvobj->DriverUnload = unl;
    drvobj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    drvobj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    drvobj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ioc;

    UNICODE_STRING devName = RTL_CONSTANT_STRING(DN);
    status = IoCreateDevice(drvobj, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SN);
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    status = PsSetLoadImageNotifyRoutine(imcb);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}
