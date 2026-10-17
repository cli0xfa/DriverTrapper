#include <fltKernel.h>
#include <bcrypt.h>
#include <ntstrsafe.h>

#include "filter_protocol.h"

namespace {

constexpr ULONG FILTER_TAG = 'fDtS';
constexpr ULONG MAX_CANDIDATES = 256;
constexpr ULONG MAX_CAPTURE_ATTEMPTS = 4; // one initial attempt plus three retries
constexpr ULONG MAX_PATH_CHARS = 1024;
constexpr ULONG IO_BUFFER_BYTES = 64 * 1024;
constexpr LONGLONG CANDIDATE_LIFETIME_100NS = 15LL * 60LL * 10000000LL;

struct Candidate {
    LIST_ENTRY Link;
    volatile LONG References;
    PFILE_OBJECT ImageFileObject;
    LARGE_INTEGER ImageLoadTime;
    LARGE_INTEGER SeenTime;
    WCHAR ImagePath[MAX_PATH_CHARS];
};

struct CaptureWork {
    PFLT_DEFERRED_IO_WORKITEM WorkItem;
    PFLT_INSTANCE Instance;
    PFILE_OBJECT FileObject;
    Candidate* Image;
    ULONG Operation;
    WCHAR DumpDirectory[512];
    WCHAR SourcePath[MAX_PATH_CHARS];
};

struct SnapshotScratch {
    WCHAR SnapshotDirectory[1024];
    WCHAR SourcePath[MAX_PATH_CHARS];
    WCHAR PartialPath[1200];
    WCHAR FinalPath[1200];
    WCHAR MetadataPath[1200];
    WCHAR EscapedSource[MAX_PATH_CHARS * 2];
    WCHAR EscapedVolume[MAX_PATH_CHARS * 2];
    WCHAR EscapedSnapshot[2400];
    WCHAR VolumePath[MAX_PATH_CHARS];
    WCHAR Metadata[8192];
    CHAR MetadataUtf8[16384];
};

class SnapshotScratchOwner {
public:
    explicit SnapshotScratchOwner(SnapshotScratch* scratch) : scratch_(scratch) {}
    SnapshotScratchOwner(const SnapshotScratchOwner&) = delete;
    SnapshotScratchOwner& operator=(const SnapshotScratchOwner&) = delete;
    ~SnapshotScratchOwner()
    {
        if (scratch_ != nullptr)
            ExFreePoolWithTag(scratch_, FILTER_TAG);
    }

    SnapshotScratch* operator->() const { return scratch_; }
    SnapshotScratch* get() const { return scratch_; }

private:
    SnapshotScratch* scratch_;
};

PFLT_FILTER gFilter = nullptr;
PFLT_PORT gServerPort = nullptr;
PFLT_PORT gClientPort = nullptr;
KSPIN_LOCK gCandidateLock;
LIST_ENTRY gCandidates;
ULONG gCandidateCount = 0;
KSPIN_LOCK gDirectoryLock;
EX_PUSH_LOCK gPortLock;
WCHAR gDumpDirectory[512] = L"C:\\DriverDump\\";
WCHAR gSystemRootDevicePath[256]{};
WCHAR gDriveDevicePaths[26][256]{};
volatile LONG gAttachedInstances = 0;
volatile LONG gUnloading = 0;
volatile LONG gImageCallbackRegistered = 0;
BCRYPT_ALG_HANDLE gSha256Provider = nullptr;
volatile LONG64 gUniqueId = 0;

void ReleaseCandidate(Candidate* candidate)
{
    if (candidate != nullptr && InterlockedDecrement(&candidate->References) == 0) {
        if (candidate->ImageFileObject != nullptr)
            ObDereferenceObject(candidate->ImageFileObject);
        ExFreePoolWithTag(candidate, FILTER_TAG);
    }
}

void CopyUnicodeString(PWCHAR destination, ULONG destinationChars, PCUNICODE_STRING source)
{
    if (destination == nullptr || destinationChars == 0)
        return;
    RtlZeroMemory(destination, destinationChars * sizeof(WCHAR));
    if (source == nullptr || source->Buffer == nullptr || source->Length == 0)
        return;
    ULONG chars = source->Length / sizeof(WCHAR);
    if (chars >= destinationChars)
        chars = destinationChars - 1;
    RtlCopyMemory(destination, source->Buffer, chars * sizeof(WCHAR));
}

NTSTATUS QuerySymbolicLinkTarget(PCWSTR linkName, PWCHAR targetBuffer, ULONG targetChars)
{
    if (linkName == nullptr || targetBuffer == nullptr || targetChars < 2)
        return STATUS_INVALID_PARAMETER;
    UNICODE_STRING link{};
    RtlInitUnicodeString(&link, linkName);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &link, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    HANDLE handle = nullptr;
    NTSTATUS status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &attributes);
    if (!NT_SUCCESS(status))
        return status;
    UNICODE_STRING target{};
    target.Buffer = targetBuffer;
    target.MaximumLength = static_cast<USHORT>(targetChars * sizeof(WCHAR));
    status = ZwQuerySymbolicLinkObject(handle, &target, nullptr);
    ZwClose(handle);
    if (NT_SUCCESS(status)) {
        ULONG chars = target.Length / sizeof(WCHAR);
        if (chars >= targetChars)
            chars = targetChars - 1;
        targetBuffer[chars] = UNICODE_NULL;
    }
    return status;
}

void ExpandImagePath(PWCHAR path, ULONG capacity)
{
    if (path == nullptr || path[0] == UNICODE_NULL)
        return;

    UNICODE_STRING input{};
    RtlInitUnicodeString(&input, path);
    UNICODE_STRING prefix = RTL_CONSTANT_STRING(L"\\SystemRoot");
    UNICODE_STRING dosDevicesPrefix = RTL_CONSTANT_STRING(L"\\DosDevices\\");
    UNICODE_STRING ntDosPrefix = RTL_CONSTANT_STRING(L"\\??\\");
    PWCHAR target = nullptr;
    ULONG prefixChars = 0;
    if (RtlPrefixUnicodeString(&prefix, &input, TRUE)) {
        if (input.Length != prefix.Length && input.Buffer[prefix.Length / sizeof(WCHAR)] != L'\\')
            return;
        target = gSystemRootDevicePath;
        prefixChars = prefix.Length / sizeof(WCHAR);
    } else if (RtlPrefixUnicodeString(&ntDosPrefix, &input, TRUE) ||
               RtlPrefixUnicodeString(&dosDevicesPrefix, &input, TRUE)) {
        prefixChars = RtlPrefixUnicodeString(&ntDosPrefix, &input, TRUE) ? 4 : 12;
        const ULONG driveOffset = prefixChars;
        if (input.Length / sizeof(WCHAR) >= driveOffset + 2 && input.Buffer[driveOffset + 1] == L':') {
            WCHAR drive = input.Buffer[driveOffset];
            if (drive >= L'a' && drive <= L'z') drive = static_cast<WCHAR>(drive - L'a' + L'A');
            if (drive < L'A' || drive > L'Z') return;
            target = gDriveDevicePaths[drive - L'A'];
            prefixChars = driveOffset + 2;
        } else {
            return;
        }
    } else if (input.Length / sizeof(WCHAR) >= 3 && input.Buffer[1] == L':' &&
               input.Buffer[2] == L'\\') {
        WCHAR drive = input.Buffer[0];
        if (drive >= L'a' && drive <= L'z') drive = static_cast<WCHAR>(drive - L'a' + L'A');
        if (drive < L'A' || drive > L'Z') return;
        target = gDriveDevicePaths[drive - L'A'];
        prefixChars = 2;
    } else {
        return;
    }

    if (target == nullptr || target[0] == UNICODE_NULL || capacity > MAX_PATH_CHARS)
        return;
    const ULONG inputChars = input.Length / sizeof(WCHAR);
    const ULONG suffixChars = inputChars - prefixChars;
    const WCHAR* suffix = input.Buffer + prefixChars;
    WCHAR expanded[MAX_PATH_CHARS]{};
    if (!NT_SUCCESS(RtlStringCchCopyW(expanded, RTL_NUMBER_OF(expanded), target)))
        return;
    if (suffixChars != 0) {
        ULONG expandedChars = 0;
        while (expandedChars + 1 < RTL_NUMBER_OF(expanded) && expanded[expandedChars] != UNICODE_NULL)
            ++expandedChars;
        if (expandedChars != 0 && expanded[expandedChars - 1] != L'\\' && suffix[0] != L'\\')
            RtlStringCchCatW(expanded, RTL_NUMBER_OF(expanded), L"\\");
        WCHAR suffixCopy[MAX_PATH_CHARS]{};
        ULONG copied = suffixChars < RTL_NUMBER_OF(suffixCopy) - 1 ? suffixChars : RTL_NUMBER_OF(suffixCopy) - 1;
        RtlCopyMemory(suffixCopy, suffix, copied * sizeof(WCHAR));
        suffixCopy[copied] = UNICODE_NULL;
        if (!NT_SUCCESS(RtlStringCchCatW(expanded, RTL_NUMBER_OF(expanded), suffixCopy)))
            return;
    }
    RtlStringCchCopyW(path, capacity, expanded);
}

void SnapshotCurrentDirectory(PWCHAR destination, ULONG destinationChars)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&gDirectoryLock, &oldIrql);
    RtlStringCchCopyW(destination, destinationChars, gDumpDirectory);
    KeReleaseSpinLock(&gDirectoryLock, oldIrql);
}

void AddImageCandidate(PCUNICODE_STRING imageName, PFILE_OBJECT fileObject)
{
    if (fileObject == nullptr &&
        (imageName == nullptr || imageName->Buffer == nullptr || imageName->Length == 0))
        return;

    auto candidate = static_cast<Candidate*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(Candidate), FILTER_TAG));
    if (candidate == nullptr)
        return;
    RtlZeroMemory(candidate, sizeof(*candidate));
    candidate->References = 1;
    candidate->ImageFileObject = fileObject;
    if (fileObject != nullptr)
        ObReferenceObject(fileObject);
    KeQuerySystemTime(&candidate->ImageLoadTime);
    candidate->SeenTime = candidate->ImageLoadTime;

    if (imageName != nullptr)
        CopyUnicodeString(candidate->ImagePath, RTL_NUMBER_OF(candidate->ImagePath), imageName);
    if (candidate->ImagePath[0] != UNICODE_NULL)
        ExpandImagePath(candidate->ImagePath, RTL_NUMBER_OF(candidate->ImagePath));

    LIST_ENTRY expired;
    InitializeListHead(&expired);
    LARGE_INTEGER now{};
    KeQuerySystemTime(&now);
    KIRQL oldIrql;
    KeAcquireSpinLock(&gCandidateLock, &oldIrql);

    for (PLIST_ENTRY entry = gCandidates.Flink; entry != &gCandidates;) {
        PLIST_ENTRY next = entry->Flink;
        auto old = CONTAINING_RECORD(entry, Candidate, Link);
        if (now.QuadPart >= old->SeenTime.QuadPart &&
            now.QuadPart - old->SeenTime.QuadPart > CANDIDATE_LIFETIME_100NS) {
            RemoveEntryList(&old->Link);
            InsertTailList(&expired, &old->Link);
            --gCandidateCount;
        }
        entry = next;
    }

    while (gCandidateCount >= MAX_CANDIDATES) {
        Candidate* oldest = nullptr;
        for (PLIST_ENTRY entry = gCandidates.Flink; entry != &gCandidates; entry = entry->Flink) {
            auto value = CONTAINING_RECORD(entry, Candidate, Link);
            if (oldest == nullptr || value->SeenTime.QuadPart < oldest->SeenTime.QuadPart)
                oldest = value;
        }
        if (oldest == nullptr)
            break;
        RemoveEntryList(&oldest->Link);
        InsertTailList(&expired, &oldest->Link);
        --gCandidateCount;
    }

    InsertHeadList(&gCandidates, &candidate->Link);
    ++gCandidateCount;
    KeReleaseSpinLock(&gCandidateLock, oldIrql);

    while (!IsListEmpty(&expired)) {
        PLIST_ENTRY entry = RemoveHeadList(&expired);
        ReleaseCandidate(CONTAINING_RECORD(entry, Candidate, Link));
    }
}

Candidate* FindCandidate(PFILE_OBJECT fileObject, PCUNICODE_STRING path)
{
    Candidate* match = nullptr;
    KIRQL oldIrql;
    KeAcquireSpinLock(&gCandidateLock, &oldIrql);
    for (PLIST_ENTRY entry = gCandidates.Flink; entry != &gCandidates; entry = entry->Flink) {
        auto candidate = CONTAINING_RECORD(entry, Candidate, Link);
        bool sameFile = fileObject != nullptr && candidate->ImageFileObject == fileObject;
        bool samePath = false;
        if (path != nullptr && path->Buffer != nullptr && candidate->ImagePath[0] != UNICODE_NULL) {
            UNICODE_STRING candidatePath{};
            RtlInitUnicodeString(&candidatePath, candidate->ImagePath);
            samePath = RtlEqualUnicodeString(&candidatePath, path, TRUE) != FALSE;
        }
        if (sameFile || samePath) {
            InterlockedIncrement(&candidate->References);
            KeQuerySystemTime(&candidate->SeenTime);
            match = candidate;
            break;
        }
    }
    KeReleaseSpinLock(&gCandidateLock, oldIrql);
    return match;
}

bool IsCandidateOperation(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects,
                          ULONG* operation, Candidate** matchedCandidate,
                          WCHAR* sourcePath, ULONG sourcePathChars)
{
    *operation = 0;
    *matchedCandidate = nullptr;
    sourcePath[0] = UNICODE_NULL;
    const UCHAR major = data->Iopb->MajorFunction;

    if (major == IRP_MJ_CREATE) {
        const ULONG options = data->Iopb->Parameters.Create.Options & 0x00ffffff;
        const ULONG disposition = data->Iopb->Parameters.Create.Options >> 24;
        if ((options & FILE_DELETE_ON_CLOSE) != 0)
            *operation = DT_FILTER_CAPTURE_DELETE_ON_CLOSE;
        else if (disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF)
            *operation = DT_FILTER_CAPTURE_OVERWRITE;
    } else if (major == IRP_MJ_SET_INFORMATION) {
        const FILE_INFORMATION_CLASS infoClass = data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        if (infoClass == FileDispositionInformation && data->Iopb->Parameters.SetFileInformation.InfoBuffer != nullptr) {
            auto info = static_cast<PFILE_DISPOSITION_INFORMATION>(data->Iopb->Parameters.SetFileInformation.InfoBuffer);
            if (info->DeleteFile)
                *operation = DT_FILTER_CAPTURE_DELETE;
        }
#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
        else if (infoClass == FileDispositionInformationEx && data->Iopb->Parameters.SetFileInformation.InfoBuffer != nullptr) {
            auto info = static_cast<PFILE_DISPOSITION_INFORMATION_EX>(data->Iopb->Parameters.SetFileInformation.InfoBuffer);
            if ((info->Flags & (FILE_DISPOSITION_DELETE | FILE_DISPOSITION_ON_CLOSE)) != 0)
                *operation = DT_FILTER_CAPTURE_DELETE;
        }
#endif
        else if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx ||
                 infoClass == FileRenameInformationBypassAccessCheck || infoClass == FileRenameInformationExBypassAccessCheck)
            *operation = DT_FILTER_CAPTURE_RENAME;
        else if (infoClass == FileEndOfFileInformation || infoClass == FileAllocationInformation ||
                 infoClass == FileValidDataLengthInformation)
            *operation = DT_FILTER_CAPTURE_TRUNCATE;
    } else if (major == IRP_MJ_WRITE) {
        *operation = DT_FILTER_CAPTURE_WRITE;
    }

    if (*operation == 0)
        return false;
    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
    if (!NT_SUCCESS(FltGetFileNameInformation(data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
        nameInfo = nullptr;

    UNICODE_STRING empty{};
    PCUNICODE_STRING path = nameInfo != nullptr ? &nameInfo->Name : &empty;
    Candidate* candidate = FindCandidate(objects->FileObject, path);
    if (nameInfo != nullptr) {
        if (candidate != nullptr)
            CopyUnicodeString(sourcePath, sourcePathChars, &nameInfo->Name);
        FltReleaseFileNameInformation(nameInfo);
    }
    if (candidate == nullptr)
        return false;
    *matchedCandidate = candidate;
    return true;
}

PCWSTR OperationName(ULONG operation)
{
    switch (operation) {
    case DT_FILTER_CAPTURE_DELETE: return L"delete";
    case DT_FILTER_CAPTURE_RENAME: return L"rename";
    case DT_FILTER_CAPTURE_TRUNCATE: return L"truncate";
    case DT_FILTER_CAPTURE_OVERWRITE: return L"overwrite";
    case DT_FILTER_CAPTURE_WRITE: return L"write";
    case DT_FILTER_CAPTURE_DELETE_ON_CLOSE: return L"delete-on-close";
    default: return L"unknown";
    }
}

void SendCaptureResult(const DT_FILTER_CAPTURE_RESULT& result)
{
    ExAcquirePushLockShared(&gPortLock);
    if (gClientPort != nullptr) {
        LARGE_INTEGER timeout{};
        timeout.QuadPart = -2000000; // Keep I/O completion independent of a stalled UI client.
        ULONG replyLength = 0;
        FltSendMessage(gFilter, &gClientPort, const_cast<DT_FILTER_CAPTURE_RESULT*>(&result),
                       sizeof(result), nullptr, &replyLength, &timeout);
    }
    ExReleasePushLockShared(&gPortLock);
}

void ReportImmediateCaptureFailure(Candidate* candidate, ULONG operation,
                                   PCWSTR sourcePath, NTSTATUS status)
{
    DT_FILTER_CAPTURE_RESULT result{};
    result.Version = DT_FILTER_PROTOCOL_VERSION;
    result.Operation = operation;
    result.Status = status;
    result.Attempts = 0;
    KeQuerySystemTime(reinterpret_cast<PLARGE_INTEGER>(&result.EventTime));
    RtlStringCchCopyW(result.SourcePath, RTL_NUMBER_OF(result.SourcePath),
        sourcePath != nullptr && sourcePath[0] != UNICODE_NULL ? sourcePath : candidate->ImagePath);
    RtlStringCchPrintfW(result.Detail, RTL_NUMBER_OF(result.Detail),
        L"Capture work could not be queued (NTSTATUS 0x%08X); operation denied.",
        static_cast<ULONG>(status));
    SendCaptureResult(result);
}

NTSTATUS OpenSnapshotDirectory(PCWSTR dumpDirectory, PWCHAR directoryPath, ULONG directoryChars)
{
    NTSTATUS status = RtlStringCchPrintfW(directoryPath, directoryChars,
                                         L"\\??\\%sSelfDeleteSnapshots\\", dumpDirectory);
    if (!NT_SUCCESS(status))
        return status;

    UNICODE_STRING name{};
    RtlInitUnicodeString(&name, directoryPath);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    IO_STATUS_BLOCK ioStatus{};
    HANDLE directoryHandle = nullptr;
    status = ZwCreateFile(&directoryHandle,
                          FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | SYNCHRONIZE, &attributes,
                          &ioStatus, nullptr, FILE_ATTRIBUTE_DIRECTORY,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
                          FILE_OPEN_FOR_BACKUP_INTENT, nullptr, 0);
    if (NT_SUCCESS(status))
        ZwClose(directoryHandle);
    return status;
}

NTSTATUS CreateEvidenceFile(PCWSTR path, HANDLE* handle)
{
    UNICODE_STRING name{};
    RtlInitUnicodeString(&name, path);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    IO_STATUS_BLOCK ioStatus{};
    return ZwCreateFile(handle, GENERIC_WRITE | SYNCHRONIZE | DELETE, &attributes, &ioStatus,
                        nullptr, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
                        FILE_OPEN_FOR_BACKUP_INTENT, nullptr, 0);
}

void DeleteEvidenceFile(PCWSTR path);

NTSTATUS WriteMetadataFile(PCWSTR path, PCCH text, ULONG textBytes)
{
    HANDLE fileHandle = nullptr;
    NTSTATUS status = CreateEvidenceFile(path, &fileHandle);
    if (!NT_SUCCESS(status))
        return status;
    IO_STATUS_BLOCK ioStatus{};
    status = ZwWriteFile(fileHandle, nullptr, nullptr, nullptr, &ioStatus,
                         const_cast<PCHAR>(text), textBytes, nullptr, nullptr);
    if (NT_SUCCESS(status) && ioStatus.Information != textBytes)
        status = STATUS_DISK_FULL;
    if (NT_SUCCESS(status))
        status = ZwFlushBuffersFile(fileHandle, &ioStatus);
    ZwClose(fileHandle);
    if (!NT_SUCCESS(status)) {
        // Do not leave a truncated JSON sidecar that could be mistaken for valid evidence.
        UNICODE_STRING name{};
        RtlInitUnicodeString(&name, path);
        OBJECT_ATTRIBUTES attributes;
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
        HANDLE cleanupHandle = nullptr;
        IO_STATUS_BLOCK cleanupStatus{};
        if (NT_SUCCESS(ZwCreateFile(&cleanupHandle, DELETE | SYNCHRONIZE, &attributes,
                &cleanupStatus, nullptr, FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0))) {
            FILE_DISPOSITION_INFORMATION disposition{ TRUE };
            ZwSetInformationFile(cleanupHandle, &cleanupStatus, &disposition,
                                 sizeof(disposition), FileDispositionInformation);
            ZwClose(cleanupHandle);
        }
    }
    return status;
}

void DeleteEvidenceFile(PCWSTR path)
{
    if (path == nullptr || path[0] == UNICODE_NULL)
        return;
    UNICODE_STRING name{};
    RtlInitUnicodeString(&name, path);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    HANDLE handle = nullptr;
    IO_STATUS_BLOCK ioStatus{};
    if (NT_SUCCESS(ZwCreateFile(&handle, DELETE | SYNCHRONIZE, &attributes, &ioStatus,
            nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0))) {
        FILE_DISPOSITION_INFORMATION disposition{ TRUE };
        ZwSetInformationFile(handle, &ioStatus, &disposition, sizeof(disposition), FileDispositionInformation);
        ZwClose(handle);
    }
}

NTSTATUS RenameSnapshot(HANDLE fileHandle, PCWSTR destination)
{
    UNICODE_STRING name{};
    RtlInitUnicodeString(&name, destination);
    ULONG bytes = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) + name.Length;
    auto rename = static_cast<PFILE_RENAME_INFORMATION>(ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, FILTER_TAG));
    if (rename == nullptr)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(rename, bytes);
    rename->ReplaceIfExists = FALSE;
    rename->RootDirectory = nullptr;
    rename->FileNameLength = name.Length;
    RtlCopyMemory(rename->FileName, name.Buffer, name.Length);
    IO_STATUS_BLOCK ioStatus{};
    NTSTATUS status = ZwSetInformationFile(fileHandle, &ioStatus, rename, bytes, FileRenameInformation);
    ExFreePoolWithTag(rename, FILTER_TAG);
    return status;
}

void EscapeJsonString(PCWSTR input, PWCHAR output, ULONG outputChars)
{
    ULONG at = 0;
    if (outputChars == 0)
        return;
    output[0] = UNICODE_NULL;
    for (ULONG index = 0; input != nullptr && input[index] != UNICODE_NULL; ++index) {
        const WCHAR ch = input[index];
        const PCWSTR escape = ch == L'\\' ? L"\\\\" : ch == L'"' ? L"\\\"" :
                              ch == L'\r' ? L"\\r" : ch == L'\n' ? L"\\n" : nullptr;
        if (escape != nullptr) {
            for (ULONG i = 0; escape[i] != UNICODE_NULL && at + 1 < outputChars; ++i)
                output[at++] = escape[i];
        } else if (ch < L' ' && at + 6 < outputChars) {
            static const WCHAR hex[] = L"0123456789abcdef";
            output[at++] = L'\\';
            output[at++] = L'u';
            output[at++] = L'0';
            output[at++] = L'0';
            output[at++] = hex[(ch >> 4) & 0xf];
            output[at++] = hex[ch & 0xf];
        } else if (at + 1 < outputChars) {
            output[at++] = ch;
        }
    }
    output[at] = UNICODE_NULL;
}

NTSTATUS SaveSnapshot(Candidate* candidate, CaptureWork* work,
                      DT_FILTER_CAPTURE_RESULT* result)
{
    auto scratchMemory = static_cast<SnapshotScratch*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SnapshotScratch), FILTER_TAG));
    if (scratchMemory == nullptr)
        return STATUS_INSUFFICIENT_RESOURCES;
    SnapshotScratchOwner scratch(scratchMemory);
    RtlZeroMemory(scratch.get(), sizeof(*scratch.get()));

    NTSTATUS status = OpenSnapshotDirectory(work->DumpDirectory,
        scratch->SnapshotDirectory, RTL_NUMBER_OF(scratch->SnapshotDirectory));
    if (!NT_SUCCESS(status))
        return status;

    if (work->SourcePath[0] != UNICODE_NULL)
        RtlStringCchCopyW(scratch->SourcePath, RTL_NUMBER_OF(scratch->SourcePath), work->SourcePath);
    else
        RtlStringCchCopyW(scratch->SourcePath, RTL_NUMBER_OF(scratch->SourcePath), candidate->ImagePath);
    if (scratch->SourcePath[0] == UNICODE_NULL)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    HANDLE sourceHandle = nullptr;
    PFILE_OBJECT sourceFile = nullptr;
    UNICODE_STRING sourceName{};
    RtlInitUnicodeString(&sourceName, scratch->SourcePath);
    OBJECT_ATTRIBUTES sourceAttributes;
    InitializeObjectAttributes(&sourceAttributes, &sourceName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    IO_STATUS_BLOCK sourceIoStatus{};
    NTSTATUS openStatus = FltCreateFileEx2(gFilter, work->Instance, &sourceHandle, &sourceFile,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &sourceAttributes, &sourceIoStatus,
        nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_FOR_BACKUP_INTENT, nullptr, 0, 0, nullptr);
    bool openedSource = NT_SUCCESS(openStatus) && sourceFile != nullptr;
    if (!openedSource)
        sourceFile = work->FileObject;
    if (sourceFile == nullptr)
        return openStatus;

    const ULONGLONG identifier = static_cast<ULONGLONG>(KeQueryInterruptTime()) ^
                                 static_cast<ULONGLONG>(InterlockedIncrement64(&gUniqueId));
    LARGE_INTEGER now{};
    KeQuerySystemTime(&now);
    const ULONGLONG stamp = static_cast<ULONGLONG>(now.QuadPart);
    status = RtlStringCchPrintfW(scratch->PartialPath, RTL_NUMBER_OF(scratch->PartialPath),
        L"%sImage-%016llX-%016llX.partial", scratch->SnapshotDirectory, stamp, identifier);
    if (NT_SUCCESS(status))
        status = RtlStringCchPrintfW(scratch->FinalPath, RTL_NUMBER_OF(scratch->FinalPath),
            L"%sImage-%016llX-%016llX.bin", scratch->SnapshotDirectory, stamp, identifier);
    if (NT_SUCCESS(status))
        status = RtlStringCchPrintfW(scratch->MetadataPath, RTL_NUMBER_OF(scratch->MetadataPath),
            L"%sImage-%016llX-%016llX.json", scratch->SnapshotDirectory, stamp, identifier);
    if (!NT_SUCCESS(status)) {
        if (openedSource) { ZwClose(sourceHandle); ObDereferenceObject(sourceFile); }
        return status;
    }

    HANDLE snapshotHandle = nullptr;
    status = CreateEvidenceFile(scratch->PartialPath, &snapshotHandle);
    if (!NT_SUCCESS(status)) {
        if (openedSource) { ZwClose(sourceHandle); ObDereferenceObject(sourceFile); }
        return status;
    }

    auto buffer = static_cast<PUCHAR>(ExAllocatePool2(POOL_FLAG_NON_PAGED, IO_BUFFER_BYTES, FILTER_TAG));
    if (buffer == nullptr) {
        ZwClose(snapshotHandle);
        DeleteEvidenceFile(scratch->PartialPath);
        if (openedSource) { ZwClose(sourceHandle); ObDereferenceObject(sourceFile); }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG hashObjectBytes = 0, returnedBytes = 0;
    status = BCryptGetProperty(gSha256Provider, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hashObjectBytes), sizeof(hashObjectBytes), &returnedBytes, 0);
    auto hashObject = NT_SUCCESS(status)
        ? ExAllocatePool2(POOL_FLAG_NON_PAGED, hashObjectBytes, FILTER_TAG) : nullptr;
    if (NT_SUCCESS(status) && hashObject == nullptr)
        status = STATUS_INSUFFICIENT_RESOURCES;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;
    if (NT_SUCCESS(status))
        status = BCryptCreateHash(gSha256Provider, &hashHandle, static_cast<PUCHAR>(hashObject),
                                  hashObjectBytes, nullptr, 0, 0);

    LARGE_INTEGER offset{};
    ULONGLONG totalBytes = 0;
    while (NT_SUCCESS(status)) {
        ULONG bytesRead = 0;
        status = FltReadFile(work->Instance, sourceFile, &offset, IO_BUFFER_BYTES,
                             buffer, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                             &bytesRead, nullptr, nullptr);
        if (status == STATUS_END_OF_FILE) {
            status = STATUS_SUCCESS;
            break;
        }
        if (!NT_SUCCESS(status) || bytesRead == 0)
            break;
        status = BCryptHashData(hashHandle, buffer, bytesRead, 0);
        if (!NT_SUCCESS(status))
            break;
        IO_STATUS_BLOCK writeStatus{};
        status = ZwWriteFile(snapshotHandle, nullptr, nullptr, nullptr, &writeStatus,
                             buffer, bytesRead, &offset, nullptr);
        if (!NT_SUCCESS(status))
            break;
        if (writeStatus.Information != bytesRead) {
            status = STATUS_DISK_FULL;
            break;
        }
        totalBytes += bytesRead;
        offset.QuadPart += bytesRead;
    }

    UCHAR digest[32]{};
    if (NT_SUCCESS(status))
        status = BCryptFinishHash(hashHandle, digest, sizeof(digest), 0);
    if (hashHandle != nullptr)
        BCryptDestroyHash(hashHandle);
    if (hashObject != nullptr)
        ExFreePoolWithTag(hashObject, FILTER_TAG);
    ExFreePoolWithTag(buffer, FILTER_TAG);

    if (NT_SUCCESS(status)) {
        IO_STATUS_BLOCK flushStatus{};
        status = ZwFlushBuffersFile(snapshotHandle, &flushStatus);
    }
    if (NT_SUCCESS(status))
        status = RenameSnapshot(snapshotHandle, scratch->FinalPath);
    ZwClose(snapshotHandle);
    if (openedSource) {
        ZwClose(sourceHandle);
        ObDereferenceObject(sourceFile);
    }
    if (!NT_SUCCESS(status)) {
        DeleteEvidenceFile(scratch->PartialPath);
        DeleteEvidenceFile(scratch->FinalPath);
        return status;
    }

    static const WCHAR hex[] = L"0123456789abcdef";
    for (ULONG index = 0; index < sizeof(digest); ++index) {
        result->Sha256[index * 2] = hex[digest[index] >> 4];
        result->Sha256[index * 2 + 1] = hex[digest[index] & 0xf];
    }
    result->Sha256[64] = UNICODE_NULL;
    result->Size = totalBytes;
    RtlStringCchCopyW(result->SnapshotPath, RTL_NUMBER_OF(result->SnapshotPath), scratch->FinalPath);

    UNICODE_STRING devicePrefix = RTL_CONSTANT_STRING(L"\\Device\\");
    UNICODE_STRING sourceNameString{};
    RtlInitUnicodeString(&sourceNameString, scratch->SourcePath);
    if (RtlPrefixUnicodeString(&devicePrefix, &sourceNameString, TRUE)) {
        ULONG slashCount = 0;
        for (ULONG index = devicePrefix.Length / sizeof(WCHAR); scratch->SourcePath[index] != UNICODE_NULL; ++index) {
            if (scratch->SourcePath[index] == L'\\' && ++slashCount == 1) {
                const ULONG chars = index;
                RtlCopyMemory(scratch->VolumePath, scratch->SourcePath, chars * sizeof(WCHAR));
                scratch->VolumePath[chars] = UNICODE_NULL;
                break;
            }
        }
    }
    EscapeJsonString(scratch->SourcePath, scratch->EscapedSource, RTL_NUMBER_OF(scratch->EscapedSource));
    EscapeJsonString(scratch->VolumePath, scratch->EscapedVolume, RTL_NUMBER_OF(scratch->EscapedVolume));
    EscapeJsonString(scratch->FinalPath, scratch->EscapedSnapshot, RTL_NUMBER_OF(scratch->EscapedSnapshot));
    status = RtlStringCchPrintfW(scratch->Metadata, RTL_NUMBER_OF(scratch->Metadata),
        L"{\r\n  \"version\": 1,\r\n  \"event_time_utc_filetime\": %I64d,\r\n"
        L"  \"image_load_time_utc_filetime\": %I64d,\r\n  \"operation\": \"%s\",\r\n"
        L"  \"result\": \"captured\",\r\n  \"size\": %I64u,\r\n"
        L"  \"sha256\": \"%s\",\r\n  \"source_volume\": \"%s\",\r\n"
        L"  \"source_path\": \"%s\",\r\n"
        L"  \"snapshot_path\": \"%s\"\r\n}\r\n",
        result->EventTime, candidate->ImageLoadTime.QuadPart, OperationName(work->Operation),
        result->Size, result->Sha256, scratch->EscapedVolume, scratch->EscapedSource, scratch->EscapedSnapshot);
    if (!NT_SUCCESS(status)) {
        DeleteEvidenceFile(scratch->FinalPath);
        return status;
    }
    ULONG metadataChars = 0;
    while (metadataChars < RTL_NUMBER_OF(scratch->Metadata) && scratch->Metadata[metadataChars] != UNICODE_NULL)
        ++metadataChars;
    ULONG metadataUtf8Bytes = 0;
    status = RtlUnicodeToUTF8N(scratch->MetadataUtf8, sizeof(scratch->MetadataUtf8), &metadataUtf8Bytes,
                               scratch->Metadata, metadataChars * sizeof(WCHAR));
    if (!NT_SUCCESS(status)) {
        DeleteEvidenceFile(scratch->FinalPath);
        return status;
    }
    status = WriteMetadataFile(scratch->MetadataPath, scratch->MetadataUtf8, metadataUtf8Bytes);
    if (!NT_SUCCESS(status))
        DeleteEvidenceFile(scratch->FinalPath);
    return status;
}

void ProcessCapture(CaptureWork* work, PFLT_CALLBACK_DATA data)
{
    Candidate* candidate = work->Image;
    NTSTATUS resultStatus = STATUS_SUCCESS;
    DT_FILTER_CAPTURE_RESULT result{};
    result.Version = DT_FILTER_PROTOCOL_VERSION;
    result.Operation = work->Operation;
    KeQuerySystemTime(reinterpret_cast<PLARGE_INTEGER>(&result.EventTime));
    RtlStringCchCopyW(result.SourcePath, RTL_NUMBER_OF(result.SourcePath),
        work->SourcePath[0] != UNICODE_NULL ? work->SourcePath : candidate->ImagePath);

    bool captured = false;
    for (ULONG attempt = 1; attempt <= MAX_CAPTURE_ATTEMPTS; ++attempt) {
        result.Attempts = attempt;
        RtlZeroMemory(result.Sha256, sizeof(result.Sha256));
        RtlZeroMemory(result.SnapshotPath, sizeof(result.SnapshotPath));
        result.Size = 0;
        resultStatus = SaveSnapshot(candidate, work, &result);
        if (NT_SUCCESS(resultStatus)) {
            captured = true;
            break;
        }
        if (attempt < MAX_CAPTURE_ATTEMPTS) {
            LARGE_INTEGER delay{};
            delay.QuadPart = -1000000; // 100 ms between bounded retries.
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    if (!captured) {
        if (resultStatus == STATUS_SUCCESS)
            resultStatus = STATUS_ACCESS_DENIED;
    }
    result.Status = resultStatus;
    if (captured) {
        RtlStringCchCopyW(result.Detail, RTL_NUMBER_OF(result.Detail), L"Snapshot, metadata and SHA-256 saved before the file operation.");
        data->IoStatus.Status = STATUS_SUCCESS;
        data->IoStatus.Information = 0;
        FltCompletePendedPreOperation(data, FLT_PREOP_SUCCESS_NO_CALLBACK, nullptr);
    } else {
        RtlStringCchPrintfW(result.Detail, RTL_NUMBER_OF(result.Detail),
            L"Capture failed with NTSTATUS 0x%08X after %lu attempts; operation denied.",
            static_cast<ULONG>(resultStatus), result.Attempts);
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        FltCompletePendedPreOperation(data, FLT_PREOP_COMPLETE, nullptr);
    }

    SendCaptureResult(result);
    ReleaseCandidate(candidate);
}

VOID FLTAPI CaptureWorkerRoutine(PFLT_DEFERRED_IO_WORKITEM workItem,
                                 PFLT_CALLBACK_DATA callbackData, PVOID context)
{
    auto work = static_cast<CaptureWork*>(context);
    ProcessCapture(work, callbackData);
    if (work->FileObject != nullptr)
        ObDereferenceObject(work->FileObject);
    FltObjectDereference(work->Instance);
    FltFreeDeferredIoWorkItem(workItem);
    ExFreePoolWithTag(work, FILTER_TAG);
}

FLT_PREOP_CALLBACK_STATUS FLTAPI DestructiveOperationPre(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID*)
{
    if (data->Iopb->MajorFunction == IRP_MJ_WRITE &&
        FlagOn(data->Iopb->IrpFlags, IRP_PAGING_IO))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    ULONG operation = 0;
    Candidate* candidate = nullptr;
    WCHAR sourcePath[MAX_PATH_CHARS]{};
    if (!IsCandidateOperation(data, objects, &operation, &candidate,
                              sourcePath, RTL_NUMBER_OF(sourcePath)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (FlagOn(data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)) {
        ReleaseCandidate(candidate);
        return FLT_PREOP_DISALLOW_FASTIO;
    }

    auto work = static_cast<CaptureWork*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CaptureWork), FILTER_TAG));
    if (work == nullptr) {
        ReportImmediateCaptureFailure(candidate, operation, sourcePath, STATUS_INSUFFICIENT_RESOURCES);
        ReleaseCandidate(candidate);
        data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    RtlZeroMemory(work, sizeof(*work));
    work->Image = candidate;
    work->Operation = operation;
    SnapshotCurrentDirectory(work->DumpDirectory, RTL_NUMBER_OF(work->DumpDirectory));
    work->Instance = objects->Instance;
    FltObjectReference(work->Instance);
    work->FileObject = objects->FileObject;
    if (work->FileObject != nullptr)
        ObReferenceObject(work->FileObject);
    RtlStringCchCopyW(work->SourcePath, RTL_NUMBER_OF(work->SourcePath),
                      sourcePath[0] != UNICODE_NULL ? sourcePath : candidate->ImagePath);
    work->WorkItem = FltAllocateDeferredIoWorkItem();
    if (work->WorkItem == nullptr) {
        ReportImmediateCaptureFailure(candidate, operation, work->SourcePath, STATUS_INSUFFICIENT_RESOURCES);
        if (work->FileObject != nullptr) ObDereferenceObject(work->FileObject);
        FltObjectDereference(work->Instance);
        ReleaseCandidate(candidate);
        ExFreePoolWithTag(work, FILTER_TAG);
        data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    NTSTATUS status = FltQueueDeferredIoWorkItem(work->WorkItem, data,
        CaptureWorkerRoutine, DelayedWorkQueue, work);
    if (!NT_SUCCESS(status)) {
        ReportImmediateCaptureFailure(candidate, operation, work->SourcePath, status);
        FltFreeDeferredIoWorkItem(work->WorkItem);
        if (work->FileObject != nullptr) ObDereferenceObject(work->FileObject);
        FltObjectDereference(work->Instance);
        ReleaseCandidate(candidate);
        ExFreePoolWithTag(work, FILTER_TAG);
        data->IoStatus.Status = status;
        data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_PENDING;
}

} // namespace

namespace {

bool ValidateDumpDirectory(PCWSTR directory)
{
    if (directory == nullptr || directory[0] == UNICODE_NULL ||
        !(((directory[0] >= L'A' && directory[0] <= L'Z') ||
           (directory[0] >= L'a' && directory[0] <= L'z')) &&
          directory[1] == L':' && directory[2] == L'\\'))
        return false;
    ULONG length = 0;
    while (length < 512 && directory[length] != UNICODE_NULL)
        ++length;
    if (length < 4 || length >= 512 || directory[length - 1] != L'\\')
        return false;
    for (ULONG index = 0; index < length; ++index) {
        const WCHAR ch = directory[index];
        if (ch == L'/' || ch == L'*' || ch == L'?' || ch == L'"' ||
            (ch == L':' && index != 1))
            return false;
    }
    return true;
}

void ClearCandidates()
{
    LIST_ENTRY detached;
    InitializeListHead(&detached);
    KIRQL oldIrql;
    KeAcquireSpinLock(&gCandidateLock, &oldIrql);
    while (!IsListEmpty(&gCandidates)) {
        PLIST_ENTRY entry = RemoveHeadList(&gCandidates);
        InsertTailList(&detached, entry);
    }
    gCandidateCount = 0;
    KeReleaseSpinLock(&gCandidateLock, oldIrql);
    while (!IsListEmpty(&detached)) {
        PLIST_ENTRY entry = RemoveHeadList(&detached);
        ReleaseCandidate(CONTAINING_RECORD(entry, Candidate, Link));
    }
}

VOID FLTAPI ImageLoadNotify(PUNICODE_STRING fullImageName, HANDLE processId, PIMAGE_INFO imageInfo)
{
    if (processId != nullptr || imageInfo == nullptr || imageInfo->SystemModeImage == 0)
        return;
    PFILE_OBJECT fileObject = nullptr;
    if (imageInfo->ExtendedInfoPresent != 0) {
        auto extended = CONTAINING_RECORD(imageInfo, IMAGE_INFO_EX, ImageInfo);
        fileObject = extended->FileObject;
    }
    AddImageCandidate(fullImageName, fileObject);
}

NTSTATUS FLTAPI FilterInstanceSetup(PCFLT_RELATED_OBJECTS,
    FLT_INSTANCE_SETUP_FLAGS, DEVICE_TYPE volumeDeviceType, FLT_FILESYSTEM_TYPE)
{
    if (volumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
        return STATUS_FLT_DO_NOT_ATTACH;
    InterlockedIncrement(&gAttachedInstances);
    return STATUS_SUCCESS;
}
VOID FLTAPI FilterInstanceTeardownComplete(PCFLT_RELATED_OBJECTS,
                                            FLT_INSTANCE_TEARDOWN_FLAGS)
{
    if (InterlockedDecrement(&gAttachedInstances) == 0 && InterlockedCompareExchange(&gUnloading, 0, 0) != 0) {
        ClearCandidates();
        if (gSha256Provider != nullptr) {
            BCryptCloseAlgorithmProvider(gSha256Provider, 0);
            gSha256Provider = nullptr;
        }
    }
}

NTSTATUS FLTAPI FilterUnloadCallback(FLT_FILTER_UNLOAD_FLAGS)
{
    InterlockedExchange(&gUnloading, 1);
    if (InterlockedExchange(&gImageCallbackRegistered, 0) != 0)
        PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);
    if (gServerPort != nullptr) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = nullptr;
    }

    // The filter manager does not unregister the minifilter on our behalf.
    // Detach it from every volume and drain its callbacks before the image is
    // unloaded; otherwise stale callback pointers can bugcheck the next I/O.
    if (gFilter != nullptr) {
        PFLT_FILTER filter = gFilter;
        FltUnregisterFilter(filter);
        gFilter = nullptr;
    }

    if (InterlockedCompareExchange(&gAttachedInstances, 0, 0) == 0) {
        ClearCandidates();
        if (gSha256Provider != nullptr) {
            BCryptCloseAlgorithmProvider(gSha256Provider, 0);
            gSha256Provider = nullptr;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS FLTAPI ClientConnect(PFLT_PORT clientPort, PVOID, PVOID, ULONG, PVOID* connectionCookie)
{
    ExAcquirePushLockExclusive(&gPortLock);
    if (gClientPort != nullptr) {
        ExReleasePushLockExclusive(&gPortLock);
        return STATUS_CONNECTION_COUNT_LIMIT;
    }
    gClientPort = clientPort;
    *connectionCookie = clientPort;
    ExReleasePushLockExclusive(&gPortLock);
    return STATUS_SUCCESS;
}

VOID FLTAPI ClientDisconnect(PVOID connectionCookie)
{
    ExAcquirePushLockExclusive(&gPortLock);
    if (gClientPort == connectionCookie)
        gClientPort = nullptr;
    ExReleasePushLockExclusive(&gPortLock);
    auto clientPort = static_cast<PFLT_PORT>(connectionCookie);
    if (clientPort != nullptr)
        FltCloseClientPort(gFilter, &clientPort);
}

NTSTATUS FLTAPI ClientMessage(PVOID, PVOID inputBuffer, ULONG inputLength,
                              PVOID outputBuffer, ULONG outputLength, PULONG returnLength)
{
    *returnLength = 0;
    if (inputBuffer == nullptr || inputLength < sizeof(DT_FILTER_COMMAND) ||
        outputBuffer == nullptr || outputLength < sizeof(DT_FILTER_REPLY))
        return STATUS_INVALID_PARAMETER;

    auto command = static_cast<DT_FILTER_COMMAND*>(inputBuffer);
    if (command->Version != DT_FILTER_PROTOCOL_VERSION)
        return STATUS_REVISION_MISMATCH;
    auto reply = static_cast<DT_FILTER_REPLY*>(outputBuffer);
    RtlZeroMemory(reply, sizeof(*reply));
    reply->Version = DT_FILTER_PROTOCOL_VERSION;
    reply->Status = STATUS_SUCCESS;
    const LONG attached = InterlockedCompareExchange(&gAttachedInstances, 0, 0);
    reply->AttachedInstances = attached > 0 ? static_cast<ULONG>(attached) : 0;

    if (command->Command == DT_FILTER_COMMAND_SET_DIRECTORY) {
        if (!ValidateDumpDirectory(command->Directory)) {
            reply->Status = STATUS_INVALID_PARAMETER;
            *returnLength = sizeof(*reply);
            return STATUS_SUCCESS;
        }
        KIRQL oldIrql;
        KeAcquireSpinLock(&gDirectoryLock, &oldIrql);
        RtlCopyMemory(gDumpDirectory, command->Directory, sizeof(gDumpDirectory));
        KeReleaseSpinLock(&gDirectoryLock, oldIrql);
    } else if (command->Command != DT_FILTER_COMMAND_QUERY_STATE) {
        reply->Status = STATUS_INVALID_DEVICE_REQUEST;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&gCandidateLock, &oldIrql);
    reply->CandidateImages = gCandidateCount;
    KeReleaseSpinLock(&gCandidateLock, oldIrql);
    *returnLength = sizeof(*reply);
    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION gOperationCallbacks[] = {
    { IRP_MJ_CREATE, 0, DestructiveOperationPre, nullptr },
    { IRP_MJ_SET_INFORMATION, 0, DestructiveOperationPre, nullptr },
    { IRP_MJ_WRITE, 0, DestructiveOperationPre, nullptr },
    { IRP_MJ_OPERATION_END }
};

FLT_REGISTRATION gFilterRegistration{};

void InitializePathMappings()
{
    RtlZeroMemory(gSystemRootDevicePath, sizeof(gSystemRootDevicePath));
    RtlZeroMemory(gDriveDevicePaths, sizeof(gDriveDevicePaths));
    QuerySymbolicLinkTarget(L"\\SystemRoot", gSystemRootDevicePath,
                            RTL_NUMBER_OF(gSystemRootDevicePath));
    for (WCHAR drive = L'A'; drive <= L'Z'; ++drive) {
        WCHAR linkName[16]{};
        if (NT_SUCCESS(RtlStringCchPrintfW(linkName, RTL_NUMBER_OF(linkName), L"\\??\\%c:", drive))) {
            PWCHAR target = gDriveDevicePaths[drive - L'A'];
            ULONG targetChars = RTL_NUMBER_OF(gDriveDevicePaths[drive - L'A']);
            if (!NT_SUCCESS(QuerySymbolicLinkTarget(linkName, target, targetChars)) || target[0] == UNICODE_NULL) {
                if (NT_SUCCESS(RtlStringCchPrintfW(linkName, RTL_NUMBER_OF(linkName), L"\\GLOBAL??\\%c:", drive)))
                    QuerySymbolicLinkTarget(linkName, target, targetChars);
            }
        }
    }
}

} // namespace

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);
    KeInitializeSpinLock(&gCandidateLock);
    KeInitializeSpinLock(&gDirectoryLock);
    InitializeListHead(&gCandidates);
    ExInitializePushLock(&gPortLock);
    InitializePathMappings();

    NTSTATUS status = BCryptOpenAlgorithmProvider(&gSha256Provider, BCRYPT_SHA256_ALGORITHM,
                                                   nullptr, BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(status))
        return status;

    gFilterRegistration.Size = sizeof(gFilterRegistration);
    gFilterRegistration.Version = FLT_REGISTRATION_VERSION;
    gFilterRegistration.OperationRegistration = gOperationCallbacks;
    gFilterRegistration.FilterUnloadCallback = FilterUnloadCallback;
    gFilterRegistration.InstanceSetupCallback = FilterInstanceSetup;
    gFilterRegistration.InstanceTeardownCompleteCallback = FilterInstanceTeardownComplete;

    status = FltRegisterFilter(driverObject, &gFilterRegistration, &gFilter);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(gSha256Provider, 0);
        gSha256Provider = nullptr;
        return status;
    }

    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING portName = RTL_CONSTANT_STRING(DT_FILTER_PORT_NAME);
        OBJECT_ATTRIBUTES attributes;
        InitializeObjectAttributes(&attributes, &portName,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, securityDescriptor);
        status = FltCreateCommunicationPort(gFilter, &gServerPort, &attributes, nullptr,
                                             ClientConnect, ClientDisconnect, ClientMessage, 1);
        FltFreeSecurityDescriptor(securityDescriptor);
    }
    if (NT_SUCCESS(status))
        status = FltStartFiltering(gFilter);
    if (NT_SUCCESS(status)) {
        status = PsSetLoadImageNotifyRoutine(ImageLoadNotify);
        if (NT_SUCCESS(status))
            InterlockedExchange(&gImageCallbackRegistered, 1);
    }
    if (!NT_SUCCESS(status)) {
        if (gServerPort != nullptr) {
            FltCloseCommunicationPort(gServerPort);
            gServerPort = nullptr;
        }
        InterlockedExchange(&gUnloading, 1);
        FltUnregisterFilter(gFilter);
        gFilter = nullptr;
        if (gAttachedInstances == 0)
            ClearCandidates();
        if (gSha256Provider != nullptr) {
            BCryptCloseAlgorithmProvider(gSha256Provider, 0);
            gSha256Provider = nullptr;
        }
        return status;
    }
    return STATUS_SUCCESS;
}
