#pragma once

#define DT_FILTER_PROTOCOL_VERSION 1
#define DT_FILTER_SERVICE_NAME L"dtself"
#define DT_FILTER_PORT_NAME L"\\SelfDeleteCapturePort"
#define DT_FILTER_ALTITUDE L"385201"

#define DT_FILTER_COMMAND_SET_DIRECTORY 1
#define DT_FILTER_COMMAND_QUERY_STATE 2

#define DT_FILTER_CAPTURE_DELETE 1
#define DT_FILTER_CAPTURE_RENAME 2
#define DT_FILTER_CAPTURE_TRUNCATE 3
#define DT_FILTER_CAPTURE_OVERWRITE 4
#define DT_FILTER_CAPTURE_WRITE 5
#define DT_FILTER_CAPTURE_DELETE_ON_CLOSE 6

typedef struct _DT_FILTER_COMMAND {
    unsigned long Version;
    unsigned long Command;
    wchar_t Directory[512];
} DT_FILTER_COMMAND;

typedef struct _DT_FILTER_REPLY {
    unsigned long Version;
    long Status;
    unsigned long AttachedInstances;
    unsigned long CandidateImages;
} DT_FILTER_REPLY;

typedef struct _DT_FILTER_CAPTURE_RESULT {
    unsigned long Version;
    unsigned long Operation;
    long Status;
    unsigned long Attempts;
    unsigned long long Size;
    long long EventTime;
    wchar_t SourcePath[1024];
    wchar_t SnapshotPath[1024];
    wchar_t Sha256[65];
    wchar_t Detail[256];
} DT_FILTER_CAPTURE_RESULT;
