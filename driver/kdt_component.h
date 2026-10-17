#pragma once

#include <ntifs.h>

extern "C" NTSTATUS KdtInitialize(PDRIVER_OBJECT driverObject);
extern "C" VOID KdtCleanup(PDRIVER_OBJECT driverObject);
