#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <exception>
#include <cstdlib>
#include <stdlib.h>

// Desktop C++/WinRT apps don't link the C++/WinRT runtime library,
// so disable the DLL module lock to avoid linker errors for delegates.
#define WINRT_NO_MODULE_LOCK

// C++/WinRT for Windows Toast notifications
// Must include Foundation.h for TypedEventHandler constructor definitions.
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.UI.Notifications.h>
#include <winrt/Windows.Data.Xml.Dom.h>

// COM/Shell for AUMID shortcut registration
#include <ShlObj.h>       // SHGetFolderPathW, CSIDL_PROGRAMS
#include <shobjidl.h>     // IShellLinkW, CLSID_ShellLink
#include <propsys.h>      // IPropertyStore
#include <propkey.h>      // PKEY_AppUserModel_ID
#include <propvarutil.h>  // InitPropVariantFromString, PropVariantClear

// Resource ID for the embedded driver
#include "driver_resource.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "propsys.lib")

using namespace winrt;
using namespace Windows::UI::Notifications;
using namespace Windows::Data::Xml::Dom;

#define IOCTL_REGISTER_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_LOAD_DATA  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _DRIVER_LOAD_INFO {
    WCHAR FilePath[512];
} DRIVER_LOAD_INFO, *PDRIVER_LOAD_INFO;

// AppUserModelID — identifies this app to the Windows notification system.
constexpr wchar_t AUMID[] = L"DriverTarpper.DriverMonitor";

// Paths for the embedded driver extraction.
const wchar_t* const DRIVER_DIR      = L"C:\\DriverDump";
const wchar_t* const DRIVER_SYS_PATH = L"C:\\DriverDump\\kdt.sys";

// Shutdown event signalled by the console control handler on Ctrl+C.
static HANDLE g_hShutdownEvent = nullptr;

// Handle to the installed kernel-driver service (kdt).
static SC_HANDLE g_hDriverService = nullptr;

// ---------------------------------------------------------------------------
// Toast notification helpers
// ---------------------------------------------------------------------------

bool EnsureAumidShortcut()
{
    wchar_t startMenuPath[MAX_PATH];
    HRESULT hr = SHGetFolderPathW(nullptr, CSIDL_PROGRAMS, nullptr, SHGFP_TYPE_CURRENT, startMenuPath);
    if (FAILED(hr)) return false;

    std::wstring shortcutPath = std::wstring(startMenuPath) + L"\\检测到驱动加载.lnk";

    DWORD attr = GetFileAttributesW(shortcutPath.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
        return true;

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    auto shellLink = winrt::create_instance<IShellLinkW>(CLSID_ShellLink, CLSCTX_INPROC_SERVER);
    if (!shellLink) return false;

    shellLink->SetPath(exePath);
    shellLink->SetDescription(L"DriverTarpper -- Kernel driver load monitor");

    auto propStore = shellLink.as<IPropertyStore>();

    PROPVARIANT pv{};
    hr = InitPropVariantFromString(AUMID, &pv);
    if (FAILED(hr)) return false;

    hr = propStore->SetValue(PKEY_AppUserModel_ID, pv);
    PropVariantClear(&pv);
    if (FAILED(hr)) return false;

    propStore->Commit();

    auto persistFile = shellLink.as<IPersistFile>();
    hr = persistFile->Save(shortcutPath.c_str(), TRUE);
    return SUCCEEDED(hr);
}

// Keep active toast notifications alive so their Activated callbacks can fire.
static std::vector<Windows::UI::Notifications::ToastNotification> g_activeToasts;

void ShowToast(const std::wstring& title, const std::wstring& body, const std::wstring& launchPath)
{
    try {
        auto xml = ToastNotificationManager::GetTemplateContent(ToastTemplateType::ToastText02);
        auto texts = xml.GetElementsByTagName(L"text");
        texts.Item(0).AppendChild(xml.CreateTextNode(title.c_str()));
        texts.Item(1).AppendChild(xml.CreateTextNode(body.c_str()));

        // Embed the file path so the activated callback can open it.
        auto toastNode = xml.SelectSingleNode(L"/toast");
        toastNode.as<Windows::Data::Xml::Dom::XmlElement>().SetAttribute(L"launch", launchPath.c_str());

        auto toast = ToastNotification(xml);

        // Capture by copy: each toast instance carries its own path.
        toast.Activated([path = launchPath](winrt::Windows::UI::Notifications::ToastNotification const&,
                                            winrt::Windows::Foundation::IInspectable const&) {
            if (path.empty()) return;
            std::wstring explorerArgs = L"/select,\"" + path + L"\"";
            ShellExecuteW(nullptr, L"open", L"explorer.exe",
                          explorerArgs.c_str(), nullptr, SW_SHOWNORMAL);
        });

        g_activeToasts.push_back(std::move(toast));
        ToastNotificationManager::CreateToastNotifier(AUMID).Show(g_activeToasts.back());
    }
    catch (const winrt::hresult_error& e) {
        std::wcerr << L"[-] Toast notification failed: " << e.message().c_str() << std::endl;
    }
}

std::wstring FileNameFromPath(const std::wstring& path)
{
    auto pos = path.rfind(L'\\');
    if (pos == std::wstring::npos) return path;
    return path.substr(pos + 1);
}

// ---------------------------------------------------------------------------
// Embedded-driver extraction + service management
// ---------------------------------------------------------------------------

/// Extract the embedded kdt.sys from this executable's resources to disk.
static bool ExtractDriverTo(const std::wstring& destPath)
{
    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_KDT_DRIVER), RT_RCDATA);
    if (!hRes) {
        std::wcerr << L"[-] Driver resource not found (IDR_KDT_DRIVER)." << std::endl;
        return false;
    }

    HGLOBAL hLoaded = LoadResource(nullptr, hRes);
    if (!hLoaded) return false;

    void* pData = LockResource(hLoaded);
    DWORD dataSize = SizeofResource(nullptr, hRes);

    if (pData == nullptr || dataSize == 0) return false;

    HANDLE hFile = CreateFileW(destPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] Cannot write driver to " << destPath
                    << L" (error " << GetLastError() << L")" << std::endl;
        return false;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, pData, dataSize, &written, nullptr);
    CloseHandle(hFile);

    if (!ok || written != dataSize) {
        DeleteFileW(destPath.c_str());
        return false;
    }
    return true;
}

/// Before extracting the driver binary, stop + delete any stale "kdt" service
/// from a previous (possibly crashed) run.  This forces the kernel to unload
/// the old driver module and release the file lock on kdt.sys.
static void CleanupStaleDriverService()
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return;

    SC_HANDLE hService = OpenServiceW(hSCM, L"kdt", SERVICE_ALL_ACCESS);
    if (hService) {
        SERVICE_STATUS ss{};
        ControlService(hService, SERVICE_CONTROL_STOP, &ss);
        DeleteService(hService);
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCM);
}

/// Install (create or update) and start the kernel driver service.
/// The caller should call StopDriverService() during shutdown.
static bool InstallAndStartDriver(const std::wstring& binaryPath)
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        std::wcerr << L"[-] OpenSCManager failed (error " << GetLastError() << L")" << std::endl;
        return false;
    }

    // Create fresh.  If a stale service entry lingers (race between
    // CleanupStaleDriverService and here), delete it and retry.
    SC_HANDLE hService = nullptr;
    for (int attempt = 0; attempt < 3; ++attempt) {
        hService = CreateServiceW(hSCM, L"kdt", L"kdt Service",
                                  SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                                  SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                  binaryPath.c_str(),
                                  nullptr, nullptr, nullptr, nullptr, nullptr);
        if (hService) break;

        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_EXISTS) {
            std::wcerr << L"[-] CreateService failed (error " << err << L")" << std::endl;
            CloseServiceHandle(hSCM);
            return false;
        }

        // Stale entry still present — remove it and retry.
        SC_HANDLE hOld = OpenServiceW(hSCM, L"kdt", DELETE | SERVICE_STOP);
        if (hOld) {
            SERVICE_STATUS ss{};
            ControlService(hOld, SERVICE_CONTROL_STOP, &ss);
            DeleteService(hOld);
            CloseServiceHandle(hOld);
        }
        Sleep(500);
    }
    CloseServiceHandle(hSCM);

    // Start (may already be running from a prior run of this same binary).
    if (!StartServiceW(hService, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            std::wcerr << L"[-] StartService failed (error " << err << L")" << std::endl;
            CloseServiceHandle(hService);
            return false;
        }
    }

    // Keep the handle so StopDriverService can stop + delete later.
    g_hDriverService = hService;
    return true;
}

static void StopDriverService()
{
    if (!g_hDriverService) return;

    // Stop the kernel driver.
    SERVICE_STATUS ss{};
    ControlService(g_hDriverService, SERVICE_CONTROL_STOP, &ss);

    // Mark for deletion — the SCM removes the entry once the service stops
    // and the last handle is closed (which happens right below).
    DeleteService(g_hDriverService);

    CloseServiceHandle(g_hDriverService);
    g_hDriverService = nullptr;

    // Clean up the extracted driver binary left on disk.
    DeleteFileW(DRIVER_SYS_PATH);
}

// ---------------------------------------------------------------------------
// Console control handler  (Ctrl+C / window close)
// ---------------------------------------------------------------------------

static BOOL WINAPI CtrlHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT ||
        ctrlType == CTRL_CLOSE_EVENT) {
        if (g_hShutdownEvent)
            SetEvent(g_hShutdownEvent);
        return TRUE;                    // don't terminate yet — let main() clean up
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Crash / unexpected-exit handlers  (best-effort driver cleanup)
// ---------------------------------------------------------------------------

/// SEH exception filter — called for access violations, stack overflows, etc.
static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS* /*ep*/)
{
    // Best-effort: if the process state isn't too corrupted this will
    // stop + delete the driver service.  If the heap is corrupt the call
    // just silently fails — no worse than crashing without the filter.
    StopDriverService();
    return EXCEPTION_CONTINUE_SEARCH;   // let WER capture the crash dump
}

/// Called by the runtime when an exception escapes a noexcept function,
/// or when a destructor / unhandled exception causes std::terminate.
static void TerminateHandler()
{
    StopDriverService();
    // Returning from a terminate handler still calls abort();
    // that's fine — the service cleanup happened above.
}

/// Called when a pure virtual function call occurs (usually a vtable race).
static void PureCallHandler()
{
    StopDriverService();
}

// ---------------------------------------------------------------------------
// NT path → DOS path conversion (unchanged)
// ---------------------------------------------------------------------------

std::wstring NtPathToDosPath(const std::wstring& ntPath)
{
    if (ntPath.empty()) {
        return L"";
    }
    const std::wstring devicePrefix = L"\\Device\\";
    size_t searchStart = 2;
    if (ntPath.find(devicePrefix) == 0) {
        searchStart = devicePrefix.length();
    }
    size_t deviceEndPos = ntPath.find(L'\\', searchStart);
    if (deviceEndPos == std::wstring::npos) {
        deviceEndPos = ntPath.length();
    }
    std::wstring deviceName = ntPath.substr(0, deviceEndPos);
    std::wstring relativePath;
    if (deviceEndPos < ntPath.length()) {
        relativePath = ntPath.substr(deviceEndPos);
    }
    std::vector<wchar_t> buffer;
    DWORD requiredSize = 0;
    while (true) {
        buffer.resize(buffer.size() + 4096);
        requiredSize = QueryDosDevice(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (requiredSize > 0) {
            break;
        }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return L"";
        }
    }
    std::vector<std::wstring> dosDevices;
    const wchar_t* ptr = buffer.data();
    while (*ptr) {
        dosDevices.emplace_back(ptr);
        ptr += wcslen(ptr) + 1;
    }
    for (const auto& dosDevice : dosDevices) {
        if (dosDevice.length() != 2 || dosDevice[1] != L':') {
            continue;
        }
        std::vector<wchar_t> ntDevicePath(MAX_PATH);
        DWORD result = QueryDosDevice(dosDevice.c_str(), ntDevicePath.data(), static_cast<DWORD>(ntDevicePath.size()));
        if (result == 0) {
            DWORD needed = GetLastError();
            if (needed == ERROR_INSUFFICIENT_BUFFER) {
                needed = QueryDosDevice(dosDevice.c_str(), nullptr, 0);
                if (needed > 0) {
                    ntDevicePath.resize(needed);
                    result = QueryDosDevice(dosDevice.c_str(), ntDevicePath.data(), static_cast<DWORD>(ntDevicePath.size()));
                }
            }
        }
        if (result > 0) {
            std::wstring ntDevicePathStr(ntDevicePath.data());
            if (ntPath.find(ntDevicePathStr) == 0) {
                std::wstring dosPath = dosDevice + relativePath;
                return dosPath;
            }
        }
    }
    return L"";
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    // ---------- initialise ----------
    winrt::init_apartment(winrt::apartment_type::multi_threaded);

    // Register crash handlers for best-effort driver cleanup on unexpected exit.
    SetUnhandledExceptionFilter(ExceptionFilter);
    std::set_terminate(TerminateHandler);
    _set_purecall_handler(PureCallHandler);

    // AUMID shortcut (toast notifications)
    if (!EnsureAumidShortcut()) {
        std::wcerr << L"[!] Could not register AUMID shortcut -- "
                    << L"toast notifications may not appear." << std::endl;
    }

    // Shutdown event + Ctrl handler so we can clean up the driver gracefully.
    g_hShutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);  // manual-reset
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // ---------- stop stale driver & extract embedded driver ----------
    CreateDirectoryW(DRIVER_DIR, nullptr);

    // Stop + delete any stale service from a previous (crashed) run,
    // so the kernel unloads the old driver and releases the file lock.
    CleanupStaleDriverService();

    std::wcout << L"[*] Extracting driver to " << DRIVER_SYS_PATH << L" ... ";
    bool extracted = false;
    for (int retry = 0; retry < 8; ++retry) {
        if (ExtractDriverTo(DRIVER_SYS_PATH)) {
            extracted = true;
            break;
        }
        // The old driver may still be unloading — wait and retry.
        Sleep(500);
    }
    if (!extracted) {
        std::wcerr << L"FAILED" << std::endl;
        return 1;
    }
    std::wcout << L"OK (" << DRIVER_SYS_PATH << L")" << std::endl;

    // ---------- install & start driver service ----------
    std::wcout << L"[*] Installing/starting driver service ... ";
    if (!InstallAndStartDriver(DRIVER_SYS_PATH)) {
        std::wcerr << L"FAILED" << std::endl;
        return 1;
    }
    std::wcout << L"OK" << std::endl;

    // ---------- open driver device (with retry) ----------
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 20; ++attempt) {
        hDevice = CreateFileW(L"\\\\.\\kdt",
                              GENERIC_READ | GENERIC_WRITE,
                              0, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hDevice != INVALID_HANDLE_VALUE) break;

        if (WaitForSingleObject(g_hShutdownEvent, 250) == WAIT_OBJECT_0) {
            // User hit Ctrl+C during startup.
            StopDriverService();
            return 0;
        }
    }

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to open driver device. Error: " << GetLastError() << std::endl;
        StopDriverService();
        return 1;
    }

    // ---------- register event ----------
    HANDLE hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (hEvent == nullptr) {
        std::cerr << "[-] Failed to create event." << std::endl;
        CloseHandle(hDevice);
        StopDriverService();
        return 1;
    }

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDevice, IOCTL_REGISTER_EVENT,
                         &hEvent, sizeof(HANDLE), nullptr, 0,
                         &bytesReturned, nullptr)) {
        std::cerr << "[-] Failed to register event. Error: " << GetLastError() << std::endl;
        CloseHandle(hEvent);
        CloseHandle(hDevice);
        StopDriverService();
        return 1;
    }

    std::cout << "[+] Monitoring started. Waiting for driver loads..." << std::endl;
    std::cout << "    Press Ctrl+C to stop and unload the monitor driver." << std::endl;

    // ---------- monitor loop ----------
    HANDLE waitHandles[] = { hEvent, g_hShutdownEvent };

    while (true) {
        DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

        if (waitResult == WAIT_OBJECT_0) {
            // Driver load event from kdt
            DRIVER_LOAD_INFO loadInfo;
            while (DeviceIoControl(hDevice, IOCTL_GET_LOAD_DATA,
                                   nullptr, 0, &loadInfo, sizeof(DRIVER_LOAD_INFO),
                                   &bytesReturned, nullptr)) {
                if (bytesReturned == 0) break;

                auto dosp = NtPathToDosPath(loadInfo.FilePath);
                auto fileName = FileNameFromPath(dosp.empty()
                    ? std::wstring(loadInfo.FilePath)
                    : dosp);
                std::wstring dumpedPath = std::wstring(DRIVER_DIR) + L"\\" + fileName;

                std::wcerr << L"[*] Notification: Driver Loaded";
                if (!dosp.empty()) {
                    std::wcerr << L" -> " << dosp;
                }
                std::wcerr << L"\n    Dumped to -> " << dumpedPath << '\n';

                ShowToast(L"检测到驱动加载", dumpedPath, dumpedPath);
            }
        } else {
            // Shutdown signal (Ctrl+C)
            std::cout << "[+] Shutting down..." << std::endl;
            break;
        }
    }

    // ---------- cleanup ----------
    CloseHandle(hEvent);
    CloseHandle(hDevice);
    StopDriverService();
    CloseHandle(g_hShutdownEvent);
    g_hShutdownEvent = nullptr;

    return 0;
}
