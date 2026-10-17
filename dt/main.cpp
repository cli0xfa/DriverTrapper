#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <propsys.h>
#include <propkey.h>
#include <propvarutil.h>
#include <fltUser.h>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.UI.Notifications.h>
#include <winrt/Windows.Data.Xml.Dom.h>

#include <algorithm>
#include <exception>
#include <cstdlib>
#include <eh.h>
#include <filesystem>
#include <iterator>
#include <memory>
#include <new>
#include <process.h>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "..\\sdfilter\\filter_protocol.h"

#pragma comment(lib, "propsys.lib")

using namespace winrt;
using namespace Windows::UI::Notifications;
using namespace Windows::Data::Xml::Dom;

#define IOCTL_REGISTER_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_LOAD_DATA  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_DUMP_DIRECTORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

constexpr wchar_t AUMID[] = L"DriverTarpper.DriverMonitor";
constexpr size_t DUMP_DIRECTORY_CHARS = 512;
constexpr UINT WM_APP_STATUS = WM_APP + 1;
constexpr UINT WM_APP_WORKER_STARTED = WM_APP + 2;
constexpr UINT WM_APP_DRIVER_EVENT = WM_APP + 3;
constexpr UINT WM_APP_WORKER_FINISHED = WM_APP + 4;
constexpr UINT WM_APP_APPLY_RESULT = WM_APP + 5;
constexpr UINT WM_APP_FILTER_STATUS = WM_APP + 6;

enum ControlId : int {
    IDC_DIRECTORY_LABEL = 1001,
    IDC_DIRECTORY_EDIT,
    IDC_BROWSE,
    IDC_APPLY,
    IDC_START,
    IDC_STOP,
    IDC_STATUS,
    IDC_FILTER_STATUS,
    IDC_EVENT_LIST,
};

typedef struct _DRIVER_LOAD_INFO {
    WCHAR FilePath[512];
    WCHAR DumpDirectory[DUMP_DIRECTORY_CHARS];
} DRIVER_LOAD_INFO, *PDRIVER_LOAD_INFO;
static_assert(sizeof(DRIVER_LOAD_INFO) == 2048, "Keep the user-mode IOCTL layout in sync with kdt.sys.");

struct UiEvent {
    std::wstring time;
    std::wstring source;
    std::wstring target;
    bool showToast = true;
};

struct ApplyResult {
    DWORD requestId;
    bool succeeded;
    DWORD error;
    std::wstring errorText;
    std::wstring directory;
};

struct FilterStatusMessage {
    bool available;
    std::wstring text;
};

struct MinifilterSession {
    HANDLE port = INVALID_HANDLE_VALUE;
    SC_HANDLE service = nullptr;
    bool available = false;
    bool unloadOnStop = false;
    bool serviceOwned = false;
};

struct FilterReceiveBuffer {
    FILTER_MESSAGE_HEADER header;
    DT_FILTER_CAPTURE_RESULT result;
};

struct WorkerArgs {
    HWND window;
    HANDLE stopEvent;
    HANDLE configEvent;
    std::wstring directory;
};

struct AppState {
    HWND window = nullptr;
    HWND directoryLabel = nullptr;
    HWND directoryEdit = nullptr;
    HWND browseButton = nullptr;
    HWND applyButton = nullptr;
    HWND startButton = nullptr;
    HWND stopButton = nullptr;
    HWND statusLabel = nullptr;
    HWND filterStatusLabel = nullptr;
    HWND eventList = nullptr;
    HANDLE stopEvent = nullptr;
    HANDLE configEvent = nullptr;
    HANDLE workerThread = nullptr;
    unsigned workerThreadId = 0;
    bool workerActive = false;
    bool workerRunning = false;
    bool stopping = false;
    bool closeWhenStopped = false;
    bool applyPending = false;
    bool toastShortcutReady = true;
    bool filterAvailable = false;
    DWORD nextRequestId = 0;
    DWORD pendingRequestId = 0;
    CRITICAL_SECTION commandLock{};
    std::wstring pendingDirectory;
    std::wstring settingsFile;
    std::wstring currentDirectory;
};

static AppState g_app;
static SC_HANDLE g_hDriverService = nullptr;
static std::vector<ToastNotification> g_activeToasts;

static std::wstring FormatSystemError(DWORD error)
{
    wchar_t* message = nullptr;
    DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                  FORMAT_MESSAGE_IGNORE_INSERTS,
                                  nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                  reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    std::wstring result;
    if (length != 0 && message != nullptr) {
        result.assign(message, length);
        while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' '))
            result.pop_back();
    }
    if (message != nullptr)
        LocalFree(message);
    if (result.empty())
        result = L"未知错误";
    return result;
}

static std::wstring MakeSystemError(const wchar_t* action, DWORD error)
{
    return std::wstring(action) + L"（错误 " + std::to_wstring(error) + L"）：" + FormatSystemError(error);
}

static void SetUiStatus(const std::wstring& status)
{
    if (g_app.statusLabel != nullptr)
        SetWindowTextW(g_app.statusLabel, status.c_str());
}

static void SetFilterUiStatus(bool available, const std::wstring& status)
{
    g_app.filterAvailable = available;
    if (g_app.filterStatusLabel != nullptr) {
        SetWindowTextW(g_app.filterStatusLabel, status.c_str());
        InvalidateRect(g_app.filterStatusLabel, nullptr, TRUE);
    }
}

static void PostStatus(HWND window, std::wstring status)
{
    auto message = new (std::nothrow) std::wstring(std::move(status));
    if (message == nullptr || !PostMessageW(window, WM_APP_STATUS, 0, reinterpret_cast<LPARAM>(message)))
        delete message;
}

static void UpdateControls()
{
    const bool canEdit = !g_app.workerActive || g_app.workerRunning;
    const bool canApply = !g_app.workerActive || (g_app.workerRunning && !g_app.stopping && !g_app.applyPending);
    EnableWindow(g_app.directoryEdit, canEdit && !g_app.stopping);
    EnableWindow(g_app.browseButton, canEdit && !g_app.stopping);
    EnableWindow(g_app.applyButton, canApply && !g_app.stopping);
    EnableWindow(g_app.startButton, !g_app.workerActive);
    EnableWindow(g_app.stopButton, g_app.workerActive && !g_app.stopping);
}

static std::wstring GetSettingsFilePath()
{
    std::vector<wchar_t> localAppData(32768);
    DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData.data(),
                                          static_cast<DWORD>(localAppData.size()));
    if (length == 0 || length >= localAppData.size())
        return L"";

    return (std::filesystem::path(std::wstring(localAppData.data(), length)) /
            L"DriverTarpper" / L"settings.ini").wstring();
}

static std::wstring LoadInitialDirectory()
{
    g_app.settingsFile = GetSettingsFilePath();
    constexpr wchar_t defaultDirectory[] = L"C:\\DriverDump\\";
    if (g_app.settingsFile.empty())
        return defaultDirectory;

    wchar_t savedDirectory[DUMP_DIRECTORY_CHARS]{};
    DWORD length = GetPrivateProfileStringW(L"Settings", L"DumpDirectory", defaultDirectory,
                                            savedDirectory, static_cast<DWORD>(std::size(savedDirectory)),
                                            g_app.settingsFile.c_str());
    if (length == 0 || length >= std::size(savedDirectory))
        return defaultDirectory;
    return savedDirectory;
}

static bool SaveDirectorySetting(const std::wstring& directory, std::wstring& error)
{
    if (g_app.settingsFile.empty()) {
        error = L"无法定位 LOCALAPPDATA，目录设置仅对本次运行有效。";
        return false;
    }

    std::error_code filesystemError;
    std::filesystem::create_directories(std::filesystem::path(g_app.settingsFile).parent_path(), filesystemError);
    if (filesystemError) {
        error = L"无法创建设置目录（错误 " + std::to_wstring(filesystemError.value()) + L"）。";
        return false;
    }

    if (!WritePrivateProfileStringW(L"Settings", L"DumpDirectory", directory.c_str(), g_app.settingsFile.c_str())) {
        error = MakeSystemError(L"保存目录设置失败", GetLastError());
        return false;
    }
    return true;
}

static bool NormalizeAndPrepareDirectory(const std::wstring& input,
                                         std::wstring& directory,
                                         std::wstring& error)
{
    const size_t first = input.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) {
        error = L"请输入转储目录。";
        return false;
    }
    const size_t last = input.find_last_not_of(L" \t\r\n");
    std::wstring path = input.substr(first, last - first + 1);
    std::replace(path.begin(), path.end(), L'/', L'\\');

    if (path.size() < 3 ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || path[2] != L'\\') {
        error = L"请输入本机磁盘或挂载卷上的绝对路径（例如 C:\\DriverDump）。不支持 UNC 或相对路径。";
        return false;
    }

    std::vector<wchar_t> fullPath(32768);
    DWORD fullPathLength = GetFullPathNameW(path.c_str(), static_cast<DWORD>(fullPath.size()),
                                            fullPath.data(), nullptr);
    if (fullPathLength == 0 || fullPathLength >= fullPath.size()) {
        error = MakeSystemError(L"无法解析目录路径", GetLastError());
        return false;
    }
    path.assign(fullPath.data(), fullPathLength);

    if (path.size() < 3 || path[1] != L':' || path[2] != L'\\') {
        error = L"目录必须位于本机磁盘或挂载卷上。";
        return false;
    }

    const std::wstring driveRoot = path.substr(0, 3);
    const UINT driveType = GetDriveTypeW(driveRoot.c_str());
    if (driveType != DRIVE_FIXED && driveType != DRIVE_REMOVABLE && driveType != DRIVE_RAMDISK) {
        error = L"目录必须位于本机固定磁盘、可移动磁盘或其挂载卷上；网络驱动器不受支持。";
        return false;
    }

    if (path.back() != L'\\')
        path.push_back(L'\\');
    if (path.size() + 1 > DUMP_DIRECTORY_CHARS) {
        error = L"目录路径过长，规范化后最多支持 511 个字符。";
        return false;
    }

    std::error_code filesystemError;
    std::filesystem::create_directories(std::filesystem::path(path), filesystemError);
    if (filesystemError) {
        error = L"无法创建目录（错误 " + std::to_wstring(filesystemError.value()) + L"）。";
        return false;
    }

    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        error = MakeSystemError(L"无法访问目录", GetLastError());
        return false;
    }
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        error = L"指定路径不是一个目录。";
        return false;
    }

    // Verify that the selected directory accepts file creation before asking the driver to use it.
    bool writable = false;
    DWORD writeError = ERROR_ACCESS_DENIED;
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        std::wstring probePath = path + L".DriverTarpper-write-" + std::to_wstring(GetCurrentProcessId()) +
                                 L"-" + std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(attempt);
        HANDLE probe = CreateFileW(probePath.c_str(), GENERIC_WRITE | DELETE, 0, nullptr, CREATE_NEW,
                                   FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (probe != INVALID_HANDLE_VALUE) {
            CloseHandle(probe);
            writable = true;
            break;
        }
        writeError = GetLastError();
        if (writeError != ERROR_FILE_EXISTS)
            break;
    }
    if (!writable) {
        error = MakeSystemError(L"目录不可写", writeError);
        return false;
    }

    directory = std::move(path);
    return true;
}

static bool EnsureAumidShortcut()
{
    wchar_t startMenuPath[MAX_PATH]{};
    HRESULT hr = SHGetFolderPathW(nullptr, CSIDL_PROGRAMS, nullptr, SHGFP_TYPE_CURRENT, startMenuPath);
    if (FAILED(hr))
        return false;

    std::wstring shortcutPath = std::wstring(startMenuPath) + L"\\检测到驱动加载.lnk";
    DWORD attributes = GetFileAttributesW(shortcutPath.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY))
        return true;

    wchar_t executablePath[32768]{};
    DWORD executableLength = GetModuleFileNameW(nullptr, executablePath,
                                                 static_cast<DWORD>(std::size(executablePath)));
    if (executableLength == 0 || executableLength >= std::size(executablePath))
        return false;

    try {
        auto shellLink = winrt::create_instance<IShellLinkW>(CLSID_ShellLink, CLSCTX_INPROC_SERVER);
        if (!shellLink || FAILED(shellLink->SetPath(executablePath)) ||
            FAILED(shellLink->SetDescription(L"DriverTarpper -- Kernel driver load monitor")))
            return false;

        auto propertyStore = shellLink.as<IPropertyStore>();
        PROPVARIANT appId{};
        hr = InitPropVariantFromString(AUMID, &appId);
        if (FAILED(hr))
            return false;

        hr = propertyStore->SetValue(PKEY_AppUserModel_ID, appId);
        PropVariantClear(&appId);
        if (FAILED(hr) || FAILED(propertyStore->Commit()))
            return false;

        auto persistFile = shellLink.as<IPersistFile>();
        return SUCCEEDED(persistFile->Save(shortcutPath.c_str(), TRUE));
    }
    catch (...) {
        return false;
    }
}

static void ShowToast(const std::wstring& title, const std::wstring& body, const std::wstring& launchPath)
{
    try {
        auto xml = ToastNotificationManager::GetTemplateContent(ToastTemplateType::ToastText02);
        auto texts = xml.GetElementsByTagName(L"text");
        texts.Item(0).AppendChild(xml.CreateTextNode(title.c_str()));
        texts.Item(1).AppendChild(xml.CreateTextNode(body.c_str()));

        auto toastNode = xml.SelectSingleNode(L"/toast");
        toastNode.as<Windows::Data::Xml::Dom::XmlElement>().SetAttribute(L"launch", launchPath.c_str());

        ToastNotification toast(xml);
        toast.Activated([path = launchPath](ToastNotification const&,
                                            Windows::Foundation::IInspectable const&) {
            if (path.empty())
                return;
            std::wstring arguments = L"/select,\"" + path + L"\"";
            ShellExecuteW(nullptr, L"open", L"explorer.exe", arguments.c_str(), nullptr, SW_SHOWNORMAL);
        });

        g_activeToasts.push_back(std::move(toast));
        ToastNotificationManager::CreateToastNotifier(AUMID).Show(g_activeToasts.back());
    }
    catch (const winrt::hresult_error&) {
        // The in-window event log remains available if Windows notifications are unavailable.
    }
}

static std::wstring GetPathBesideExecutable(const wchar_t* fileName)
{
    std::vector<wchar_t> executablePath(MAX_PATH);
    while (true) {
        DWORD length = GetModuleFileNameW(nullptr, executablePath.data(), static_cast<DWORD>(executablePath.size()));
        if (length == 0)
            return L"";
        if (length < executablePath.size()) {
            std::filesystem::path executable(std::wstring(executablePath.data(), length));
            return (executable.parent_path() / fileName).wstring();
        }
        constexpr size_t maxPathLength = 32768;
        if (executablePath.size() >= maxPathLength)
            return L"";
        executablePath.resize(std::min(maxPathLength, executablePath.size() * 2));
    }
}

static std::wstring GetDriverPathBesideExecutable()
{
    return GetPathBesideExecutable(L"kdt.sys");
}

static bool StopDriverService(std::wstring& error)
{
    if (g_hDriverService == nullptr)
        return true;

    SERVICE_STATUS serviceStatus{};
    if (!ControlService(g_hDriverService, SERVICE_CONTROL_STOP, &serviceStatus)) {
        DWORD stopError = GetLastError();
        if (stopError != ERROR_SERVICE_NOT_ACTIVE && stopError != ERROR_SERVICE_MARKED_FOR_DELETE) {
            error = MakeSystemError(L"停止 kdt 驱动失败", stopError);
            CloseServiceHandle(g_hDriverService);
            g_hDriverService = nullptr;
            return false;
        }
    }

    bool deleted = DeleteService(g_hDriverService) != FALSE;
    DWORD deleteError = deleted ? ERROR_SUCCESS : GetLastError();
    if (!deleted && deleteError != ERROR_SERVICE_MARKED_FOR_DELETE) {
        error = MakeSystemError(L"删除 kdt 服务项失败", deleteError);
        CloseServiceHandle(g_hDriverService);
        g_hDriverService = nullptr;
        return false;
    }

    CloseServiceHandle(g_hDriverService);
    g_hDriverService = nullptr;
    return true;
}

static bool IsOwnDriverService(SC_HANDLE service);

static bool CleanupStaleDriverService(std::wstring& error)
{
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (manager == nullptr) {
        error = MakeSystemError(L"打开服务管理器失败", GetLastError());
        return false;
    }

    SC_HANDLE service = OpenServiceW(manager, L"kdt",
                                     SERVICE_QUERY_CONFIG | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        DWORD openError = GetLastError();
        CloseServiceHandle(manager);
        if (openError == ERROR_SERVICE_DOES_NOT_EXIST)
            return true;
        error = MakeSystemError(L"检查旧 kdt 服务失败", openError);
        return false;
    }

    if (!IsOwnDriverService(service)) {
        error = L"检测到服务名为 kdt 的其他驱动服务，映像路径与本程序旁的 kdt.sys 不同；为避免影响其他程序，未停止或删除该服务。";
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return false;
    }

    SERVICE_STATUS status{};
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        DWORD stopError = GetLastError();
        if (stopError != ERROR_SERVICE_NOT_ACTIVE && stopError != ERROR_SERVICE_MARKED_FOR_DELETE) {
            error = MakeSystemError(L"停止旧 kdt 驱动失败", stopError);
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return false;
        }
    }

    if (!DeleteService(service)) {
        DWORD deleteError = GetLastError();
        if (deleteError != ERROR_SERVICE_MARKED_FOR_DELETE) {
            error = MakeSystemError(L"删除旧 kdt 服务项失败", deleteError);
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return false;
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return true;
}

static bool InstallAndStartDriver(const std::wstring& binaryPath, std::wstring& error)
{
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (manager == nullptr) {
        error = MakeSystemError(L"打开服务管理器失败", GetLastError());
        return false;
    }

    SC_HANDLE service = nullptr;
    for (int attempt = 0; attempt < 3; ++attempt) {
        service = CreateServiceW(manager, L"kdt", L"kdt Service", SERVICE_ALL_ACCESS,
                                 SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                 binaryPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (service != nullptr)
            break;

        DWORD createError = GetLastError();
        if (createError != ERROR_SERVICE_EXISTS) {
            error = MakeSystemError(L"创建 kdt 驱动服务失败", createError);
            CloseServiceHandle(manager);
            return false;
        }

        SC_HANDLE oldService = OpenServiceW(manager, L"kdt",
                                            SERVICE_QUERY_CONFIG | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
        if (oldService == nullptr) {
            error = MakeSystemError(L"打开残留 kdt 服务失败", GetLastError());
            CloseServiceHandle(manager);
            return false;
        }

        if (!IsOwnDriverService(oldService)) {
            error = L"服务名 kdt 已被其他驱动服务占用；为避免影响其他程序，未停止或删除该服务。";
            CloseServiceHandle(oldService);
            CloseServiceHandle(manager);
            return false;
        }

        SERVICE_STATUS status{};
        ControlService(oldService, SERVICE_CONTROL_STOP, &status);
        DeleteService(oldService);
        CloseServiceHandle(oldService);
        Sleep(300);
    }
    CloseServiceHandle(manager);

    if (service == nullptr) {
        error = L"无法清理残留的 kdt 服务项。";
        return false;
    }

    g_hDriverService = service;
    if (!StartServiceW(service, 0, nullptr)) {
        DWORD startError = GetLastError();
        if (startError != ERROR_SERVICE_ALREADY_RUNNING) {
            error = MakeSystemError(L"启动 kdt 驱动失败", startError);
            std::wstring cleanupError;
            StopDriverService(cleanupError);
            if (!cleanupError.empty())
                error += L"\r\n" + cleanupError;
            return false;
        }
    }
    return true;
}

static std::wstring NtPathToDosPath(const std::wstring& ntPath)
{
    if (ntPath.empty())
        return L"";

    const std::wstring devicePrefix = L"\\Device\\";
    size_t searchStart = ntPath.find(devicePrefix) == 0 ? devicePrefix.length() : 2;
    size_t deviceEnd = ntPath.find(L'\\', searchStart);
    if (deviceEnd == std::wstring::npos)
        deviceEnd = ntPath.length();
    const std::wstring deviceName = ntPath.substr(0, deviceEnd);
    const std::wstring relativePath = deviceEnd < ntPath.length() ? ntPath.substr(deviceEnd) : L"";

    std::vector<wchar_t> devices(4096);
    DWORD deviceLength = QueryDosDeviceW(nullptr, devices.data(), static_cast<DWORD>(devices.size()));
    while (deviceLength == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER && devices.size() < 32768) {
        devices.resize(std::min<size_t>(32768, devices.size() * 2));
        deviceLength = QueryDosDeviceW(nullptr, devices.data(), static_cast<DWORD>(devices.size()));
    }
    if (deviceLength == 0)
        return L"";

    for (const wchar_t* current = devices.data(); *current != L'\0'; current += wcslen(current) + 1) {
        if (wcslen(current) != 2 || current[1] != L':')
            continue;
        std::vector<wchar_t> ntDevicePath(32768);
        DWORD result = QueryDosDeviceW(current, ntDevicePath.data(), static_cast<DWORD>(ntDevicePath.size()));
        if (result > 0) {
            const std::wstring devicePath(ntDevicePath.data());
            if (ntPath.compare(0, devicePath.size(), devicePath) == 0 &&
                (ntPath.size() == devicePath.size() || ntPath[devicePath.size()] == L'\\'))
                return std::wstring(current) + relativePath;
        }
    }
    return L"";
}

static std::wstring FileNameFromPath(const std::wstring& path)
{
    const size_t slash = path.find_last_of(L'\\');
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

static bool SetDriverDirectory(HANDLE device, const std::wstring& directory, DWORD& error)
{
    DWORD bytesReturned = 0;
    const DWORD inputBytes = static_cast<DWORD>((directory.size() + 1) * sizeof(WCHAR));
    if (!DeviceIoControl(device, IOCTL_SET_DUMP_DIRECTORY,
                         const_cast<wchar_t*>(directory.c_str()), inputBytes,
                         nullptr, 0, &bytesReturned, nullptr)) {
        error = GetLastError();
        return false;
    }
    return true;
}

static std::wstring FormatFilterError(const wchar_t* action, HRESULT result)
{
    DWORD code = HRESULT_FACILITY(result) == FACILITY_WIN32 ? HRESULT_CODE(result) : ERROR_GEN_FAILURE;
    return std::wstring(action) + L"（HRESULT 0x" + [] (HRESULT value) {
        wchar_t text[16]{};
        swprintf_s(text, L"%08X", static_cast<unsigned long>(value));
        return std::wstring(text);
    }(result) + L"）：" + FormatSystemError(code);
}

class ScopedLoadDriverPrivilege {
public:
    ScopedLoadDriverPrivilege() = default;
    ScopedLoadDriverPrivilege(const ScopedLoadDriverPrivilege&) = delete;
    ScopedLoadDriverPrivilege& operator=(const ScopedLoadDriverPrivilege&) = delete;

    ~ScopedLoadDriverPrivilege()
    {
        DWORD ignored = ERROR_SUCCESS;
        Restore(ignored);
    }

    bool Enable(DWORD& errorCode)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_)) {
            errorCode = GetLastError();
            return false;
        }

        LUID privilege{};
        if (!LookupPrivilegeValueW(nullptr, L"SeLoadDriverPrivilege", &privilege)) {
            errorCode = GetLastError();
            CloseHandle(token_);
            token_ = nullptr;
            return false;
        }

        TOKEN_PRIVILEGES requested{};
        requested.PrivilegeCount = 1;
        requested.Privileges[0].Luid = privilege;
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        DWORD returnedBytes = 0;
        SetLastError(ERROR_SUCCESS);
        if (!AdjustTokenPrivileges(token_, FALSE, &requested, sizeof(previous_),
                                   &previous_, &returnedBytes)) {
            errorCode = GetLastError();
            CloseHandle(token_);
            token_ = nullptr;
            return false;
        }

        const DWORD adjustError = GetLastError();
        if (adjustError != ERROR_SUCCESS) {
            errorCode = adjustError;
            CloseHandle(token_);
            token_ = nullptr;
            return false;
        }

        restoreRequired_ = previous_.PrivilegeCount != 0;
        errorCode = ERROR_SUCCESS;
        return true;
    }

    bool Restore(DWORD& errorCode)
    {
        if (token_ == nullptr) {
            errorCode = ERROR_SUCCESS;
            return true;
        }

        if (restoreRequired_) {
            SetLastError(ERROR_SUCCESS);
            if (!AdjustTokenPrivileges(token_, FALSE, &previous_, 0, nullptr, nullptr)) {
                errorCode = GetLastError();
                return false;
            }
            const DWORD restoreError = GetLastError();
            if (restoreError != ERROR_SUCCESS) {
                errorCode = restoreError;
                return false;
            }
        }

        restoreRequired_ = false;
        CloseHandle(token_);
        token_ = nullptr;
        errorCode = ERROR_SUCCESS;
        return true;
    }

private:
    HANDLE token_ = nullptr;
    TOKEN_PRIVILEGES previous_{};
    bool restoreRequired_ = false;
};

static HRESULT LoadMinifilterWithPrivilege(DWORD& privilegeError, DWORD& restoreError)
{
    ScopedLoadDriverPrivilege privilege;
    if (!privilege.Enable(privilegeError))
        return HRESULT_FROM_WIN32(privilegeError);

    const HRESULT result = FilterLoad(DT_FILTER_SERVICE_NAME);
    privilege.Restore(restoreError);
    return result;
}

static HRESULT UnloadMinifilterWithPrivilege(DWORD& privilegeError, DWORD& restoreError)
{
    ScopedLoadDriverPrivilege privilege;
    if (!privilege.Enable(privilegeError))
        return HRESULT_FROM_WIN32(privilegeError);

    const HRESULT result = FilterUnload(DT_FILTER_SERVICE_NAME);
    privilege.Restore(restoreError);
    return result;
}

static bool CheckMinifilterAltitude(std::wstring& error)
{
    std::vector<BYTE> buffer(8192);
    HANDLE enumeration = INVALID_HANDLE_VALUE;
    DWORD bytesReturned = 0;
    HRESULT result = FilterFindFirst(FilterAggregateStandardInformation, buffer.data(),
        static_cast<DWORD>(buffer.size()), &bytesReturned, &enumeration);
    if (FAILED(result)) {
        if (HRESULT_FACILITY(result) == FACILITY_WIN32 && HRESULT_CODE(result) == ERROR_NO_MORE_ITEMS)
            return true;
        error = FormatFilterError(L"检查已加载的文件系统过滤器失败", result);
        return false;
    }

    bool collision = false;
    for (;;) {
        ULONG offset = 0;
        while (offset + sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION) <= bytesReturned) {
            auto info = reinterpret_cast<PFILTER_AGGREGATE_STANDARD_INFORMATION>(buffer.data() + offset);
            USHORT nameLength = 0, nameOffset = 0, altitudeLength = 0, altitudeOffset = 0;
            if ((info->Flags & FLTFL_ASI_IS_MINIFILTER) != 0) {
                nameLength = info->Type.MiniFilter.FilterNameLength;
                nameOffset = info->Type.MiniFilter.FilterNameBufferOffset;
                altitudeLength = info->Type.MiniFilter.FilterAltitudeLength;
                altitudeOffset = info->Type.MiniFilter.FilterAltitudeBufferOffset;
            } else if ((info->Flags & FLTFL_ASI_IS_LEGACYFILTER) != 0) {
                nameLength = info->Type.LegacyFilter.FilterNameLength;
                nameOffset = info->Type.LegacyFilter.FilterNameBufferOffset;
                altitudeLength = info->Type.LegacyFilter.FilterAltitudeLength;
                altitudeOffset = info->Type.LegacyFilter.FilterAltitudeBufferOffset;
            }
            const size_t entrySize = info->NextEntryOffset != 0 ? info->NextEntryOffset : bytesReturned - offset;
            if (nameOffset + nameLength <= entrySize && altitudeOffset + altitudeLength <= entrySize &&
                nameOffset >= sizeof(*info) && altitudeOffset >= sizeof(*info)) {
                auto name = reinterpret_cast<const wchar_t*>(buffer.data() + offset + nameOffset);
                auto altitude = reinterpret_cast<const wchar_t*>(buffer.data() + offset + altitudeOffset);
                std::wstring_view filterName(name, nameLength / sizeof(wchar_t));
                std::wstring_view filterAltitude(altitude, altitudeLength / sizeof(wchar_t));
                const std::wstring filterNameText(filterName);
                const bool isOurFilter = _wcsicmp(filterNameText.c_str(), DT_FILTER_SERVICE_NAME) == 0 ||
                                         _wcsicmp(filterNameText.c_str(), L"sdfilter") == 0;
                if (_wcsicmp(std::wstring(filterAltitude).c_str(), DT_FILTER_ALTITUDE) == 0 && !isOurFilter) {
                    error = L"实验 altitude " + std::wstring(DT_FILTER_ALTITUDE) + L" 已由过滤器 " +
                            std::wstring(filterName) + L" 使用；为避免加载顺序冲突，自删除捕获已禁用。";
                    collision = true;
                    break;
                }
            }
            if (info->NextEntryOffset == 0)
                break;
            offset += info->NextEntryOffset;
        }
        if (collision)
            break;

        result = FilterFindNext(enumeration, FilterAggregateStandardInformation,
            buffer.data(), static_cast<DWORD>(buffer.size()), &bytesReturned);
        if (FAILED(result)) {
            if (HRESULT_FACILITY(result) == FACILITY_WIN32 && HRESULT_CODE(result) == ERROR_NO_MORE_ITEMS)
                break;
            error = FormatFilterError(L"继续检查文件系统过滤器失败", result);
            collision = true;
            break;
        }
    }
    FilterFindClose(enumeration);
    return !collision;
}

static bool SetRegistryString(HKEY key, const wchar_t* name, const std::wstring& value,
                              std::wstring& error)
{
    const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    const LSTATUS status = RegSetValueExW(key, name, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(value.c_str()), bytes);
    if (status == ERROR_SUCCESS)
        return true;
    error = MakeSystemError(L"写入 minifilter 实例注册表失败", static_cast<DWORD>(status));
    return false;
}

static bool SetRegistryDword(HKEY key, const wchar_t* name, DWORD value, std::wstring& error)
{
    const LSTATUS status = RegSetValueExW(key, name, 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&value), sizeof(value));
    if (status == ERROR_SUCCESS)
        return true;
    error = MakeSystemError(L"写入 minifilter 实例标志失败", static_cast<DWORD>(status));
    return false;
}

static std::wstring StripServicePathQuotes(std::wstring path)
{
    if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"')
        path = path.substr(1, path.size() - 2);
    return path;
}

static bool RegisterMinifilterService(const std::wstring& driverPath,
                                     MinifilterSession& session, std::wstring& error)
{
    constexpr wchar_t displayName[] = L"DriverTarpper self-delete evidence filter";
    constexpr wchar_t loadOrderGroup[] = L"FSFilter Activity Monitor";
    constexpr wchar_t instanceName[] = L"DriverTarpper Instance";
    constexpr wchar_t serviceRegistryPath[] = L"SYSTEM\\CurrentControlSet\\Services\\dtself\\Parameters";
    static constexpr wchar_t dependencies[] = L"FltMgr\0";
    const std::wstring serviceImagePath = driverPath.find_first_of(L" \t") == std::wstring::npos
        ? driverPath : L"\"" + driverPath + L"\"";

    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (manager == nullptr) {
        error = MakeSystemError(L"打开服务管理器以注册 minifilter 失败", GetLastError());
        return false;
    }

    SC_HANDLE service = CreateServiceW(manager, DT_FILTER_SERVICE_NAME, displayName,
        SERVICE_ALL_ACCESS, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, serviceImagePath.c_str(), loadOrderGroup, nullptr,
        dependencies, nullptr, nullptr);
    if (service == nullptr && GetLastError() == ERROR_SERVICE_EXISTS) {
        service = OpenServiceW(manager, DT_FILTER_SERVICE_NAME, SERVICE_ALL_ACCESS);
        if (service == nullptr) {
            error = MakeSystemError(L"打开现有 minifilter 服务失败", GetLastError());
            CloseServiceHandle(manager);
            return false;
        }

        DWORD requiredBytes = 0;
        QueryServiceConfigW(service, nullptr, 0, &requiredBytes);
        if (requiredBytes == 0) {
            error = MakeSystemError(L"查询现有 minifilter 服务配置失败", GetLastError());
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return false;
        }
        std::vector<BYTE> configBuffer(requiredBytes);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
        if (!QueryServiceConfigW(service, config, requiredBytes, &requiredBytes)) {
            error = MakeSystemError(L"读取现有 minifilter 服务配置失败", GetLastError());
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return false;
        }

        std::wstring oldPath = StripServicePathQuotes(config->lpBinaryPathName != nullptr
            ? config->lpBinaryPathName : L"");
        const size_t separator = oldPath.find_last_of(L"\\/");
        const std::wstring oldFileName = separator == std::wstring::npos
            ? oldPath : oldPath.substr(separator + 1);
        const bool belongsToTool = _wcsicmp(oldFileName.c_str(), L"sdfilter.sys") == 0 ||
            (config->lpDisplayName != nullptr &&
             _wcsnicmp(config->lpDisplayName, displayName, std::size(displayName) - 1) == 0);
        if (!belongsToTool) {
            error = L"服务名 dtself 已被其他驱动占用；为避免改动其他服务，minifilter 未启动。";
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return false;
        }

        if (!ChangeServiceConfigW(service, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL, serviceImagePath.c_str(), loadOrderGroup, nullptr,
                dependencies, nullptr, nullptr, displayName)) {
            error = MakeSystemError(L"更新便携式 minifilter 服务配置失败", GetLastError());
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return false;
        }
    } else if (service == nullptr) {
        error = MakeSystemError(L"创建 minifilter 服务失败", GetLastError());
        CloseServiceHandle(manager);
        return false;
    }

    session.service = service;
    session.serviceOwned = true;
    CloseServiceHandle(manager);

    auto configureInstances = [&](HKEY parent, const wchar_t* subkey) {
        HKEY instances = nullptr;
        LSTATUS status = RegCreateKeyExW(parent, subkey, 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
            nullptr, &instances, nullptr);
        if (status != ERROR_SUCCESS) {
            error = MakeSystemError(L"创建 minifilter 实例注册表失败", static_cast<DWORD>(status));
            return false;
        }

        bool configured = SetRegistryString(instances, L"DefaultInstance", instanceName, error);
        HKEY instance = nullptr;
        if (configured) {
            status = RegCreateKeyExW(instances, instanceName, 0, nullptr,
                REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                nullptr, &instance, nullptr);
            if (status != ERROR_SUCCESS) {
                error = MakeSystemError(L"创建 minifilter 默认实例失败", static_cast<DWORD>(status));
                configured = false;
            }
        }
        if (configured) {
            configured = SetRegistryString(instance, L"Altitude", DT_FILTER_ALTITUDE, error) &&
                         SetRegistryDword(instance, L"Flags", 0, error);
        }
        if (instance != nullptr)
            RegCloseKey(instance);
        RegCloseKey(instances);
        return configured;
    };

    HKEY parameters = nullptr;
    LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, serviceRegistryPath, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY,
        nullptr, &parameters, nullptr);
    if (status != ERROR_SUCCESS) {
        error = MakeSystemError(L"创建 minifilter 参数注册表失败", static_cast<DWORD>(status));
        return false;
    }
    bool configured = configureInstances(parameters, L"Instances");
    RegCloseKey(parameters);
    if (!configured)
        return false;

    // Windows versions before 11 24H2 read instance definitions from the
    // service root; newer Windows reads them from Parameters.
    std::wstring legacyRegistryPath = serviceRegistryPath;
    legacyRegistryPath.resize(legacyRegistryPath.rfind(L"\\Parameters"));
    HKEY serviceKey = nullptr;
    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, legacyRegistryPath.c_str(), 0,
        KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY, &serviceKey);
    if (status != ERROR_SUCCESS) {
        error = MakeSystemError(L"打开 minifilter 服务注册表失败", static_cast<DWORD>(status));
        return false;
    }
    configured = configureInstances(serviceKey, L"Instances");
    RegCloseKey(serviceKey);
    return configured;
}

static bool SendFilterCommand(HANDLE port, ULONG command, const std::wstring& directory,
                              DT_FILTER_REPLY* reply, std::wstring& error)
{
    DT_FILTER_COMMAND message{};
    message.Version = DT_FILTER_PROTOCOL_VERSION;
    message.Command = command;
    if (command == DT_FILTER_COMMAND_SET_DIRECTORY) {
        if (directory.empty() || directory.size() + 1 > std::size(message.Directory)) {
            error = L"转储目录超出 minifilter 支持的长度。";
            return false;
        }
        wcscpy_s(message.Directory, directory.c_str());
    }
    DT_FILTER_REPLY localReply{};
    DWORD returned = 0;
    HRESULT result = FilterSendMessage(port, &message, sizeof(message), &localReply,
                                       sizeof(localReply), &returned);
    if (FAILED(result)) {
        error = FormatFilterError(L"与 minifilter 通信失败", result);
        return false;
    }
    if (returned < sizeof(localReply) || localReply.Version != DT_FILTER_PROTOCOL_VERSION) {
        error = L"minifilter 返回了不兼容的通信响应。";
        return false;
    }
    if (localReply.Status < 0) {
        wchar_t status[16]{};
        swprintf_s(status, L"%08X", static_cast<unsigned long>(localReply.Status));
        error = std::wstring(L"minifilter 拒绝了命令，NTSTATUS 0x") + status;
        return false;
    }
    if (reply != nullptr)
        *reply = localReply;
    return true;
}

static void CloseMinifilterSession(MinifilterSession& session, std::wstring& error)
{
    if (session.port != INVALID_HANDLE_VALUE) {
        CloseHandle(session.port);
        session.port = INVALID_HANDLE_VALUE;
    }
    session.available = false;
    bool canRemoveService = !session.unloadOnStop;
    if (session.unloadOnStop) {
        DWORD privilegeError = ERROR_SUCCESS;
        DWORD restoreError = ERROR_SUCCESS;
        HRESULT result = UnloadMinifilterWithPrivilege(privilegeError, restoreError);
        if (restoreError != ERROR_SUCCESS) {
            if (!error.empty()) error += L"\r\n";
            error += MakeSystemError(L"恢复 SeLoadDriverPrivilege 状态失败", restoreError);
        }
        if (FAILED(result) && result != HRESULT_FROM_WIN32(ERROR_SERVICE_NOT_ACTIVE) &&
            result != ERROR_FLT_FILTER_NOT_FOUND) {
            if (!error.empty()) error += L"\r\n";
            error += FormatFilterError(privilegeError == ERROR_SUCCESS
                ? L"卸载 minifilter 失败" : L"启用 SeLoadDriverPrivilege 失败，无法卸载 minifilter", result);
        } else {
            session.unloadOnStop = false;
            canRemoveService = true;
        }
    }

    if (session.serviceOwned && canRemoveService) {
        SC_HANDLE service = session.service;
        if (service == nullptr) {
            SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            DWORD openError = manager == nullptr ? GetLastError() : ERROR_SUCCESS;
            if (manager != nullptr) {
                service = OpenServiceW(manager, DT_FILTER_SERVICE_NAME, DELETE);
                if (service == nullptr)
                    openError = GetLastError();
                CloseServiceHandle(manager);
            }
            if (service == nullptr && openError == ERROR_SERVICE_DOES_NOT_EXIST)
                session.serviceOwned = false;
            else if (service == nullptr) {
                if (!error.empty()) error += L"\r\n";
                error += MakeSystemError(L"重新打开 minifilter 服务以清理失败", openError);
            }
        }
        if (service != nullptr) {
            if (!DeleteService(service)) {
                const DWORD deleteError = GetLastError();
                if (deleteError != ERROR_SERVICE_MARKED_FOR_DELETE) {
                    if (!error.empty()) error += L"\r\n";
                    error += MakeSystemError(L"清理临时 minifilter 服务失败", deleteError);
                } else {
                    session.serviceOwned = false;
                }
            } else {
                session.serviceOwned = false;
            }
            if (service == session.service)
                session.service = nullptr;
            CloseServiceHandle(service);
        }
    }

    if (session.service != nullptr) {
        CloseServiceHandle(session.service);
        session.service = nullptr;
    }
}

static bool StartMinifilterSession(const std::wstring& directory, HANDLE stopEvent,
                                   MinifilterSession& session, std::wstring& error)
{
    if (!CheckMinifilterAltitude(error))
        return false;

    const std::wstring driverPath = GetPathBesideExecutable(L"sdfilter.sys");
    DWORD attributes = driverPath.empty() ? INVALID_FILE_ATTRIBUTES : GetFileAttributesW(driverPath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        error = L"请将 sdfilter.sys 放在 dt.exe 同一目录。";
        if (driverPath.empty())
            error += L"无法确定 dt.exe 所在目录。";
        else
            error += L"\r\n预期路径：" + driverPath;
        return false;
    }

    if (!RegisterMinifilterService(driverPath, session, error)) {
        std::wstring cleanupError;
        CloseMinifilterSession(session, cleanupError);
        if (!cleanupError.empty()) error += L"\r\n" + cleanupError;
        return false;
    }
    if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0) {
        error = L"启动已取消。";
        CloseMinifilterSession(session, error);
        return false;
    }

    DWORD privilegeError = ERROR_SUCCESS;
    DWORD restoreError = ERROR_SUCCESS;
    HRESULT loadResult = LoadMinifilterWithPrivilege(privilegeError, restoreError);
    const bool alreadyRunning = HRESULT_FACILITY(loadResult) == FACILITY_WIN32 &&
        (HRESULT_CODE(loadResult) == ERROR_SERVICE_ALREADY_RUNNING ||
         HRESULT_CODE(loadResult) == ERROR_ALREADY_EXISTS);
    if (SUCCEEDED(loadResult) || alreadyRunning) {
        session.unloadOnStop = true;
        if (restoreError != ERROR_SUCCESS) {
            error = MakeSystemError(L"恢复 SeLoadDriverPrivilege 状态失败", restoreError);
            CloseMinifilterSession(session, error);
            return false;
        }
    } else {
        error = FormatFilterError(privilegeError == ERROR_SUCCESS
            ? L"加载 minifilter 失败" : L"启用 SeLoadDriverPrivilege 失败，无法加载 minifilter", loadResult);
        if (restoreError != ERROR_SUCCESS)
            error += L"\r\n" + MakeSystemError(L"恢复 SeLoadDriverPrivilege 状态失败", restoreError);
        CloseMinifilterSession(session, error);
        return false;
    }

    HRESULT connectResult = E_FAIL;
    for (int attempt = 0; attempt < 20; ++attempt) {
        connectResult = FilterConnectCommunicationPort(DT_FILTER_PORT_NAME, 0,
            nullptr, 0, nullptr, &session.port);
        if (SUCCEEDED(connectResult))
            break;
        if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
            break;
        if (HRESULT_FACILITY(connectResult) != FACILITY_WIN32 ||
            (HRESULT_CODE(connectResult) != ERROR_FILE_NOT_FOUND &&
             HRESULT_CODE(connectResult) != ERROR_PIPE_NOT_CONNECTED))
            break;
        WaitForSingleObject(stopEvent, 250);
    }
    if (FAILED(connectResult)) {
        error = FormatFilterError(L"连接 minifilter 通信端口失败", connectResult);
        CloseMinifilterSession(session, error);
        return false;
    }
    // dtself is this tool's dedicated service. Clean up an instance left by
    // an earlier crash as well as one loaded by this process.
    session.unloadOnStop = true;
    DT_FILTER_REPLY state{};
    bool attached = false;
    for (int attempt = 0; attempt < 20; ++attempt) {
        if (!SendFilterCommand(session.port, DT_FILTER_COMMAND_QUERY_STATE, L"", &state, error)) {
            CloseMinifilterSession(session, error);
            return false;
        }
        if (state.AttachedInstances != 0) {
            attached = true;
            break;
        }
        if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
            break;
        WaitForSingleObject(stopEvent, 250);
    }
    if (!attached) {
        error = L"minifilter 已启动，但未能附加到本机文件系统卷。";
        CloseMinifilterSession(session, error);
        return false;
    }

    if (!SendFilterCommand(session.port, DT_FILTER_COMMAND_SET_DIRECTORY, directory, nullptr, error)) {
        CloseMinifilterSession(session, error);
        return false;
    }
    session.available = true;
    return true;
}

static bool SetMinifilterDirectory(MinifilterSession& session, const std::wstring& directory,
                                   std::wstring& error)
{
    if (!session.available)
        return true;
    return SendFilterCommand(session.port, DT_FILTER_COMMAND_SET_DIRECTORY, directory, nullptr, error);
}

static bool BeginFilterReceive(MinifilterSession& session, FilterReceiveBuffer& buffer, OVERLAPPED& overlapped)
{
    ResetEvent(overlapped.hEvent);
    HRESULT result = FilterGetMessage(session.port, &buffer.header, sizeof(buffer), &overlapped);
    if (result == HRESULT_FROM_WIN32(ERROR_IO_PENDING))
        return true;
    if (SUCCEEDED(result)) {
        SetEvent(overlapped.hEvent);
        return true;
    }
    return false;
}

enum class ExistingDriverState {
    NotLoaded,
    Attached,
    Failed,
};

static bool IsOwnDriverService(SC_HANDLE service)
{
    const std::wstring expectedPath = GetDriverPathBesideExecutable();
    if (expectedPath.empty())
        return false;

    DWORD requiredBytes = 0;
    QueryServiceConfigW(service, nullptr, 0, &requiredBytes);
    if (requiredBytes == 0)
        return false;

    std::vector<BYTE> configBuffer(requiredBytes);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
    if (!QueryServiceConfigW(service, config, requiredBytes, &requiredBytes) ||
        config->lpBinaryPathName == nullptr)
        return false;

    return _wcsicmp(config->lpBinaryPathName, expectedPath.c_str()) == 0;
}

static ExistingDriverState ProbeExistingDriver(HANDLE& device, std::wstring& error)
{
    HANDLE deviceProbe = CreateFileW(L"\\\\.\\kdt", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD deviceError = deviceProbe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;

    // An openable device link is sufficient to reuse the driver. Only claim its
    // service handle when it is the service this application installs; external
    // services own their driver's lifetime and must not be stopped on exit.
    if (deviceProbe != INVALID_HANDLE_VALUE) {
        device = deviceProbe;

        SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (manager != nullptr) {
            SC_HANDLE service = OpenServiceW(manager, L"kdt",
                                              SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS |
                                                  SERVICE_STOP | DELETE);
            if (service != nullptr) {
                SERVICE_STATUS status{};
                if (QueryServiceStatus(service, &status) && status.dwCurrentState == SERVICE_RUNNING &&
                    IsOwnDriverService(service)) {
                    g_hDriverService = service;
                    service = nullptr;
                }
                if (service != nullptr)
                    CloseServiceHandle(service);
            }
            CloseServiceHandle(manager);
        }
        return ExistingDriverState::Attached;
    }

    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) {
        error = MakeSystemError(L"检查 kdt 服务状态失败", GetLastError());
        return ExistingDriverState::Failed;
    }

    SC_HANDLE service = OpenServiceW(manager, L"kdt", SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);
    if (service == nullptr) {
        const DWORD serviceError = GetLastError();
        CloseServiceHandle(manager);
        if (serviceError == ERROR_SERVICE_DOES_NOT_EXIST &&
            (deviceError == ERROR_FILE_NOT_FOUND || deviceError == ERROR_PATH_NOT_FOUND))
            return ExistingDriverState::NotLoaded;
        if (serviceError == ERROR_SERVICE_DOES_NOT_EXIST) {
            error = MakeSystemError(L"kdt 服务项不存在，但无法确认驱动设备状态", deviceError);
            return ExistingDriverState::Failed;
        }
        error = MakeSystemError(L"打开 kdt 服务状态失败", serviceError);
        return ExistingDriverState::Failed;
    }

    SERVICE_STATUS status{};
    if (!QueryServiceStatus(service, &status)) {
        const DWORD statusError = GetLastError();
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        error = MakeSystemError(L"读取 kdt 服务状态失败", statusError);
        return ExistingDriverState::Failed;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (status.dwCurrentState == SERVICE_RUNNING) {
        error = MakeSystemError(L"kdt 服务已运行，但无法打开驱动设备", deviceError);
        return ExistingDriverState::Failed;
    }
    return ExistingDriverState::NotLoaded;
}

static void PostDriverEvent(HWND window, const DRIVER_LOAD_INFO& info)
{
    const size_t sourceLength = wcsnlen_s(info.FilePath, std::size(info.FilePath));
    const size_t directoryLength = wcsnlen_s(info.DumpDirectory, std::size(info.DumpDirectory));
    std::wstring ntPath(info.FilePath, sourceLength);
    std::wstring source = NtPathToDosPath(ntPath);
    if (source.empty())
        source = ntPath;

    std::wstring directory(info.DumpDirectory, directoryLength);
    std::wstring target = directory + FileNameFromPath(source);

    SYSTEMTIME localTime{};
    GetLocalTime(&localTime);
    wchar_t timeText[32]{};
    swprintf_s(timeText, L"%04u-%02u-%02u %02u:%02u:%02u",
               localTime.wYear, localTime.wMonth, localTime.wDay,
               localTime.wHour, localTime.wMinute, localTime.wSecond);

    auto event = new (std::nothrow) UiEvent{timeText, std::move(source), std::move(target)};
    if (event == nullptr || !PostMessageW(window, WM_APP_DRIVER_EVENT, 0, reinterpret_cast<LPARAM>(event)))
        delete event;
}

static void PostApplyResult(HWND window, DWORD requestId, bool succeeded,
                            DWORD error, const std::wstring& directory,
                            const std::wstring& errorText = L"")
{
    auto result = new (std::nothrow) ApplyResult{requestId, succeeded, error, errorText, directory};
    if (result == nullptr || !PostMessageW(window, WM_APP_APPLY_RESULT, 0, reinterpret_cast<LPARAM>(result)))
        delete result;
}

static void PostFilterStatus(HWND window, bool available, std::wstring status)
{
    auto message = new (std::nothrow) FilterStatusMessage{available, std::move(status)};
    if (message == nullptr || !PostMessageW(window, WM_APP_FILTER_STATUS, 0, reinterpret_cast<LPARAM>(message)))
        delete message;
}

static std::wstring DisplayFilterPath(const wchar_t* rawPath, size_t capacity)
{
    const size_t length = wcsnlen_s(rawPath, capacity);
    std::wstring path(rawPath, length);
    if (path.rfind(L"\\??\\", 0) == 0)
        return path.substr(4);
    std::wstring dosPath = NtPathToDosPath(path);
    return dosPath.empty() ? path : dosPath;
}

static void PostFilterCaptureEvent(HWND window, const DT_FILTER_CAPTURE_RESULT& result)
{
    std::wstring source = DisplayFilterPath(result.SourcePath, std::size(result.SourcePath));
    std::wstring target;
    const wchar_t* operation = L"unknown";
    switch (result.Operation) {
    case DT_FILTER_CAPTURE_DELETE: operation = L"delete"; break;
    case DT_FILTER_CAPTURE_RENAME: operation = L"rename"; break;
    case DT_FILTER_CAPTURE_TRUNCATE: operation = L"truncate"; break;
    case DT_FILTER_CAPTURE_OVERWRITE: operation = L"overwrite"; break;
    case DT_FILTER_CAPTURE_WRITE: operation = L"write"; break;
    case DT_FILTER_CAPTURE_DELETE_ON_CLOSE: operation = L"delete-on-close"; break;
    }
    if (result.Status >= 0) {
        target = std::wstring(L"已捕获（") + operation + L"）：" +
            DisplayFilterPath(result.SnapshotPath, std::size(result.SnapshotPath)) +
            L"；SHA-256 " + result.Sha256 + L"；" + std::to_wstring(result.Size) + L" 字节";
    } else {
        target = std::wstring(L"捕获失败（") + operation + L"）：" + result.Detail;
    }

    FILETIME utc{};
    utc.dwLowDateTime = static_cast<DWORD>(result.EventTime);
    utc.dwHighDateTime = static_cast<DWORD>(static_cast<ULONGLONG>(result.EventTime) >> 32);
    FILETIME local{};
    SYSTEMTIME localTime{};
    wchar_t timeText[32]{};
    if (FileTimeToLocalFileTime(&utc, &local) && FileTimeToSystemTime(&local, &localTime))
        swprintf_s(timeText, L"%04u-%02u-%02u %02u:%02u:%02u",
            localTime.wYear, localTime.wMonth, localTime.wDay,
            localTime.wHour, localTime.wMinute, localTime.wSecond);
    else
        GetTimeFormatEx(LOCALE_NAME_USER_DEFAULT, 0, nullptr, L"HH:mm:ss", timeText, static_cast<int>(std::size(timeText)));

    auto event = new (std::nothrow) UiEvent{timeText, std::move(source), std::move(target), false};
    if (event == nullptr || !PostMessageW(window, WM_APP_DRIVER_EVENT, 0, reinterpret_cast<LPARAM>(event)))
        delete event;
}

static unsigned __stdcall MonitorWorker(void* parameter)
{
    std::unique_ptr<WorkerArgs> args(static_cast<WorkerArgs*>(parameter));
    const HWND window = args->window;
    HANDLE device = INVALID_HANDLE_VALUE;
    HANDLE driverEvent = nullptr;
    bool failed = false;
    bool monitoringStarted = false;
    bool stopRequested = false;
    bool ownsDriverLifecycle = false;
    ExistingDriverState existingDriver = ExistingDriverState::NotLoaded;
    MinifilterSession minifilter{};
    OVERLAPPED filterReceive{};
    FilterReceiveBuffer filterMessage{};
    bool filterReceivePending = false;
    std::wstring activeDirectory = args->directory;
    std::wstring error;

    if (!failed && WaitForSingleObject(args->stopEvent, 0) == WAIT_OBJECT_0)
        stopRequested = true;

    if (!failed && !stopRequested) {
        PostStatus(window, L"正在注册并启动自删除捕获过滤器…");
        std::wstring filterError;
        if (StartMinifilterSession(args->directory, args->stopEvent, minifilter, filterError)) {
            PostFilterStatus(window, true, L"自删除捕获可用：命中的内核映像文件会在破坏性操作前保存快照。");
        } else if (WaitForSingleObject(args->stopEvent, 0) != WAIT_OBJECT_0) {
            PostFilterStatus(window, false, L"自删除捕获不可用：" + filterError + L"；kdt 映像监控仍可运行。");
        } else {
            stopRequested = true;
        }
    }

    if (!failed && !stopRequested) {
        PostStatus(window, L"正在检查现有 kdt 驱动…");
        existingDriver = ProbeExistingDriver(device, error);
        ownsDriverLifecycle = g_hDriverService != nullptr;
        if (existingDriver == ExistingDriverState::Failed)
            failed = true;
    }

    if (!failed && !stopRequested) {
        if (existingDriver == ExistingDriverState::Attached) {
            PostStatus(window, ownsDriverLifecycle ? L"已复用本程序管理的 kdt 驱动…"
                                                  : L"已复用由其他服务管理的 kdt 驱动…");
        } else {
            const std::wstring driverPath = GetDriverPathBesideExecutable();
            if (driverPath.empty()) {
                failed = true;
                error = L"无法确定 dt.exe 所在目录，未能查找 kdt.sys。";
            }

            if (!failed) {
                DWORD attributes = GetFileAttributesW(driverPath.c_str());
                if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    failed = true;
                    error = L"请将 kdt.sys 放在 dt.exe 同一目录。\r\n预期路径：" + driverPath;
                    if (attributes == INVALID_FILE_ATTRIBUTES)
                        error += L"\r\n" + MakeSystemError(L"文件检查失败", GetLastError());
                }
            }

            if (!failed && !stopRequested) {
                PostStatus(window, L"正在清理上次运行遗留的 kdt 服务…");
                if (!CleanupStaleDriverService(error))
                    failed = true;
            }

            if (!failed && !stopRequested) {
                PostStatus(window, L"正在启动驱动…");
                if (!InstallAndStartDriver(driverPath, error)) {
                    failed = true;
                } else {
                    ownsDriverLifecycle = g_hDriverService != nullptr;
                }
            }

            if (!failed && !stopRequested) {
                PostStatus(window, L"正在连接驱动设备…");
                for (int attempt = 0; attempt < 20; ++attempt) {
                    device = CreateFileW(L"\\\\.\\kdt", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (device != INVALID_HANDLE_VALUE)
                        break;
                    if (WaitForSingleObject(args->stopEvent, 250) == WAIT_OBJECT_0) {
                        stopRequested = true;
                        break;
                    }
                }
                if (!stopRequested && device == INVALID_HANDLE_VALUE) {
                    failed = true;
                    error = MakeSystemError(L"无法打开驱动设备", GetLastError());
                }
            }
        }
    }

    if (!failed && !stopRequested) {
        DWORD ioError = ERROR_SUCCESS;
        if (!SetDriverDirectory(device, args->directory, ioError)) {
            failed = true;
            if (existingDriver == ExistingDriverState::Attached &&
                (ioError == ERROR_INVALID_FUNCTION || ioError == ERROR_NOT_SUPPORTED ||
                 ioError == ERROR_INVALID_PARAMETER)) {
                if (ownsDriverLifecycle) {
                    error = L"已加载的 kdt 驱动版本不支持设置转储目录。程序会尝试卸载由本程序管理的服务；完成后请再次点击“开始”以加载当前目录中的 kdt.sys。";
                } else {
                    error = L"已加载的 kdt 驱动版本不支持设置转储目录。该驱动由其他服务管理，程序不会卸载它；请先通过其管理程序停止驱动，再重新启动监控。";
                }
            } else {
                error = MakeSystemError(L"向驱动设置转储目录失败", ioError);
            }
        }
    }

    if (!failed && !stopRequested) {
        driverEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (driverEvent == nullptr) {
            failed = true;
            error = MakeSystemError(L"创建驱动通知事件失败", GetLastError());
        }
    }

    if (!failed && !stopRequested) {
        DWORD bytesReturned = 0;
        if (!DeviceIoControl(device, IOCTL_REGISTER_EVENT, &driverEvent, sizeof(driverEvent),
                             nullptr, 0, &bytesReturned, nullptr)) {
            failed = true;
            error = MakeSystemError(L"注册驱动通知事件失败", GetLastError());
        }
    }

    if (!failed && !stopRequested && minifilter.available) {
        filterReceive.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (filterReceive.hEvent == nullptr || !BeginFilterReceive(minifilter, filterMessage, filterReceive)) {
            std::wstring receiveError = filterReceive.hEvent == nullptr
                ? MakeSystemError(L"创建 minifilter 接收事件失败", GetLastError())
                : L"无法接收 minifilter 捕获结果。";
            std::wstring cleanupError;
            CloseMinifilterSession(minifilter, cleanupError);
            if (!cleanupError.empty()) receiveError += L"\r\n" + cleanupError;
            PostFilterStatus(window, false, L"自删除捕获不可用：" + receiveError + L"；kdt 映像监控仍可运行。");
        } else {
            filterReceivePending = true;
        }
    }

    if (!failed && !stopRequested) {
        monitoringStarted = true;
        auto startedDirectory = new (std::nothrow) std::wstring(args->directory);
        if (startedDirectory == nullptr ||
            !PostMessageW(window, WM_APP_WORKER_STARTED, 0, reinterpret_cast<LPARAM>(startedDirectory))) {
            delete startedDirectory;
            failed = true;
            error = L"无法通知窗口监控已经启动。";
        }
    }

    if (monitoringStarted && !failed) {
        auto disableMinifilter = [&](const std::wstring& reason) {
            if (filterReceivePending && minifilter.port != INVALID_HANDLE_VALUE) {
                CancelIoEx(minifilter.port, &filterReceive);
                DWORD ignored = 0;
                GetOverlappedResult(minifilter.port, &filterReceive, &ignored, TRUE);
                filterReceivePending = false;
            }
            if (minifilter.port != INVALID_HANDLE_VALUE) {
                CloseHandle(minifilter.port);
                minifilter.port = INVALID_HANDLE_VALUE;
            }
            minifilter.available = false;
            std::wstring unloadError;
            CloseMinifilterSession(minifilter, unloadError);
            std::wstring status = L"自删除捕获不可用：" + reason;
            if (!unloadError.empty()) status += L"；" + unloadError;
            status += L"；kdt 映像监控仍可运行。";
            PostFilterStatus(window, false, std::move(status));
        };

        bool running = true;
        while (running) {
            HANDLE waitHandles[] = { args->stopEvent, driverEvent, args->configEvent,
                                     minifilter.available ? filterReceive.hEvent : nullptr };
            const DWORD handleCount = minifilter.available ? 4 : 3;
            DWORD waitResult = WaitForMultipleObjects(handleCount, waitHandles, FALSE, INFINITE);
            if (waitResult == WAIT_OBJECT_0) {
                stopRequested = true;
                break;
            }
            if (waitResult == WAIT_OBJECT_0 + 1) {
                while (true) {
                    DRIVER_LOAD_INFO loadInfo{};
                    DWORD bytesReturned = 0;
                    if (!DeviceIoControl(device, IOCTL_GET_LOAD_DATA, nullptr, 0,
                                         &loadInfo, sizeof(loadInfo), &bytesReturned, nullptr)) {
                        failed = true;
                        error = MakeSystemError(L"读取驱动加载事件失败", GetLastError());
                        running = false;
                        break;
                    }
                    if (bytesReturned == 0)
                        break;
                    PostDriverEvent(window, loadInfo);
                }
                continue;
            }
            if (waitResult == WAIT_OBJECT_0 + 2) {
                std::wstring requestedDirectory;
                DWORD requestId = 0;
                EnterCriticalSection(&g_app.commandLock);
                requestedDirectory = g_app.pendingDirectory;
                requestId = g_app.pendingRequestId;
                LeaveCriticalSection(&g_app.commandLock);

                DWORD ioError = ERROR_SUCCESS;
                std::wstring filterError;
                const bool driverUpdated = SetDriverDirectory(device, requestedDirectory, ioError);
                const bool filterWasAvailable = minifilter.available;
                const bool filterUpdated = !filterWasAvailable ||
                    SetMinifilterDirectory(minifilter, requestedDirectory, filterError);
                if (driverUpdated && filterUpdated) {
                    activeDirectory = requestedDirectory;
                    PostApplyResult(window, requestId, true, ERROR_SUCCESS, requestedDirectory);
                    continue;
                }

                std::wstring errorText;
                if (!driverUpdated)
                    errorText = MakeSystemError(L"更新 kdt 转储目录失败", ioError);
                if (!filterUpdated) {
                    if (!errorText.empty()) errorText += L"\r\n";
                    errorText += filterError;
                }

                bool rollbackSucceeded = true;
                std::wstring rollbackErrors;
                DWORD rollbackError = ERROR_SUCCESS;
                if (!SetDriverDirectory(device, activeDirectory, rollbackError)) {
                    rollbackSucceeded = false;
                    rollbackErrors += MakeSystemError(L"回滚 kdt 转储目录失败", rollbackError);
                }
                bool filterRollbackFailed = false;
                if (filterWasAvailable) {
                    std::wstring filterRollbackError;
                    if (!SetMinifilterDirectory(minifilter, activeDirectory, filterRollbackError)) {
                        filterRollbackFailed = true;
                        if (!rollbackErrors.empty()) rollbackErrors += L"\r\n";
                        rollbackErrors += L"回滚 minifilter 转储目录失败：" + filterRollbackError;
                    }
                }
                if (!rollbackErrors.empty())
                    errorText += L"\r\n" + rollbackErrors;
                if (filterRollbackFailed) {
                    disableMinifilter(L"目录更新失败后无法恢复旧配置，已尝试卸载过滤器。");
                    rollbackSucceeded = false;
                    errorText += L"\r\n过滤器目录回滚失败；即使卸载请求已发送，也停止监控以避免配置状态不一致。";
                }

                PostApplyResult(window, requestId, false,
                    ioError != ERROR_SUCCESS ? ioError : ERROR_GEN_FAILURE,
                    requestedDirectory, errorText);
                if (!rollbackSucceeded) {
                    failed = true;
                    error = L"目录更新失败，且至少一个驱动未能恢复原目录；为避免后续捕获写入不一致路径，监控已停止。\r\n" + errorText;
                    running = false;
                }
                continue;
            }

            if (minifilter.available && waitResult == WAIT_OBJECT_0 + 3) {
                DWORD received = 0;
                filterReceivePending = false;
                if (!GetOverlappedResult(minifilter.port, &filterReceive, &received, FALSE)) {
                    DWORD receiveError = GetLastError();
                    disableMinifilter(MakeSystemError(L"接收 minifilter 捕获结果失败", receiveError));
                    continue;
                }
                if (received < sizeof(FILTER_MESSAGE_HEADER) + sizeof(DT_FILTER_CAPTURE_RESULT) ||
                    filterMessage.result.Version != DT_FILTER_PROTOCOL_VERSION) {
                    disableMinifilter(L"minifilter 返回了不完整或不兼容的捕获结果。");
                    continue;
                }
                PostFilterCaptureEvent(window, filterMessage.result);
                RtlZeroMemory(&filterMessage, sizeof(filterMessage));
                if (!BeginFilterReceive(minifilter, filterMessage, filterReceive)) {
                    disableMinifilter(L"无法继续接收 minifilter 捕获结果。");
                    continue;
                }
                filterReceivePending = true;
                continue;
            }

            failed = true;
            error = L"等待驱动通知时发生错误。";
            running = false;
        }
    }

    if (driverEvent != nullptr)
        CloseHandle(driverEvent);
    if (device != INVALID_HANDLE_VALUE)
        CloseHandle(device);

    std::wstring cleanupError;
    if (!StopDriverService(cleanupError)) {
        failed = true;
        if (!error.empty())
            error += L"\r\n";
        error += cleanupError;
    }

    const bool minifilterWasManaged = minifilter.unloadOnStop;
    if (filterReceivePending && minifilter.port != INVALID_HANDLE_VALUE) {
        CancelIoEx(minifilter.port, &filterReceive);
        DWORD ignored = 0;
        GetOverlappedResult(minifilter.port, &filterReceive, &ignored, TRUE);
        filterReceivePending = false;
    }
    if (filterReceive.hEvent != nullptr) {
        CloseHandle(filterReceive.hEvent);
        filterReceive.hEvent = nullptr;
    }
    std::wstring filterCleanupError;
    CloseMinifilterSession(minifilter, filterCleanupError);
    if (!filterCleanupError.empty()) {
        failed = true;
        if (!error.empty()) error += L"\r\n";
        error += filterCleanupError;
    }

    if (stopRequested && !failed) {
        error = ownsDriverLifecycle ? L"监控已停止，驱动服务已卸载。"
                                    : L"监控已停止；驱动由其他服务管理，程序未卸载它。";
        if (minifilterWasManaged) {
            error += L"自删除捕获过滤器已排空并卸载。";
            PostFilterStatus(window, false, L"自删除捕获已停止；minifilter 已卸载。");
        }
    }
    else if (failed && error.empty())
        error = L"监控启动或运行失败。";

    auto finalMessage = new (std::nothrow) std::wstring(std::move(error));
    if (finalMessage == nullptr ||
        !PostMessageW(window, WM_APP_WORKER_FINISHED, failed ? FALSE : TRUE,
                      reinterpret_cast<LPARAM>(finalMessage)))
        delete finalMessage;
    return 0;
}

static bool ReadDirectoryEdit(std::wstring& directory, std::wstring& error)
{
    const int length = GetWindowTextLengthW(g_app.directoryEdit);
    if (length <= 0) {
        error = L"请输入转储目录。";
        return false;
    }
    std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1);
    GetWindowTextW(g_app.directoryEdit, buffer.data(), length + 1);
    return NormalizeAndPrepareDirectory(std::wstring(buffer.data()), directory, error);
}

static void ApplyDirectory()
{
    std::wstring directory;
    std::wstring error;
    if (!ReadDirectoryEdit(directory, error)) {
        SetUiStatus(error);
        MessageBoxW(g_app.window, error.c_str(), L"目录无效", MB_OK | MB_ICONERROR);
        return;
    }

    if (!g_app.workerActive) {
        g_app.currentDirectory = directory;
        SetWindowTextW(g_app.directoryEdit, directory.c_str());
        std::wstring saveError;
        if (SaveDirectorySetting(directory, saveError))
            SetUiStatus(L"目录已应用并保存。开始监控时会加载驱动。" );
        else
            SetUiStatus(L"目录已应用；设置未能保存：" + saveError);
        return;
    }

    if (!g_app.workerRunning || g_app.stopping || g_app.applyPending)
        return;

    EnterCriticalSection(&g_app.commandLock);
    g_app.pendingDirectory = directory;
    g_app.pendingRequestId = ++g_app.nextRequestId;
    g_app.applyPending = true;
    LeaveCriticalSection(&g_app.commandLock);

    if (!SetEvent(g_app.configEvent)) {
        const DWORD lastError = GetLastError();
        g_app.applyPending = false;
        UpdateControls();
        error = MakeSystemError(L"提交目录更新失败", lastError);
        SetUiStatus(error);
        MessageBoxW(g_app.window, error.c_str(), L"应用目录失败", MB_OK | MB_ICONERROR);
        return;
    }

    SetUiStatus(L"正在将新目录应用到驱动…");
    UpdateControls();
}

static void StartMonitor()
{
    if (g_app.workerActive)
        return;

    std::wstring directory;
    std::wstring error;
    if (!ReadDirectoryEdit(directory, error)) {
        SetUiStatus(error);
        MessageBoxW(g_app.window, error.c_str(), L"目录无效", MB_OK | MB_ICONERROR);
        return;
    }

    g_app.stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_app.configEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (g_app.stopEvent == nullptr || g_app.configEvent == nullptr) {
        DWORD lastError = GetLastError();
        if (g_app.stopEvent != nullptr) CloseHandle(g_app.stopEvent);
        if (g_app.configEvent != nullptr) CloseHandle(g_app.configEvent);
        g_app.stopEvent = nullptr;
        g_app.configEvent = nullptr;
        error = MakeSystemError(L"创建监控事件失败", lastError);
        SetUiStatus(error);
        MessageBoxW(g_app.window, error.c_str(), L"启动失败", MB_OK | MB_ICONERROR);
        return;
    }

    auto args = new (std::nothrow) WorkerArgs{g_app.window, g_app.stopEvent, g_app.configEvent, directory};
    if (args == nullptr) {
        CloseHandle(g_app.stopEvent);
        CloseHandle(g_app.configEvent);
        g_app.stopEvent = nullptr;
        g_app.configEvent = nullptr;
        SetUiStatus(L"内存不足，无法启动监控线程。" );
        return;
    }

    g_app.workerActive = true;
    g_app.workerRunning = false;
    g_app.stopping = false;
    g_app.applyPending = false;
    g_app.closeWhenStopped = false;
    g_app.workerThread = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 0, MonitorWorker, args, 0,
                                                                  &g_app.workerThreadId));
    if (g_app.workerThread == nullptr) {
        delete args;
        CloseHandle(g_app.stopEvent);
        CloseHandle(g_app.configEvent);
        g_app.stopEvent = nullptr;
        g_app.configEvent = nullptr;
        g_app.workerActive = false;
        SetUiStatus(MakeSystemError(L"创建监控线程失败", GetLastError()));
        UpdateControls();
        return;
    }

    SetUiStatus(L"正在启动监控…");
    UpdateControls();
}

static void StopMonitor()
{
    if (!g_app.workerActive || g_app.stopping)
        return;
    g_app.stopping = true;
    if (g_app.stopEvent != nullptr)
        SetEvent(g_app.stopEvent);
    SetUiStatus(L"正在停止监控…");
    UpdateControls();
}

static void BrowseForDirectory()
{
    IFileOpenDialog* dialog = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&dialog));
    if (FAILED(hr)) {
        std::wstring error = L"无法打开目录选择器（HRESULT " + std::to_wstring(static_cast<unsigned long>(hr)) + L"）。";
        SetUiStatus(error);
        return;
    }

    DWORD options = 0;
    hr = dialog->GetOptions(&options);
    if (SUCCEEDED(hr))
        hr = dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOCHANGEDIR);
    if (SUCCEEDED(hr))
        hr = dialog->Show(g_app.window);

    if (SUCCEEDED(hr)) {
        IShellItem* item = nullptr;
        hr = dialog->GetResult(&item);
        if (SUCCEEDED(hr)) {
            PWSTR selectedPath = nullptr;
            hr = item->GetDisplayName(SIGDN_FILESYSPATH, &selectedPath);
            if (SUCCEEDED(hr) && selectedPath != nullptr) {
                SetWindowTextW(g_app.directoryEdit, selectedPath);
                CoTaskMemFree(selectedPath);
            }
            item->Release();
        }
    }

    dialog->Release();
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
        std::wstring error = L"目录选择器失败（HRESULT " + std::to_wstring(static_cast<unsigned long>(hr)) + L"）。";
        SetUiStatus(error);
    }
}

static void LayoutControls(HWND window)
{
    RECT client{};
    GetClientRect(window, &client);
    const int width = client.right - client.left;
    const int height = client.bottom - client.top;
    const int margin = 16;

    MoveWindow(GetDlgItem(window, IDC_DIRECTORY_LABEL), margin, 17, 66, 24, TRUE);
    MoveWindow(g_app.directoryEdit, 86, 14, std::max(120, width - 306), 28, TRUE);
    MoveWindow(g_app.browseButton, width - 208, 14, 88, 28, TRUE);
    MoveWindow(g_app.applyButton, width - 112, 14, 96, 28, TRUE);
    MoveWindow(g_app.startButton, 86, 55, 92, 30, TRUE);
    MoveWindow(g_app.stopButton, 188, 55, 92, 30, TRUE);
    MoveWindow(g_app.statusLabel, 296, 58, std::max(100, width - 312), 24, TRUE);
    MoveWindow(g_app.filterStatusLabel, margin, 88, std::max(100, width - margin * 2), 22, TRUE);
    MoveWindow(g_app.eventList, margin, 117, std::max(100, width - margin * 2), std::max(80, height - 133), TRUE);

    const int listWidth = std::max(100, width - margin * 2);
    ListView_SetColumnWidth(g_app.eventList, 0, 145);
    ListView_SetColumnWidth(g_app.eventList, 1, std::max(220, (listWidth - 425) / 2));
    ListView_SetColumnWidth(g_app.eventList, 2, std::max(220, listWidth - 145 - std::max(220, (listWidth - 425) / 2) - 8));
}

static bool CreateControls(HWND window)
{
    const DWORD childStyle = WS_CHILD | WS_VISIBLE;
    g_app.directoryEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        childStyle | WS_TABSTOP | ES_AUTOHSCROLL, 86, 14, 500, 28, window,
        reinterpret_cast<HMENU>(IDC_DIRECTORY_EDIT), nullptr, nullptr);
    g_app.directoryLabel = CreateWindowExW(0, L"STATIC", L"转储目录：",
        childStyle | SS_LEFT | SS_CENTERIMAGE, 16, 17, 66, 24, window,
        reinterpret_cast<HMENU>(IDC_DIRECTORY_LABEL), nullptr, nullptr);
    g_app.browseButton = CreateWindowExW(0, L"BUTTON", L"浏览…",
        childStyle | WS_TABSTOP | BS_PUSHBUTTON, 0, 14, 88, 28, window,
        reinterpret_cast<HMENU>(IDC_BROWSE), nullptr, nullptr);
    g_app.applyButton = CreateWindowExW(0, L"BUTTON", L"应用",
        childStyle | WS_TABSTOP | BS_PUSHBUTTON, 0, 14, 96, 28, window,
        reinterpret_cast<HMENU>(IDC_APPLY), nullptr, nullptr);
    g_app.startButton = CreateWindowExW(0, L"BUTTON", L"开始监控",
        childStyle | WS_TABSTOP | BS_PUSHBUTTON, 86, 55, 92, 30, window,
        reinterpret_cast<HMENU>(IDC_START), nullptr, nullptr);
    g_app.stopButton = CreateWindowExW(0, L"BUTTON", L"停止监控",
        childStyle | WS_TABSTOP | BS_PUSHBUTTON, 188, 55, 92, 30, window,
        reinterpret_cast<HMENU>(IDC_STOP), nullptr, nullptr);
    g_app.statusLabel = CreateWindowExW(0, L"STATIC", L"",
        childStyle | SS_LEFT | SS_CENTERIMAGE, 296, 58, 500, 24, window,
        reinterpret_cast<HMENU>(IDC_STATUS), nullptr, nullptr);
    g_app.filterStatusLabel = CreateWindowExW(0, L"STATIC", L"自删除捕获尚未启动（按需）",
        childStyle | SS_LEFT | SS_CENTERIMAGE, 16, 88, 860, 22, window,
        reinterpret_cast<HMENU>(IDC_FILTER_STATUS), nullptr, nullptr);
    g_app.eventList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        childStyle | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS, 16, 101, 860, 480, window,
        reinterpret_cast<HMENU>(IDC_EVENT_LIST), nullptr, nullptr);

    if (g_app.directoryLabel == nullptr || g_app.directoryEdit == nullptr || g_app.browseButton == nullptr || g_app.applyButton == nullptr ||
        g_app.startButton == nullptr || g_app.stopButton == nullptr || g_app.statusLabel == nullptr ||
        g_app.filterStatusLabel == nullptr ||
        g_app.eventList == nullptr)
        return false;

    HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    for (HWND control : {g_app.directoryLabel, g_app.directoryEdit, g_app.browseButton, g_app.applyButton,
                         g_app.startButton, g_app.stopButton, g_app.statusLabel, g_app.filterStatusLabel,
                         g_app.eventList})
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    ListView_SetExtendedListViewStyle(g_app.eventList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    const wchar_t* columns[] = { L"时间", L"映像路径", L"预期转储路径" };
    const int widths[] = { 145, 360, 360 };
    for (int index = 0; index < 3; ++index) {
        LVCOLUMNW column{};
        column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        column.pszText = const_cast<wchar_t*>(columns[index]);
        column.cx = widths[index];
        column.iSubItem = index;
        if (ListView_InsertColumn(g_app.eventList, index, &column) == -1)
            return false;
    }

    SetWindowTextW(g_app.directoryEdit, g_app.currentDirectory.c_str());
    SetFilterUiStatus(false, L"自删除捕获尚未启动（按需）。启动监控时会加载 minifilter。");
    SetUiStatus(g_app.toastShortcutReady
        ? L"设置已加载；监控尚未启动。"
        : L"设置已加载；Toast 快捷方式无法注册，系统通知可能不可用。监控尚未启动。");
    LayoutControls(window);
    UpdateControls();
    return true;
}

static void AppendEventToList(const UiEvent& event)
{
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = ListView_GetItemCount(g_app.eventList);
    item.pszText = const_cast<wchar_t*>(event.time.c_str());
    const int row = ListView_InsertItem(g_app.eventList, &item);
    if (row < 0)
        return;

    ListView_SetItemText(g_app.eventList, row, 1, const_cast<wchar_t*>(event.source.c_str()));
    ListView_SetItemText(g_app.eventList, row, 2, const_cast<wchar_t*>(event.target.c_str()));
    ListView_EnsureVisible(g_app.eventList, row, FALSE);
    if (event.showToast)
        ShowToast(L"检测到驱动加载", event.target, event.target);
}

static LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    case WM_CREATE:
        g_app.window = window;
        if (!CreateControls(window))
            return -1;
        return 0;

    case WM_SIZE:
        if (g_app.eventList != nullptr)
            LayoutControls(window);
        return 0;

    case WM_GETMINMAXINFO: {
        auto limits = reinterpret_cast<MINMAXINFO*>(lParam);
        limits->ptMinTrackSize.x = 720;
        limits->ptMinTrackSize.y = 445;
        return 0;
    }

    case WM_CTLCOLORSTATIC:
        if (reinterpret_cast<HWND>(lParam) == g_app.filterStatusLabel) {
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetTextColor(dc, g_app.filterAvailable ? RGB(0, 112, 60) : RGB(176, 64, 32));
            SetBkMode(dc, TRANSPARENT);
            return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
        }
        break;

    case WM_COMMAND:
        if (HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case IDC_BROWSE: BrowseForDirectory(); return 0;
            case IDC_APPLY: ApplyDirectory(); return 0;
            case IDC_START: StartMonitor(); return 0;
            case IDC_STOP: StopMonitor(); return 0;
            }
        }
        break;

    case WM_APP_STATUS: {
        std::unique_ptr<std::wstring> status(reinterpret_cast<std::wstring*>(lParam));
        if (status)
            SetUiStatus(*status);
        return 0;
    }

    case WM_APP_WORKER_STARTED: {
        std::unique_ptr<std::wstring> directory(reinterpret_cast<std::wstring*>(lParam));
        g_app.workerRunning = true;
        g_app.stopping = false;
        if (directory) {
            g_app.currentDirectory = *directory;
            SetWindowTextW(g_app.directoryEdit, g_app.currentDirectory.c_str());
            std::wstring saveError;
            if (!SaveDirectorySetting(g_app.currentDirectory, saveError))
                SetUiStatus(L"监控已启动；目录设置未能保存：" + saveError);
            else
                SetUiStatus(L"监控中，转储目录：" + g_app.currentDirectory);
        }
        UpdateControls();
        return 0;
    }

    case WM_APP_DRIVER_EVENT: {
        std::unique_ptr<UiEvent> event(reinterpret_cast<UiEvent*>(lParam));
        if (event)
            AppendEventToList(*event);
        return 0;
    }

    case WM_APP_FILTER_STATUS: {
        std::unique_ptr<FilterStatusMessage> status(reinterpret_cast<FilterStatusMessage*>(lParam));
        if (status)
            SetFilterUiStatus(status->available, status->text);
        return 0;
    }

    case WM_APP_APPLY_RESULT: {
        std::unique_ptr<ApplyResult> result(reinterpret_cast<ApplyResult*>(lParam));
        if (result && result->requestId == g_app.pendingRequestId) {
            g_app.applyPending = false;
            if (result->succeeded) {
                g_app.currentDirectory = result->directory;
                SetWindowTextW(g_app.directoryEdit, g_app.currentDirectory.c_str());
                std::wstring saveError;
                if (SaveDirectorySetting(g_app.currentDirectory, saveError))
                    SetUiStatus(L"转储目录已更新：" + g_app.currentDirectory);
                else
                    SetUiStatus(L"转储目录已更新，但设置未能保存：" + saveError);
            }
            else {
                SetWindowTextW(g_app.directoryEdit, g_app.currentDirectory.c_str());
                std::wstring error = result->errorText.empty()
                    ? MakeSystemError(L"驱动拒绝了目录更新", result->error)
                    : result->errorText;
                SetUiStatus(error);
                MessageBoxW(window, error.c_str(), L"应用目录失败", MB_OK | MB_ICONERROR);
            }
            UpdateControls();
        }
        return 0;
    }

    case WM_APP_WORKER_FINISHED: {
        std::unique_ptr<std::wstring> result(reinterpret_cast<std::wstring*>(lParam));
        const bool succeeded = wParam != FALSE;
        g_app.workerActive = false;
        g_app.workerRunning = false;
        g_app.stopping = false;
        g_app.applyPending = false;
        EnterCriticalSection(&g_app.commandLock);
        g_app.pendingDirectory.clear();
        LeaveCriticalSection(&g_app.commandLock);

        if (g_app.workerThread != nullptr) {
            CloseHandle(g_app.workerThread);
            g_app.workerThread = nullptr;
        }
        if (g_app.stopEvent != nullptr) {
            CloseHandle(g_app.stopEvent);
            g_app.stopEvent = nullptr;
        }
        if (g_app.configEvent != nullptr) {
            CloseHandle(g_app.configEvent);
            g_app.configEvent = nullptr;
        }

        const std::wstring messageText = result ? *result : L"监控线程已结束。";
        SetWindowTextW(g_app.directoryEdit, g_app.currentDirectory.c_str());
        SetUiStatus(messageText);
        UpdateControls();
        if (!succeeded)
            MessageBoxW(window, messageText.c_str(), L"监控结束", MB_OK | MB_ICONERROR);
        if (g_app.closeWhenStopped)
            DestroyWindow(window);
        return 0;
    }

    case WM_CLOSE:
        if (g_app.workerActive) {
            const int answer = MessageBoxW(window,
                L"驱动正在启动或监控中。关闭窗口将停止监控、排空并卸载本程序启动的 minifilter；只有由本程序管理的 kdt 服务会被卸载。是否继续？",
                L"确认退出", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
            if (answer != IDYES)
                return 0;
            g_app.closeWhenStopped = true;
            StopMonitor();
            return 0;
        }
        DestroyWindow(window);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS*)
{
    std::wstring ignored;
    StopDriverService(ignored);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void TerminateHandler()
{
    std::wstring ignored;
    StopDriverService(ignored);
    abort();
}

static void PureCallHandler()
{
    std::wstring ignored;
    StopDriverService(ignored);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand)
{
    try {
        winrt::init_apartment(winrt::apartment_type::single_threaded);
    }
    catch (const winrt::hresult_error& error) {
        MessageBoxW(nullptr, error.message().c_str(), L"初始化失败", MB_OK | MB_ICONERROR);
        return 1;
    }

    InitializeCriticalSection(&g_app.commandLock);
    SetUnhandledExceptionFilter(ExceptionFilter);
    std::set_terminate(TerminateHandler);
    _set_purecall_handler(PureCallHandler);

    INITCOMMONCONTROLSEX commonControls{sizeof(commonControls), ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES};
    if (!InitCommonControlsEx(&commonControls)) {
        DeleteCriticalSection(&g_app.commandLock);
        MessageBoxW(nullptr, L"初始化 Windows 公共控件失败。", L"启动失败", MB_OK | MB_ICONERROR);
        return 1;
    }

    g_app.currentDirectory = LoadInitialDirectory();
    g_app.toastShortcutReady = EnsureAumidShortcut();

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.hInstance = instance;
    windowClass.lpfnWndProc = WindowProc;
    windowClass.lpszClassName = L"DriverTarpperMainWindow";
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (RegisterClassExW(&windowClass) == 0) {
        DWORD error = GetLastError();
        DeleteCriticalSection(&g_app.commandLock);
        MessageBoxW(nullptr, MakeSystemError(L"注册窗口类失败", error).c_str(), L"启动失败", MB_OK | MB_ICONERROR);
        return 1;
    }

    HWND window = CreateWindowExW(0, windowClass.lpszClassName, L"DriverTarpper - 驱动加载监控",
                                  WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                  920, 620, nullptr, nullptr, instance, nullptr);
    if (window == nullptr) {
        DWORD error = GetLastError();
        DeleteCriticalSection(&g_app.commandLock);
        MessageBoxW(nullptr, MakeSystemError(L"创建主窗口失败", error).c_str(), L"启动失败", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(window, showCommand);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    DeleteCriticalSection(&g_app.commandLock);
    return static_cast<int>(message.wParam);
}
