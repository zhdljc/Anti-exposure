// =====================================================================
//  ANTI v5.0 - Windows Privacy Toolkit
//  Complete Integration Edition
//
//  Features:
//    - Native C++ privacy scanner (registry, services, credentials, tasks)
//    - External tool integration (15 GitHub projects, one-click clone)
//    - Real-time monitoring (WMI events + polling for processes/registry)
//    - System tray with context menu and balloon notifications
//    - Auto-start on login (Run key + startup folder)
//    - Block mode (hosts + policies + identity wipe)
//
//  Compile: cl /std:c++17 /EHsc /O2 ANTI.cpp
//  Depends: advapi32, ole32, oleaut32, netapi32, credui, shell32,
//           wbemuuid, wintrust, comctl32, gdi32, user32
// =====================================================================
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <wincred.h>
#include <lm.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <comdef.h>
#include <wbemidl.h>
#include <cwchar>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <queue>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <conio.h>
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

// =====================================================================
//  COLORS
// =====================================================================
#define C_DEF   7
#define C_CYAN  11
#define C_GREEN 10
#define C_YEL   14
#define C_RED   12
#define C_MAG   13
#define C_GRAY  8
#define C_WHITE 15

static HANDLE g_hOut = INVALID_HANDLE_VALUE;
static HWND   g_hWnd = NULL;
static HINSTANCE g_hInst = NULL;

#define WM_TRAYICON (WM_USER + 1)
#define IDM_TRAY_SHOW   1001
#define IDM_TRAY_SCAN   1002
#define IDM_TRAY_BLOCK  1003
#define IDM_TRAY_EXIT   1004
#define IDT_MONITOR     2001

static void SetColor(int c) { SetConsoleTextAttribute(g_hOut, (WORD)c); }
static void GotoXY(int x, int y) { COORD p{ (SHORT)x, (SHORT)y }; SetConsoleCursorPosition(g_hOut, p); }
static void HideCursor() { CONSOLE_CURSOR_INFO ci{ 1, FALSE }; SetConsoleCursorInfo(g_hOut, &ci); }
static void ShowCursor() { CONSOLE_CURSOR_INFO ci{ 1, TRUE };  SetConsoleCursorInfo(g_hOut, &ci); }

static void ClearScreen() {
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    DWORD count = 0;
    GetConsoleScreenBufferInfo(g_hOut, &csbi);
    DWORD cells = (DWORD)csbi.dwSize.X * csbi.dwSize.Y;
    COORD home{ 0, 0 };
    FillConsoleOutputCharacterW(g_hOut, L' ', cells, home, &count);
    FillConsoleOutputAttribute(g_hOut, csbi.wAttributes, cells, home, &count);
    SetConsoleCursorPosition(g_hOut, home);
}

static void WOut(const std::wstring& s) {
    if (s.empty()) return;
    DWORD written = 0;
    WriteConsoleW(g_hOut, s.c_str(), (DWORD)s.size(), &written, NULL);
}
static void Banner();

// =====================================================================
//  INPUT
// =====================================================================
static std::wstring ReadLineW() {
    ShowCursor();
    std::wstring s;
    for (;;) {
        wchar_t c = (wchar_t)_getwch();
        if (c == L'\r' || c == L'\n') break;
        if (c == L'\b') {
            if (!s.empty()) { s.pop_back(); WOut(L"\b \b"); }
            continue;
        }
        if (c >= 32 && c != 127) { s.push_back(c); WOut(std::wstring(1, c)); }
    }
    HideCursor();
    return s;
}

// =====================================================================
//  DATA STRUCTURES
// =====================================================================
enum Sev { SV_INFO, SV_LOW, SV_MED, SV_HIGH, SV_CRIT };
enum Cat { CT_REG, CT_SVC, CT_PRC, CT_CRED, CT_ACCT, CT_OD, CT_TASK, CT_HOST, CT_EXT };

struct Finding {
    Cat cat; Sev sev;
    std::wstring title, path, value, detail, action;
    std::wstring delType;      // "reg" | "cred" | "svc" | "task" | "none"
    HKEY hRoot = nullptr;
    std::wstring regPath, regValue;
    bool delOk = false;
};

struct CredRow {
    std::wstring target, user;
    DWORD persist;
    DWORD type;
};

// External tool definition
struct ExtTool {
    const wchar_t* name;
    const wchar_t* repo;      // GitHub repo URL
    const wchar_t* desc;
    const wchar_t* script;    // relative path to main script
    bool recommended;
};

// =====================================================================
//  EXTERNAL TOOLS (15 projects)
// =====================================================================
static const std::vector<ExtTool> g_extTools = {
    { L"deGDID", L"https://github.com/yegors/deGDID.git",
      L"Deletes GDID and prevents minting new ones",
      L"degdid.ps1", true },
    { L"noid-privacy", L"https://github.com/NexusOne23/noid-privacy.git",
      L"630+ privacy settings, 7 modules, BAVR pattern",
      L"noid-privacy.ps1", true },
    { L"Privacy.sexy-Revamped", L"https://github.com/Turtlecute33/Privacy.sexy-Revamped.git",
      L"Script builder for debloating and hardening",
      L"", false },
    { L"ReWindows", L"https://github.com/Synalix/ReWindows.git",
      L"Modern Windows optimization & privacy utility",
      L"", false },
    { L"Win11Debloat", L"https://github.com/scavin/Win11Debloat.git",
      L"Remove pre-installed apps, disable telemetry",
      L"Win11Debloat.ps1", false },
    { L"WindowsSpyBlocker", L"https://github.com/crazy-max/WindowsSpyBlocker.git",
      L"Hosts + firewall blocking rules (347+ entries)",
      L"", false },
    { L"windows-telemetry-guard", L"https://github.com/WallabyDesigns/windows-telemetry-guard.git",
      L"Telemetry monitoring and blocking guard",
      L"", false },
    { L"Sophia-Script", L"https://github.com/farag2/Sophia-Script-for-Windows.git",
      L"Most powerful PowerShell tweaker for Windows",
      L"", false },
    { L"Windows-Optimize-Harden-Debloat", L"https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat.git",
      L"STIG/SRG compliant hardening script",
      L"", false },
    { L"Privatezilla", L"https://github.com/builtbybel/privatezilla.git",
      L"Privacy & security check (60 settings)",
      L"", false },
    { L"Bloatynosy", L"https://github.com/builtbybel/Bloatynosy.git",
      L"Bloatware removal and privacy tool",
      L"", false },
    { L"TowelProtocol", L"https://github.com/zerocool26/TowelProtocol.git",
      L"Windows 11 privacy hardening framework",
      L"", false },
    { L"Windows-Telemetry-Disabler", L"https://github.com/EXLOUD/Windows-Telemetry-Disabler.git",
      L"TrustedInstaller-level telemetry disabler",
      L"telemetry-win.ps1", false },
    { L"Windows11-Privacy-Optimizer", L"https://github.com/n03stalg1a/Windows11-Privacy-Optimizer.git",
      L"Batch script for privacy optimization",
      L"Windows11-Privacy-Optimizer.bat", false },
};

// =====================================================================
//  GLOBAL STATE
// =====================================================================
static std::vector<Finding> g_find;
static std::vector<CredRow>  g_creds;
static std::mutex g_mtx;
static std::mutex g_phaseMtx;
static std::atomic<int>    g_done{ 0 };
static std::atomic<bool>   g_stop{ false };
static std::atomic<size_t> g_scanCount{ 0 };
static std::wstring g_phase = L"";
static std::atomic<bool>   g_monitorRunning{ false };
static std::atomic<bool>   g_exitRequested{ false };
static std::wstring g_toolsDir;    // <exe_dir>\tools
static std::wstring g_exeDir;

static void SetPhase(const wchar_t* p) {
    std::lock_guard<std::mutex> lk(g_phaseMtx);
    g_phase = p;
}
static std::wstring GetPhase() {
    std::lock_guard<std::mutex> lk(g_phaseMtx);
    return g_phase;
}

// =====================================================================
//  HELPERS
// =====================================================================
static std::wstring Fmt(const std::wstring& s, size_t max = 80) {
    if (s.size() <= max) return s;
    return s.substr(0, max - 3) + L"...";
}
static const wchar_t* SevTag(Sev s) {
    switch (s) {
    case SV_CRIT: return L"[CRIT]";
    case SV_HIGH: return L"[HIGH]";
    case SV_MED:  return L"[MED ]";
    case SV_LOW:  return L"[LOW ]";
    default:      return L"[INFO]";
    }
}
static int SevColor(Sev s) {
    switch (s) {
    case SV_CRIT: case SV_HIGH: return C_RED;
    case SV_MED:  return C_YEL;
    case SV_LOW:  return C_CYAN;
    default:      return C_GRAY;
    }
}
static const wchar_t* CatName(Cat c) {
    switch (c) {
    case CT_REG:  return L"Registry";
    case CT_SVC:  return L"Service";
    case CT_PRC:  return L"Process";
    case CT_CRED: return L"Credential";
    case CT_ACCT: return L"Account";
    case CT_OD:   return L"OneDrive";
    case CT_TASK: return L"Task";
    case CT_HOST: return L"Hosts";
    case CT_EXT:  return L"External";
    }
    return L"?";
}

static void Push(const Finding& f) {
    std::lock_guard<std::mutex> lk(g_mtx);
    for (auto& e : g_find)
        if (e.cat == f.cat && e.path == f.path && e.value == f.value) return;
    g_find.push_back(f);
}

static bool LooksLikeIdentity(const std::wstring& s) {
    if (s.size() < 8) return false;
    if (s.size() >= 4 && s.compare(0, 4, L"0018") == 0) return true;
    if (s.size() == 38 && s.front() == L'{' && s.back() == L'}' &&
        s[9] == L'-' && s[14] == L'-' && s[19] == L'-' && s[24] == L'-') return true;
    if (s.size() == 36 && s[8] == L'-' && s[13] == L'-' && s[18] == L'-' && s[23] == L'-') return true;
    int sep = 0;
    for (wchar_t c : s) if (c == L'_' || c == L'.') sep++;
    if (sep >= 2 && s.size() >= 12 && s.size() <= 64) return true;
    return false;
}

static bool IsElevated() {
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te{};
        DWORD sz = sizeof(te);
        if (GetTokenInformation(token, TokenElevation, &te, sz, &sz))
            elevated = te.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
}

static bool IsInWindowsTerminal() {
    wchar_t buf[8];
    return GetEnvironmentVariableW(L"WT_SESSION", buf, 8) > 0;
}

static std::wstring FindWindowsTerminal() {
    wchar_t path[MAX_PATH];
    if (SearchPathW(NULL, L"wt.exe", NULL, MAX_PATH, path, NULL) > 0)
        return path;
    wchar_t* lad = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &lad))) {
        std::wstring p = std::wstring(lad) + L"\\Microsoft\\WindowsApps\\wt.exe";
        CoTaskMemFree(lad);
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) return p;
    }
    return L"";
}

static void EnsureElevatedAndWt() {
    bool elevated = IsElevated();
    bool inWt = IsInWindowsTerminal();
    if (elevated && inWt) return;

    wchar_t exePath[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    std::wstring dir(exePath);
    size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) dir = dir.substr(0, slash);

    if (!elevated) {
        if (!inWt) {
            std::wstring wt = FindWindowsTerminal();
            if (!wt.empty()) {
                std::wstring params = L"nt \"" + std::wstring(exePath) + L"\"";
                SHELLEXECUTEINFOW sei{ sizeof(sei) };
                sei.lpVerb = L"runas";
                sei.lpFile = wt.c_str();
                sei.lpParameters = params.c_str();
                sei.lpDirectory = dir.c_str();
                sei.nShow = SW_SHOWNORMAL;
                if (ShellExecuteExW(&sei)) ExitProcess(0);
            }
        }
        SHELLEXECUTEINFOW sei{ sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = exePath;
        sei.lpDirectory = dir.c_str();
        sei.nShow = SW_SHOWNORMAL;
        if (ShellExecuteExW(&sei)) ExitProcess(0);
    }
}

// =====================================================================
//  REGISTRY HELPERS
// =====================================================================
static bool RegValueIfKeyExists(HKEY root, const std::wstring& path,
    const std::wstring& name, DWORD value) {
    HKEY hk = nullptr;
    REGSAM sam = KEY_READ | KEY_SET_VALUE | KEY_WOW64_64KEY;
    if (RegOpenKeyExW(root, path.c_str(), 0, sam, &hk) != ERROR_SUCCESS)
        return false;
    LSTATUS r = RegSetValueExW(hk, name.c_str(), 0, REG_DWORD,
        (const BYTE*)&value, sizeof(value));
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

static bool RegCreatePolicyValue(HKEY root, const std::wstring& path,
    const std::wstring& name, DWORD value) {
    HKEY hk = nullptr;
    REGSAM sam = KEY_SET_VALUE | KEY_WOW64_64KEY;
    DWORD disp = 0;
    LSTATUS r = RegCreateKeyExW(root, path.c_str(), 0, NULL,
        REG_OPTION_NON_VOLATILE, sam, NULL, &hk, &disp);
    if (r != ERROR_SUCCESS) return false;
    r = RegSetValueExW(hk, name.c_str(), 0, REG_DWORD,
        (const BYTE*)&value, sizeof(value));
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

static bool RegDeleteValueIfExists(HKEY root, const std::wstring& path,
    const std::wstring& name) {
    HKEY hk = nullptr;
    REGSAM sam = KEY_SET_VALUE | KEY_WOW64_64KEY;
    if (RegOpenKeyExW(root, path.c_str(), 0, sam, &hk) != ERROR_SUCCESS)
        return false;
    LSTATUS r = RegDeleteValueW(hk, name.c_str());
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

static bool RegDeleteTreeIfExists(HKEY root, const std::wstring& path) {
    HKEY hk = nullptr;
    REGSAM sam = KEY_READ | KEY_WOW64_64KEY;
    if (RegOpenKeyExW(root, path.c_str(), 0, sam, &hk) != ERROR_SUCCESS)
        return false;
    RegCloseKey(hk);
    return RegDeleteTreeW(root, path.c_str()) == ERROR_SUCCESS;
}

// =====================================================================
//  NATIVE SCANNERS
// =====================================================================
struct RegTarget {
    HKEY root; const wchar_t* path; const wchar_t* valueHint;
    Sev sev; const wchar_t* action;
};

static const std::vector<RegTarget> g_regTargets = {
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\IdentityCRL\\ExtendedProperties", L"LID",
      SV_CRIT, L"Delete the LID value only (keep ExtendedProperties key)." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\IdentityCRL\\Immersive\\production\\Property", L"DeviceId",
      SV_CRIT, L"Delete the DeviceId value." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\IdentityCRL\\UserExtendedProperties", nullptr,
      SV_HIGH, L"Expand subkeys and delete CID / LID values." },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\IdentityCRL\\DeviceIdentities", nullptr,
      SV_CRIT, L"Inspect each subkey's DeviceId XML; delete DeviceId values (keep keys)." },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\IdentityStore\\Cache", nullptr,
      SV_HIGH, L"Machine identity cache. Remove DeviceId values." },
    { HKEY_USERS, L".DEFAULT\\Software\\Microsoft\\IdentityCRL\\DeviceIdentities", nullptr,
      SV_CRIT, L"Default-user identity root. Remove DeviceId values." },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
      SV_CRIT, L"System-wide GUID. Deleting affects licensing/apps. BACK UP FIRST." },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId",
      SV_CRIT, L"Telemetry machine ID. Safe to delete." },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack", nullptr,
      SV_MED, L"Telemetry diagnostics cache. You may clear the subkeys." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled",
      SV_MED, L"Set to 0 or delete the whole key." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Id",
      SV_CRIT, L"Advertising GUID. Delete." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"Start_TrackProgs",
      SV_MED, L"Program launch tracking. Set to 0." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"Start_TrackDocs",
      SV_MED, L"Recent documents tracking. Set to 0." },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", L"AllowTelemetry",
      SV_HIGH, L"Set to 0 (Security) to disable telemetry." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\DeveloperTools", L"deviceid",
      SV_MED, L"Delete if you don't use Visual Studio dev tools." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\OneDrive", L"DeviceIdForODC",
      SV_HIGH, L"Unlink OneDrive, then delete this value." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\OneDrive", L"DeviceIdChangeTrackWinV2",
      SV_MED, L"Unlink OneDrive, then delete this value." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Clipboard", L"EnableCloudClipboard",
      SV_MED, L"Cloud clipboard sync. Set to 0." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Input\\Settings", L"CloudCandidateEnabled",
      SV_LOW, L"Cloud IME candidates. Set to 0." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\CDP", nullptr,
      SV_HIGH, L"Connected Devices Platform cache. Clear subkeys." },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Speech_OneCore\\Settings\\OnlineSpeechPrivacy", L"HasAccepted",
      SV_MED, L"Online speech recognition. Set to 0." },
};

static bool ReadRegValue(HKEY hk, DWORD i, DWORD maxVal, DWORD maxData,
    std::wstring& name, std::wstring& dataStr, DWORD& type) {
    std::vector<wchar_t> vn(maxVal + 1);
    DWORD vnSize = maxVal + 1;
    std::vector<BYTE> data(maxData + 4);
    DWORD dataSize = maxData + 4;
    if (RegEnumValueW(hk, i, vn.data(), &vnSize, nullptr, &type, data.data(), &dataSize) != ERROR_SUCCESS)
        return false;
    name = vn.data();
    if (type == REG_SZ || type == REG_EXPAND_SZ)
        dataStr = reinterpret_cast<wchar_t*>(data.data());
    else if (type == REG_BINARY)
        dataStr = L"<binary " + std::to_wstring(dataSize) + L" bytes>";
    else if (type == REG_DWORD && dataSize >= 4) {
        DWORD v = *reinterpret_cast<DWORD*>(data.data());
        dataStr = std::to_wstring(v);
    }
    return true;
}

static void ScanRegistryWorker() {
    SetPhase(L"Registry");
    for (const auto& t : g_regTargets) {
        if (g_stop) break;
        HKEY hk = nullptr;
        REGSAM sam = KEY_READ | KEY_WOW64_64KEY;
        if (RegOpenKeyExW(t.root, t.path, 0, sam, &hk) != ERROR_SUCCESS) continue;
        g_scanCount++;

        DWORD nSub = 0, nVal = 0, maxVal = 0, maxData = 0;
        RegQueryInfoKeyW(hk, nullptr, nullptr, nullptr, &nSub, nullptr, nullptr,
            &nVal, &maxVal, &maxData, nullptr, nullptr);

        for (DWORD i = 0; i < nVal && !g_stop; i++) {
            std::wstring name, dataStr;
            DWORD type = 0;
            if (!ReadRegValue(hk, i, maxVal, maxData, name, dataStr, type)) continue;

            bool match = false;
            if (t.valueHint && _wcsicmp(name.c_str(), t.valueHint) == 0) match = true;
            if (!t.valueHint && (name.find(L"DeviceId") != std::wstring::npos ||
                name.find(L"LID") != std::wstring::npos ||
                name.find(L"MachineId") != std::wstring::npos ||
                name.find(L"CID") != std::wstring::npos))
                match = true;
            if (!match && LooksLikeIdentity(dataStr)) match = true;

            if (match) {
                Finding f;
                f.cat = CT_REG; f.sev = t.sev;
                f.title = L"Identity artifact in registry";
                f.path = (t.root == HKEY_CURRENT_USER ? L"HKCU\\" :
                    t.root == HKEY_LOCAL_MACHINE ? L"HKLM\\" : L"HKU\\") + std::wstring(t.path);
                f.value = name;
                f.detail = dataStr.empty() ? L"(empty)" : Fmt(dataStr, 60);
                f.action = t.action;
                f.delOk = true;
                f.delType = L"reg";
                f.hRoot = t.root;
                f.regPath = t.path;
                f.regValue = name;
                Push(f);
            }
        }

        if (nSub > 0 && t.valueHint == nullptr) {
            for (DWORD si = 0; si < nSub && !g_stop; si++) {
                wchar_t subName[512] = { 0 };
                DWORD subLen = 512;
                if (RegEnumKeyExW(hk, si, subName, &subLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    continue;
                g_scanCount++;
                Finding f;
                f.cat = CT_REG; f.sev = t.sev;
                f.title = L"Identity subkey (may contain GUID)";
                f.path = std::wstring(t.path) + L"\\" + subName;
                f.value = subName;
                f.detail = L"Open this subkey and inspect DeviceId / LID values.";
                f.action = t.action;
                Push(f);
            }
        }
        RegCloseKey(hk);
    }
    g_done++;
}

// =====================================================================
//  SERVICES SCANNER
// =====================================================================
struct SvcTarget { const wchar_t* name; Sev sev; const wchar_t* action; };

static const std::vector<SvcTarget> g_svcTargets = {
    { L"DiagTrack",        SV_HIGH, L"Disable: sc.exe config DiagTrack start= disabled" },
    { L"dmwappushservice", SV_HIGH, L"Disable: sc.exe config dmwappushservice start= disabled" },
    { L"CDPSvc",           SV_HIGH, L"Disable only if no MS account is used." },
    { L"CDPUserSvc",       SV_HIGH, L"Disable only if no MS account is used." },
    { L"OneSyncSvc",       SV_MED,  L"Disable to stop cloud sync." },
    { L"Wlidsvc",          SV_CRIT, L"Disable only after MSA credentials are removed." },
    { L"TokenBroker",      SV_HIGH, L"Disable after removing all credentials." },
    { L"XblAuthManager",   SV_LOW,  L"Disable if not using Xbox." },
    { L"XblGameSave",      SV_LOW,  L"Disable if not using Xbox." },
    { L"XboxGipSvc",       SV_LOW,  L"Disable if not using Xbox." },
    { L"XboxNetApiSvc",    SV_LOW,  L"Disable if not using Xbox." },
    { L"MapsBroker",       SV_MED,  L"Downloaded Maps. Safe to disable." },
    { L"WerSvc",           SV_MED,  L"Error reporting uploads. Disable." },
    { L"PcaSvc",           SV_MED,  L"Program Compatibility Assistant (telemetry). Disable." },
    { L"RetailDemo",       SV_LOW,  L"Retail demo service. Disable." },
    { L"WSearch",          SV_INFO, L"Windows Search indexer (weak privacy link)." },
    { L"DoSvc",            SV_LOW,  L"Delivery Optimization P2P uploads. Disable to stop seeding." },
};

static void ScanServicesWorker() {
    SetPhase(L"Services");
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { g_done++; return; }

    DWORD need = 0, ret = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        nullptr, 0, &need, &ret, &resume, nullptr);
    std::vector<BYTE> buf(need ? need : 1);
    auto* pSvc = (LPENUM_SERVICE_STATUS_PROCESSW)buf.data();

    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        buf.data(), need, &need, &ret, &resume, nullptr)) {
        for (DWORD i = 0; i < ret && !g_stop; i++) {
            g_scanCount++;
            std::wstring n = pSvc[i].lpServiceName;
            for (const auto& t : g_svcTargets) {
                if (_wcsicmp(n.c_str(), t.name) != 0) continue;
                Finding f;
                f.cat = CT_SVC; f.sev = t.sev;
                f.title = L"Tracking / identity service";
                f.path = n;
                f.value = (pSvc[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING)
                    ? L"RUNNING" : L"STOPPED";
                f.detail = pSvc[i].lpDisplayName ? pSvc[i].lpDisplayName : L"";
                f.action = t.action;
                f.delOk = true;
                f.delType = L"svc";
                Push(f);
                break;
            }
        }
    }
    CloseServiceHandle(scm);
    g_done++;
}

// =====================================================================
//  PROCESSES SCANNER
// =====================================================================
static const std::vector<std::pair<const wchar_t*, Sev>> g_procTargets = {
    { L"YourPhone",        SV_MED },
    { L"PhoneExperience",  SV_MED },
    { L"Widgets",          SV_MED },
    { L"WidgetService",    SV_MED },
    { L"Copilot",          SV_MED },
    { L"GameBar",          SV_LOW },
    { L"XboxGame",         SV_LOW },
    { L"Teams",            SV_MED },
    { L"OneDrive",         SV_LOW },
    { L"DiagTrack",        SV_HIGH },
    { L"CompatTelRunner",  SV_HIGH },
    { L"DeviceCensus",     SV_HIGH },
    { L"wsappx",           SV_MED },
    { L"SearchApp",        SV_LOW },
    { L"MicrosoftEdge",    SV_LOW },
};

static void ScanProcessesWorker() {
    SetPhase(L"Processes");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { g_done++; return; }
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (g_stop) break;
            g_scanCount++;
            std::wstring name = pe.szExeFile;
            for (const auto& t : g_procTargets) {
                if (name.find(t.first) == std::wstring::npos) continue;
                Finding f;
                f.cat = CT_PRC; f.sev = t.second;
                f.title = L"Privacy-relevant process";
                f.path = name;
                f.value = L"PID " + std::to_wstring(pe.th32ProcessID);
                f.detail = L"Currently running";
                f.action = L"Close it, or disable its parent service.";
                Push(f);
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    g_done++;
}

// =====================================================================
//  CREDENTIALS SCANNER
// =====================================================================
static void ScanCredentialsWorker() {
    SetPhase(L"Credentials");
    PCREDENTIALW* creds = nullptr;
    DWORD count = 0;
    if (CredEnumerateW(nullptr, 0, &count, &creds)) {
        for (DWORD i = 0; i < count && !g_stop; i++) {
            g_scanCount++;
            std::wstring target = creds[i]->TargetName ? creds[i]->TargetName : L"";
            std::wstring user = creds[i]->UserName ? creds[i]->UserName : L"";
            std::wstring low = target;
            std::transform(low.begin(), low.end(), low.begin(), towlower);

            bool hit =
                low.find(L"microsoftaccount") != std::wstring::npos ||
                low.find(L"virtualapp/didlogical") != std::wstring::npos ||
                low.find(L"windowslive") != std::wstring::npos ||
                low.find(L"snapshotencryption") != std::wstring::npos ||
                low.find(L"ss:") != std::wstring::npos ||
                low.find(L"live.com") != std::wstring::npos;

            if (hit) {
                CredRow r;
                r.target = target; r.user = user;
                r.persist = creds[i]->Persist;
                r.type = creds[i]->Type;
                { std::lock_guard<std::mutex> lk(g_mtx); g_creds.push_back(r); }

                Finding f;
                f.cat = CT_CRED; f.sev = SV_CRIT;
                f.title = L"Stored Microsoft identity credential";
                f.path = target;
                f.value = user;
                f.detail = L"Persist=" + std::to_wstring(creds[i]->Persist);
                f.action = L"Delete (press D in review, or A to delete all).";
                f.delOk = true;
                f.delType = L"cred";
                Push(f);
            }
        }
        CredFree(creds);
    }
    g_done++;
}

// =====================================================================
//  ACCOUNTS SCANNER
// =====================================================================
static void ScanAccountsWorker() {
    SetPhase(L"Accounts");
    LPUSER_INFO_0 buf = nullptr;
    DWORD read = 0, total = 0, resume = 0;
    if (NetUserEnum(nullptr, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&buf,
        MAX_PREFERRED_LENGTH, &read, &total, &resume) == NERR_Success) {
        for (DWORD i = 0; i < read; i++) {
            g_scanCount++;
            std::wstring user = buf[i].usri0_name;
            if (_wcsicmp(user.c_str(), L"Administrator") == 0 ||
                _wcsicmp(user.c_str(), L"Guest") == 0 ||
                _wcsicmp(user.c_str(), L"DefaultAccount") == 0 ||
                _wcsicmp(user.c_str(), L"WDAGUtilityAccount") == 0) continue;

            Finding f;
            f.cat = CT_ACCT; f.sev = SV_INFO;
            f.title = L"Local Windows account";
            f.path = user;
            f.value = L"Local user";
            f.detail = L"Verify this account is yours; remove unknown accounts.";
            f.action = L"net user <name> /delete   (only if unknown)";
            Push(f);
        }
        NetApiBufferFree(buf);
    }
    g_done++;
}

// =====================================================================
//  ONEDRIVE SCANNER
// =====================================================================
static void ScanOneDriveWorker() {
    SetPhase(L"OneDrive");
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\OneDrive",
        0, KEY_READ, &hk) == ERROR_SUCCESS) {
        g_scanCount++;
        DWORD nVal = 0;
        RegQueryInfoKeyW(hk, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            &nVal, nullptr, nullptr, nullptr, nullptr);
        if (nVal > 0) {
            Finding f;
            f.cat = CT_OD; f.sev = SV_MED;
            f.title = L"OneDrive is linked to this account";
            f.path = L"HKCU\\Software\\Microsoft\\OneDrive";
            f.value = std::to_wstring(nVal) + L" values";
            f.detail = L"OneDrive stores a per-device ID (ODC).";
            f.action = L"Tray OneDrive -> Settings -> Unlink this PC.";
            Push(f);
        }
        RegCloseKey(hk);
    }
    g_done++;
}

// =====================================================================
//  TASKS SCANNER
// =====================================================================
static const wchar_t* g_telemetryTasks[] = {
    L"\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
    L"\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
    L"\\Microsoft\\Windows\\Application Experience\\StartupAppTask",
    L"\\Microsoft\\Windows\\Autochk\\Proxy",
    L"\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
    L"\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
    L"\\Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",
    L"\\Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
    L"\\Microsoft\\Windows\\Feedback\\Siuf\\DmClient",
    L"\\Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload",
    L"\\Microsoft\\Windows\\Windows Error Reporting\\QueueReporting",
    L"\\Microsoft\\Windows\\CloudExperienceHost\\CreateObjectTask",
    L"\\Microsoft\\Windows\\PI\\Sqm-Tasks",
};

static void ScanTasksWorker() {
    SetPhase(L"Tasks");
    for (auto* t : g_telemetryTasks) {
        if (g_stop) break;
        g_scanCount++;
        std::wstring cmd = L"schtasks /Query /TN \"" + std::wstring(t) + L"\" >nul 2>&1";
        if (_wsystem(cmd.c_str()) == 0) {
            Finding f;
            f.cat = CT_TASK; f.sev = SV_HIGH;
            f.title = L"Telemetry / feedback scheduled task";
            f.path = t;
            f.value = L"Present";
            f.detail = L"Uploads telemetry data periodically";
            f.action = L"Disable: schtasks /Change /TN \"<name>\" /Disable";
            f.delOk = true;
            f.delType = L"task";
            Push(f);
        }
    }
    g_done++;
}

// =====================================================================
//  HOSTS SCANNER
// =====================================================================
static const char* g_hostsBegin = "# ==== ANTI PRIVACY BLOCK BEGIN ====";
static const char* g_hostsEnd = "# ==== ANTI PRIVACY BLOCK END ====";

static const char* g_blockedHosts[] = {
    "vortex.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "telemetry.microsoft.com",
    "watson.telemetry.microsoft.com",
    "settings-win.data.microsoft.com",
    "reports.wes.df.telemetry.microsoft.com",
    "services.wes.df.telemetry.microsoft.com",
    "sqm.df.telemetry.microsoft.com",
    "telemetry.urs.microsoft.com",
    "statsfe2.ws.microsoft.com",
    "compatexchange.cloudapp.net",
    "choice.microsoft.com",
    "df.telemetry.microsoft.com",
    "redir.metaservices.microsoft.com",
    "survey.watson.microsoft.com",
    "oca.telemetry.microsoft.com",
    "wes.df.telemetry.microsoft.com",
    "v10.events.data.microsoft.com",
    "v20.events.data.microsoft.com",
    "self.events.data.microsoft.com",
    "browser.events.data.microsoft.com",
    "mobile.events.data.microsoft.com",
    "pipe.aria.microsoft.com",
    "mobile.pipe.aria.microsoft.com",
    "browser.pipe.aria.microsoft.com",
    "feedback.windows.com",
    "feedback.microsoft-hohm.com",
    "feedback.search.microsoft.com",
    "watson.live.com",
};

static std::wstring GetHostsPath() {
    wchar_t buf[MAX_PATH] = { 0 };
    GetSystemDirectoryW(buf, MAX_PATH);
    return std::wstring(buf) + L"\\drivers\\etc\\hosts";
}

static std::string ReadFileA(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return {};
    DWORD size = GetFileSize(h, NULL);
    std::string buf;
    if (size > 0 && size < 4 * 1024 * 1024) {
        buf.resize(size);
        DWORD read = 0;
        if (!ReadFile(h, &buf[0], size, &read, NULL)) buf.clear();
        else buf.resize(read);
    }
    CloseHandle(h);
    return buf;
}

static bool WriteFileA(const std::wstring& path, const std::string& data) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &written, NULL);
    CloseHandle(h);
    return ok && written == (DWORD)data.size();
}

static void ScanHostsWorker() {
    SetPhase(L"Hosts");
    std::wstring path = GetHostsPath();
    std::string content = ReadFileA(path);
    g_scanCount++;
    bool blocked = content.find(g_hostsBegin) != std::string::npos;
    Finding f;
    f.cat = CT_HOST;
    f.sev = blocked ? SV_INFO : SV_HIGH;
    f.title = blocked
        ? L"Hosts file already blocks telemetry (good)"
        : L"Hosts file does NOT block telemetry domains";
    f.path = path;
    f.value = blocked ? L"BLOCKED" : L"UNBLOCKED";
    f.detail = blocked ? L"Upload channel to telemetry hosts is closed"
        : L"vortex / telemetry endpoints remain reachable";
    f.action = blocked ? L"Keep it as is."
        : L"Menu [3]: Apply privacy block.";
    Push(f);
    g_done++;
}

// =====================================================================
//  DELETE / DISABLE ACTIONS
// =====================================================================
static bool DeleteCredentialTyped(const std::wstring& target, DWORD type) {
    return CredDeleteW(target.c_str(), type, 0) != FALSE;
}

static bool DeleteCredential(const std::wstring& target) {
    bool ok = false;
    ok |= CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0) != FALSE;
    ok |= CredDeleteW(target.c_str(), CRED_TYPE_DOMAIN_PASSWORD, 0) != FALSE;
    ok |= CredDeleteW(target.c_str(), CRED_TYPE_DOMAIN_VISIBLE_PASSWORD, 0) != FALSE;
    return ok;
}

static bool ServiceExists(const std::wstring& name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, name.c_str(), SERVICE_QUERY_STATUS);
    bool exists = (svc != nullptr);
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return exists;
}

static bool DisableServiceIfExists(const std::wstring& name) {
    if (!ServiceExists(name)) return false;
    std::wstring cmd = L"sc.exe config \"" + name + L"\" start= disabled"
        L" >nul 2>&1 && sc.exe stop \"" + name + L"\" >nul 2>&1";
    return _wsystem(cmd.c_str()) == 0;
}

static bool DisableTaskIfExists(const std::wstring& task) {
    std::wstring query = L"schtasks /Query /TN \"" + task + L"\" >nul 2>&1";
    if (_wsystem(query.c_str()) != 0) return false;
    std::wstring cmd = L"schtasks /Change /TN \"" + task + L"\" /Disable >nul 2>&1";
    return _wsystem(cmd.c_str()) == 0;
}

static bool EnableTaskIfExists(const std::wstring& task) {
    std::wstring query = L"schtasks /Query /TN \"" + task + L"\" >nul 2>&1";
    if (_wsystem(query.c_str()) != 0) return false;
    std::wstring cmd = L"schtasks /Change /TN \"" + task + L"\" /Enable >nul 2>&1";
    return _wsystem(cmd.c_str()) == 0;
}

static void DeleteAllCredentials() {
    std::lock_guard<std::mutex> lk(g_mtx);
    for (const auto& c : g_creds) DeleteCredentialTyped(c.target, c.type);
}

// =====================================================================
//  DEVICE IDENTITY WIPE
// =====================================================================
static void WipeDeviceIdentities() {
    struct Scope { HKEY root; const wchar_t* prefix; };
    Scope scopes[] = {
        { HKEY_USERS,         L".DEFAULT\\Software\\Microsoft\\IdentityCRL\\DeviceIdentities\\production" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\IdentityCRL\\DeviceIdentities\\production" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\IdentityCRL\\DeviceIdentities\\production" },
    };

    for (const auto& sc : scopes) {
        HKEY hkProd = nullptr;
        REGSAM sam = KEY_READ | KEY_WOW64_64KEY;
        if (RegOpenKeyExW(sc.root, sc.prefix, 0, sam, &hkProd) != ERROR_SUCCESS)
            continue;

        DWORD nSub = 0;
        RegQueryInfoKeyW(hkProd, nullptr, nullptr, nullptr, &nSub,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD i = 0; i < nSub; ++i) {
            wchar_t sid[256] = { 0 };
            DWORD sidLen = 256;
            if (RegEnumKeyExW(hkProd, i, sid, &sidLen, nullptr,
                nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;
            if (_wcsicmp(sid, L"Logs") == 0) continue;

            std::wstring sidPath = std::wstring(sc.prefix) + L"\\" + sid;
            HKEY hkSid = nullptr;
            if (RegOpenKeyExW(sc.root, sidPath.c_str(), 0, sam, &hkSid) != ERROR_SUCCESS)
                continue;

            RegDeleteValueIfExists(sc.root, sidPath, L"ValidDeviceId");

            DWORD nDev = 0;
            RegQueryInfoKeyW(hkSid, nullptr, nullptr, nullptr, &nDev,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

            for (DWORD j = 0; j < nDev; ++j) {
                wchar_t dev[256] = { 0 };
                DWORD devLen = 256;
                if (RegEnumKeyExW(hkSid, j, dev, &devLen, nullptr,
                    nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    continue;
                std::wstring devPath = sidPath + L"\\" + dev;
                RegDeleteTreeIfExists(sc.root, devPath);
            }
            RegCloseKey(hkSid);
        }
        RegCloseKey(hkProd);
    }
}

// =====================================================================
//  PRIVACY POLICIES
// =====================================================================
static int ApplyPrivacyPolicies() {
    int ok = 0;
    ok += RegCreatePolicyValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
        L"AllowTelemetry", 0);
    ok += RegCreatePolicyValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
        L"DoNotShowFeedbackNotifications", 1);
    ok += RegCreatePolicyValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        L"EnableActivityFeed", 0);
    ok += RegCreatePolicyValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        L"PublishUserActivities", 0);
    ok += RegCreatePolicyValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        L"UploadUserActivities", 0);
    ok += RegCreatePolicyValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
        L"DisableWindowsConsumerFeatures", 1);
    ok += RegCreatePolicyValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors",
        L"DisableLocation", 1);
    ok += RegCreatePolicyValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
        L"AllowCortana", 0);
    ok += RegCreatePolicyValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
        L"DisableWebSearch", 1);
    ok += RegCreatePolicyValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
        L"ConnectedSearchUseWeb", 0);
    ok += RegCreatePolicyValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive",
        L"DisableFileSyncNGSC", 1);

    RegValueIfKeyExists(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection",
        L"AllowTelemetry", 0);

    RegCreatePolicyValue(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
        L"Enabled", 0);
    RegCreatePolicyValue(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
        L"DisabledByGroupPolicy", 1);
    RegCreatePolicyValue(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Clipboard",
        L"EnableCloudClipboard", 0);
    RegCreatePolicyValue(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Input\\Settings",
        L"CloudCandidateEnabled", 0);
    RegCreatePolicyValue(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\InputPersonalization",
        L"RestrictImplicitTextCollection", 1);
    RegCreatePolicyValue(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\InputPersonalization",
        L"RestrictImplicitInkCollection", 1);
    RegCreatePolicyValue(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Speech_OneCore\\Settings\\OnlineSpeechPrivacy",
        L"HasAccepted", 0);
    RegCreatePolicyValue(HKEY_CURRENT_USER,
        L"Software\\Policies\\Microsoft\\Windows\\WindowsCopilot",
        L"TurnOffWindowsCopilot", 1);
    RegCreatePolicyValue(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Siuf\\Rules",
        L"NumberOfSIUFInPeriod", 0);

    RegDeleteValueIfExists(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Id");
    RegDeleteValueIfExists(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId");
    RegDeleteValueIfExists(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\DeveloperTools", L"deviceid");
    RegDeleteValueIfExists(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\IdentityCRL\\ExtendedProperties", L"LID");

    WipeDeviceIdentities();
    return ok;
}

static void RemovePrivacyPolicies() {
    RegDeleteTreeIfExists(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection");
    RegDeleteTreeIfExists(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent");
    RegDeleteTreeIfExists(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search");
    RegDeleteValueIfExists(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"EnableActivityFeed");
    RegDeleteValueIfExists(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"PublishUserActivities");
    RegDeleteValueIfExists(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"UploadUserActivities");
    RegDeleteTreeIfExists(HKEY_CURRENT_USER,
        L"Software\\Policies\\Microsoft\\Windows\\WindowsCopilot");
    RegDeleteValueIfExists(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection",
        L"AllowTelemetry");
}

// =====================================================================
//  HOSTS BLOCK / UNBLOCK
// =====================================================================
static bool ApplyHostsBlock() {
    std::wstring path = GetHostsPath();
    std::string content = ReadFileA(path);

    size_t b = content.find(g_hostsBegin);
    size_t e = content.find(g_hostsEnd);
    if (b != std::string::npos && e != std::string::npos && e > b) {
        e += strlen(g_hostsEnd);
        content.erase(b, e - b);
    }

    std::string block = std::string("\r\n") + g_hostsBegin + "\r\n";
    for (auto* h : g_blockedHosts) {
        block += "0.0.0.0 ";
        block += h;
        block += "\r\n";
        block += ":: ";
        block += h;
        block += "\r\n";
    }
    block += std::string(g_hostsEnd) + "\r\n";

    content += block;
    return WriteFileA(path, content);
}

static bool RemoveHostsBlock() {
    std::wstring path = GetHostsPath();
    std::string content = ReadFileA(path);
    size_t b = content.find(g_hostsBegin);
    size_t e = content.find(g_hostsEnd);
    if (b == std::string::npos || e == std::string::npos || e <= b) return true;
    e += strlen(g_hostsEnd);
    content.erase(b, e - b);
    return WriteFileA(path, content);
}

// =====================================================================
//  EXTERNAL TOOL MANAGEMENT
// =====================================================================
static bool DirectoryExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

static bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

static bool EnsureDirectory(const std::wstring& path) {
    if (DirectoryExists(path)) return true;
    return CreateDirectoryW(path.c_str(), NULL) != FALSE ||
        GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool IsGitAvailable() {
    return _wsystem(L"git --version >nul 2>&1") == 0;
}

static bool CloneTool(const ExtTool& tool) {
    std::wstring dir = g_toolsDir + L"\\" + tool.name;
    if (DirectoryExists(dir)) return true; // already cloned

    std::wstring cmd = L"git clone --depth 1 \"" + std::wstring(tool.repo) +
        L"\" \"" + dir + L"\" >nul 2>&1";
    return _wsystem(cmd.c_str()) == 0;
}

static void CloneAllTools() {
    ClearScreen();
    SetColor(C_CYAN);
    GotoXY(2, 1); WOut(L"+----------------------------------------------------------------------+");
    GotoXY(2, 2); WOut(L"|  Cloning external privacy tools from GitHub...                      |");
    GotoXY(2, 3); WOut(L"+----------------------------------------------------------------------+");
    SetColor(C_DEF);

    if (!IsGitAvailable()) {
        GotoXY(4, 5); SetColor(C_RED);
        WOut(L"Git is not installed. Install from https://git-scm.com/download/win");
        GotoXY(4, 7); SetColor(C_WHITE);
        WOut(L"Press any key...");
        _getwch();
        return;
    }

    EnsureDirectory(g_toolsDir);

    int y = 5;
    int okCount = 0;
    for (size_t i = 0; i < g_extTools.size(); i++) {
        const auto& t = g_extTools[i];
        GotoXY(4, y);
        SetColor(C_WHITE);
        WOut(std::to_wstring(i + 1) + L"/" + std::to_wstring(g_extTools.size()) +
            L"  " + t.name + (t.recommended ? L"  [RECOMMENDED]" : L""));

        GotoXY(4, y + 1);
        bool ok = CloneTool(t);
        if (ok) {
            SetColor(C_GREEN);
            WOut(L"     OK");
            okCount++;
        }
        else {
            SetColor(C_YEL);
            WOut(L"     SKIP (already exists or clone failed)");
        }
        y += 2;

        if (y > 24) break;
    }

    GotoXY(4, y + 2); SetColor(C_GREEN);
    WOut(L"Done: " + std::to_wstring(okCount) + L"/" +
        std::to_wstring(g_extTools.size()) + L" tools available in " + g_toolsDir);
    GotoXY(4, y + 4); SetColor(C_WHITE);
    WOut(L"Press any key...");
    _getwch();
}

static void RunToolScript(const ExtTool& tool) {
    std::wstring dir = g_toolsDir + L"\\" + tool.name;

    if (!DirectoryExists(dir)) {
        ClearScreen();
        SetColor(C_RED);
        GotoXY(4, 5);
        WOut(L"Tool not cloned yet. Run [7] CLONE first.");
        GotoXY(4, 7); SetColor(C_WHITE);
        WOut(L"Press any key...");
        _getwch();
        return;
    }

    // Try to find the main script
    std::wstring scriptPath;
    if (tool.script && wcslen(tool.script) > 0) {
        scriptPath = dir + L"\\" + tool.script;
    }

    if (FileExists(scriptPath)) {
        std::wstring ext = scriptPath.substr(scriptPath.find_last_of(L'.'));
        std::wstring cmd;

        if (ext == L".ps1") {
            cmd = L"powershell.exe -ExecutionPolicy Bypass -NoProfile -File \"" +
                scriptPath + L"\"";
        }
        else if (ext == L".bat" || ext == L".cmd") {
            cmd = L"cmd.exe /c \"" + scriptPath + L"\"";
        }
        else {
            cmd = L"\"" + scriptPath + L"\"";
        }

        ClearScreen();
        SetColor(C_YEL);
        GotoXY(4, 5);
        WOut(L"Launching " + std::wstring(tool.name) + L"...");
        GotoXY(4, 7); SetColor(C_GRAY);
        WOut(L"Command: " + Fmt(cmd, 70));
        GotoXY(4, 9); SetColor(C_WHITE);
        WOut(L"Press any key to execute...");
        _getwch();

        _wsystem(cmd.c_str());

        GotoXY(4, 11); SetColor(C_GREEN);
        WOut(L"Tool finished. Press any key...");
        _getwch();
    }
    else {
        // No script found, just open the folder
        std::wstring cmd = L"explorer.exe \"" + dir + L"\"";
        _wsystem(cmd.c_str());
    }
}

static void ShowExternalTools() {
    ClearScreen();
    Banner();

    GotoXY(2, 5); SetColor(C_WHITE);
    WOut(L"External Privacy Tools (" + std::to_wstring(g_extTools.size()) + L" projects)");
    GotoXY(2, 6); SetColor(C_GRAY);
    WOut(L"Press [C] to clone all, [1-15] to run a specific tool, [Q] to go back");

    int y = 8;
    for (size_t i = 0; i < g_extTools.size(); i++) {
        const auto& t = g_extTools[i];
        std::wstring dir = g_toolsDir + L"\\" + t.name;
        bool cloned = DirectoryExists(dir);

        GotoXY(2, y);
        SetColor(C_YEL);
        WOut(L"[" + std::to_wstring(i + 1) + L"] ");
        SetColor(cloned ? C_GREEN : C_GRAY);
        WOut(cloned ? L"[+] " : L"[ ] ");
        SetColor(C_WHITE);
        WOut(t.name);
        if (t.recommended) {
            SetColor(C_MAG);
            WOut(L"  *RECOMMENDED*");
        }
        y++;

        GotoXY(6, y); SetColor(C_GRAY);
        WOut(t.desc);
        y += 2;

        if (y > 22) break;
    }

    GotoXY(2, y + 1); SetColor(C_WHITE);
    WOut(L"> ");
    wchar_t ch = (wchar_t)_getwch();
    if (ch >= L'A' && ch <= L'Z') ch = (wchar_t)(ch + 32);

    if (ch == L'c') {
        CloneAllTools();
    }
    else if (ch >= L'1' && ch <= L'9') {
        int idx = ch - L'1';
        if (idx < (int)g_extTools.size())
            RunToolScript(g_extTools[idx]);
    }
    else if (ch == L'0' && g_extTools.size() >= 10) {
        RunToolScript(g_extTools[9]);
    }
    else if (ch == L'q' || ch == 27) {
        return;
    }
}

// =====================================================================
//  REAL-TIME MONITOR (WMI-based)
// =====================================================================
static std::atomic<bool> g_threatDetected{ false };

// Simple process watcher (polling-based, works without WMI)
static void MonitorProcesses() {
    std::set<DWORD> knownPids;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{ sizeof(pe) };
            if (Process32FirstW(snap, &pe)) {
                do { knownPids.insert(pe.th32ProcessID); } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }

    while (g_monitorRunning && !g_exitRequested) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;

        PROCESSENTRY32W pe{ sizeof(pe) };
        if (Process32FirstW(snap, &pe)) {
            do {
                if (knownPids.find(pe.th32ProcessID) != knownPids.end()) continue;
                knownPids.insert(pe.th32ProcessID);

                std::wstring name = pe.szExeFile;
                for (const auto& t : g_procTargets) {
                    if (name.find(t.first) == std::wstring::npos) continue;

                    // Threat detected - notify
                    std::wstring msg = L"Privacy process detected: " + name;
                    if (g_hWnd) {
                        NOTIFYICONDATAW nid{};
                        nid.cbSize = sizeof(nid);
                        nid.hWnd = g_hWnd;
                        nid.uID = 1;
                        nid.uFlags = NIF_INFO;
                        nid.dwInfoFlags = NIIF_WARNING;
                        wcscpy_s(nid.szInfoTitle, L"ANTI Monitor");
                        wcsncpy_s(nid.szInfo, msg.c_str(), _TRUNCATE);
                        Shell_NotifyIconW(NIM_MODIFY, &nid);
                    }
                    g_threatDetected = true;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);

        // Trim knownPids to avoid unbounded growth
        if (knownPids.size() > 10000) {
            knownPids.clear();
            // Rebuild
            snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                if (Process32FirstW(snap, &pe)) {
                    do { knownPids.insert(pe.th32ProcessID); } while (Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }
        }
    }
}

// Registry watcher (polling-based)
static void MonitorRegistry() {
    // Watch for changes in key identity locations
    const wchar_t* watchPaths[] = {
        L"Software\\Microsoft\\IdentityCRL\\ExtendedProperties",
        L"Software\\Microsoft\\IdentityCRL\\Immediate\\production\\Property",
        L"Software\\Microsoft\\SQMClient",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
    };
    const wchar_t* watchValues[] = {
        L"LID", L"DeviceId", L"MachineId", L"Id"
    };

    while (g_monitorRunning && !g_exitRequested) {
        std::this_thread::sleep_for(std::chrono::seconds(10));

        for (size_t i = 0; i < ARRAY_SIZE(watchPaths); i++) {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, watchPaths[i], 0, KEY_READ, &hk) != ERROR_SUCCESS)
                continue;

            for (size_t j = 0; j < ARRAY_SIZE(watchValues); j++) {
                wchar_t buf[512] = { 0 };
                DWORD sz = sizeof(buf);
                DWORD type = 0;
                if (RegQueryValueExW(hk, watchValues[j], NULL, &type, (LPBYTE)buf, &sz) == ERROR_SUCCESS) {
                    // Value exists and was created/changed
                    if (g_hWnd) {
                        std::wstring msg = L"Registry identity value detected: " + std::wstring(watchValues[j]);
                        NOTIFYICONDATAW nid{};
                        nid.cbSize = sizeof(nid);
                        nid.hWnd = g_hWnd;
                        nid.uID = 1;
                        nid.uFlags = NIF_INFO;
                        nid.dwInfoFlags = NIIF_WARNING;
                        wcscpy_s(nid.szInfoTitle, L"ANTI Monitor");
                        wcsncpy_s(nid.szInfo, msg.c_str(), _TRUNCATE);
                        Shell_NotifyIconW(NIM_MODIFY, &nid);
                    }
                    g_threatDetected = true;
                }
            }
            RegCloseKey(hk);
        }
    }
}

static void StartMonitoring() {
    if (g_monitorRunning) return;
    g_monitorRunning = true;
    g_threatDetected = false;

    std::thread t1(MonitorProcesses);
    t1.detach();

    std::thread t2(MonitorRegistry);
    t2.detach();
}

static void StopMonitoring() {
    g_monitorRunning = false;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

// =====================================================================
//  AUTO-START MANAGEMENT
// =====================================================================
static bool IsAutoStartEnabled() {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_READ, &hk) != ERROR_SUCCESS)
        return false;

    wchar_t buf[MAX_PATH] = { 0 };
    DWORD sz = sizeof(buf);
    LSTATUS r = RegQueryValueExW(hk, L"ANTI", NULL, NULL, (LPBYTE)buf, &sz);
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

static bool EnableAutoStart() {
    wchar_t exePath[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
        return false;

    std::wstring cmd = L"\"" + std::wstring(exePath) + L"\" --tray";
    LSTATUS r = RegSetValueExW(hk, L"ANTI", 0, REG_SZ,
        (const BYTE*)cmd.c_str(),
        (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

static bool DisableAutoStart() {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
        return false;

    LSTATUS r = RegDeleteValueW(hk, L"ANTI");
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

// =====================================================================
//  SYSTEM TRAY
// =====================================================================
static NOTIFYICONDATAW g_nid{};

static void InitTrayIcon(HWND hWnd) {
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hWnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wcscpy_s(g_nid.szTip, L"ANTI - Privacy Monitor");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static void RemoveTrayIcon() {
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

static void ShowTrayMenu(HWND hWnd) {
    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_SHOW, L"Show Console");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_SCAN, L"Quick Scan");
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_BLOCK, L"Apply Privacy Block");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_EXIT, L"Exit");

    SetForegroundWindow(hWnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
}

// =====================================================================
//  WINDOW PROCEDURE
// =====================================================================
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP) {
            ShowTrayMenu(hWnd);
        }
        else if (lParam == WM_LBUTTONDBLCLK) {
            ShowWindow(GetConsoleWindow(), SW_SHOW);
            ShowWindow(GetConsoleWindow(), SW_RESTORE);
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDM_TRAY_SHOW:
            ShowWindow(GetConsoleWindow(), SW_SHOW);
            ShowWindow(GetConsoleWindow(), SW_RESTORE);
            break;
        case IDM_TRAY_SCAN:
            // Quick scan in background - just notify
        {
            NOTIFYICONDATAW nid = g_nid;
            nid.uFlags = NIF_INFO;
            nid.dwInfoFlags = NIIF_INFO;
            wcscpy_s(nid.szInfoTitle, L"ANTI");
            wcscpy_s(nid.szInfo, L"Quick scan requested. Open console for details.");
            Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
        break;
        case IDM_TRAY_BLOCK:
            ApplyPrivacyPolicies();
            break;
        case IDM_TRAY_EXIT:
            g_exitRequested = true;
            g_monitorRunning = false;
            RemoveTrayIcon();
            PostQuitMessage(0);
            break;
        }
        return 0;

    case WM_TIMER:
        if (wParam == IDT_MONITOR) {
            // Periodic check - update tray tooltip
            if (g_threatDetected) {
                wcscpy_s(g_nid.szTip, L"ANTI - THREAT DETECTED!");
                Shell_NotifyIconW(NIM_MODIFY, &g_nid);
            }
        }
        return 0;

    case WM_DESTROY:
        RemoveTrayIcon();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static HWND CreateHiddenWindow(HINSTANCE hInst) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"ANTIHiddenWnd";
    RegisterClassExW(&wc);

    return CreateWindowExW(0, L"ANTIHiddenWnd", L"ANTI", 0,
        0, 0, 0, 0, NULL, NULL, hInst, NULL);
}

// =====================================================================
//  UI
// =====================================================================
static void Banner() {
    SetColor(C_CYAN);
    GotoXY(2, 1); WOut(L"+----------------------------------------------------------------------+");
    GotoXY(2, 2); WOut(L"|  ANTI v5.0 - Windows Privacy Toolkit  (Integrated Edition)           |");
    GotoXY(2, 3); WOut(L"|  Scan - Block - Remove - Monitor - Integrate                         |");
    GotoXY(2, 4); WOut(L"+----------------------------------------------------------------------+");
    SetColor(C_DEF);
}

static void DrawProgress(int y, int pct, const std::wstring& phase) {
    const int width = 40;
    int filled = pct * width / 100;
    GotoXY(4, y);
    SetColor(C_GRAY); WOut(L"[");
    SetColor(C_GREEN); WOut(std::wstring(filled, L'#'));
    SetColor(C_GRAY); WOut(std::wstring(width - filled, L'-'));
    WOut(L"] ");
    SetColor(C_YEL); WOut(std::to_wstring(pct) + L"%  ");
    SetColor(C_WHITE);
    WOut(L"Phase: " + Fmt(phase, 14) + L"  Items: " + std::to_wstring(g_scanCount.load()));
}

static void RunScan() {
    g_find.clear(); g_creds.clear();
    g_done = 0; g_stop = false; g_scanCount = 0;

    ClearScreen();
    Banner();
    HideCursor();

    std::thread t1(ScanRegistryWorker);
    std::thread t2(ScanServicesWorker);
    std::thread t3(ScanProcessesWorker);
    std::thread t4(ScanCredentialsWorker);
    std::thread t5(ScanAccountsWorker);
    std::thread t6(ScanOneDriveWorker);
    std::thread t7(ScanTasksWorker);
    std::thread t8(ScanHostsWorker);

    const int total = 8;
    while (g_done.load() < total) {
        int pct = (g_done.load() * 100) / total;
        DrawProgress(7, pct, GetPhase());

        GotoXY(4, 9); SetColor(C_GRAY);
        WOut(L"Live findings: ");
        SetColor(C_RED); WOut(std::to_wstring(g_find.size()));

        GotoXY(4, 10); SetColor(C_GRAY);
        WOut(L"Credentials:   ");
        SetColor(C_RED); WOut(std::to_wstring(g_creds.size()));

        GotoXY(4, 12); SetColor(C_YEL);
        WOut(L"Press ESC to stop early.");

        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        if (_kbhit()) {
            wchar_t c = (wchar_t)_getwch();
            if (c == 27) { g_stop = true; break; }
        }
    }
    g_stop = true;
    t1.join(); t2.join(); t3.join(); t4.join();
    t5.join(); t6.join(); t7.join(); t8.join();

    ClearScreen();
    Banner();
    GotoXY(4, 7); SetColor(C_GREEN);
    WOut(L"Scan complete.  Findings: " + std::to_wstring(g_find.size()) +
        L"   Credentials: " + std::to_wstring(g_creds.size()));
    GotoXY(4, 9); SetColor(C_WHITE);
    WOut(L"Press any key to review findings...");
    _getwch();
}

static void ReviewFindings() {
    if (g_find.empty()) {
        ClearScreen(); Banner();
        GotoXY(4, 7); SetColor(C_YEL);
        WOut(L"No findings. Run a scan first (Menu [1]).");
        GotoXY(4, 9); SetColor(C_WHITE);
        WOut(L"Press any key...");
        _getwch();
        return;
    }
    std::sort(g_find.begin(), g_find.end(),
        [](const Finding& a, const Finding& b) {
            if (a.sev != b.sev) return a.sev > b.sev;
            return a.cat < b.cat;
        });

    const size_t pageSize = 4;
    size_t page = 0;

    while (true) {
        size_t pages = (g_find.size() + pageSize - 1) / pageSize;
        if (pages == 0) pages = 1;
        if (page >= pages) page = pages - 1;

        ClearScreen();
        Banner();
        GotoXY(2, 5); SetColor(C_WHITE);
        WOut(L"Page " + std::to_wstring(page + 1) + L"/" + std::to_wstring(pages) +
            L"   [N]ext [P]rev [D]elete one [A]ll MSA creds [Q]uit   Total: " +
            std::to_wstring(g_find.size()));

        int y = 6;
        for (size_t i = page * pageSize;
            i < (std::min)((page + 1) * pageSize, g_find.size()); i++) {
            const auto& f = g_find[i];
            size_t local = i - page * pageSize + 1;

            GotoXY(2, y);
            SetColor(C_YEL); WOut(L"[" + std::to_wstring(local) + L"] ");
            SetColor(SevColor(f.sev)); WOut(SevTag(f.sev));
            WOut(L" ");
            SetColor(C_CYAN);
            WOut(L"[" + std::wstring(CatName(f.cat)) + L"] ");
            SetColor(C_WHITE);
            WOut(Fmt(f.title, 50));
            y++;

            GotoXY(6, y); SetColor(C_GRAY);
            WOut(L"Path : " + Fmt(f.path, 70)); y++;

            if (!f.value.empty()) {
                GotoXY(6, y); SetColor(C_GRAY);
                WOut(L"Value: " + Fmt(f.value, 70)); y++;
            }
            GotoXY(6, y); SetColor(C_MAG);
            WOut(L"Act  : " + Fmt(f.action, 70));
            y += 2;
        }

        GotoXY(2, y + 1); SetColor(C_WHITE); WOut(L"> ");
        wchar_t ch = (wchar_t)_getwch();
        if (ch >= L'A' && ch <= L'Z') ch = (wchar_t)(ch + 32);

        if (ch == L'q' || ch == 27) break;
        if (ch == L'n' && page + 1 < pages) page++;
        else if (ch == L'p' && page > 0) page--;
        else if (ch == L'd') {
            GotoXY(4, y + 1); SetColor(C_YEL);
            WOut(L"Delete item # (1-" + std::to_wstring(pageSize) + L", 0=cancel): ");
            std::wstring s = ReadLineW();
            int idx = _wtoi(s.c_str());
            if (idx >= 1 && idx <= (int)pageSize) {
                size_t gi = page * pageSize + (idx - 1);
                if (gi < g_find.size()) {
                    Finding& f = g_find[gi];
                    bool ok = false;
                    if (f.delType == L"reg")
                        ok = RegDeleteValueIfExists(f.hRoot, f.regPath, f.regValue);
                    else if (f.delType == L"cred")
                        ok = DeleteCredential(f.path);
                    else if (f.delType == L"svc")
                        ok = DisableServiceIfExists(f.path);
                    else if (f.delType == L"task")
                        ok = DisableTaskIfExists(f.path);

                    GotoXY(4, y + 2);
                    SetColor(ok ? C_GREEN : C_RED);
                    WOut(ok ? L"Deleted." : L"Failed or not supported.");
                    std::this_thread::sleep_for(std::chrono::milliseconds(900));
                    if (ok) g_find.erase(g_find.begin() + gi);
                }
            }
        }
        else if (ch == L'a') {
            GotoXY(4, y + 1); SetColor(C_YEL);
            WOut(L"Delete ALL detected MSA credentials? [y/N]: ");
            wchar_t c2 = (wchar_t)_getwch();
            if (c2 == L'y' || c2 == L'Y') {
                DeleteAllCredentials();
                GotoXY(4, y + 2); SetColor(C_GREEN);
                WOut(L"All detected MSA credentials deleted.");
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
        }
    }
}

static void ApplyBlock() {
    ClearScreen(); Banner();
    GotoXY(4, 6); SetColor(C_YEL);
    WOut(L"Applying privacy block...");
    int y = 8;

    GotoXY(4, y); SetColor(C_WHITE);
    WOut(L"[1/5] Blocking telemetry domains in hosts file...");
    bool hostsOk = ApplyHostsBlock();
    GotoXY(4, y + 1);
    SetColor(hostsOk ? C_GREEN : C_RED);
    WOut(hostsOk
        ? (L"      OK - " + std::to_wstring(ARRAY_SIZE(g_blockedHosts)) + L" domains blocked")
        : std::wstring(L"      FAILED - run as Administrator"));
    y += 3;

    GotoXY(4, y); SetColor(C_WHITE);
    WOut(L"[2/5] Disabling telemetry scheduled tasks...");
    int taskOk = 0, taskTotal = (int)ARRAY_SIZE(g_telemetryTasks);
    for (auto* t : g_telemetryTasks)
        if (DisableTaskIfExists(t)) taskOk++;
    GotoXY(4, y + 1); SetColor(taskOk > 0 ? C_GREEN : C_YEL);
    WOut(L"      " + std::to_wstring(taskOk) + L"/" + std::to_wstring(taskTotal) + L" tasks disabled");
    y += 3;

    GotoXY(4, y); SetColor(C_WHITE);
    WOut(L"[3/5] Applying privacy policies and wiping device identities...");
    int polOk = ApplyPrivacyPolicies();
    GotoXY(4, y + 1); SetColor(C_GREEN);
    WOut(L"      " + std::to_wstring(polOk) + L" policy values written");
    y += 3;

    GotoXY(4, y); SetColor(C_WHITE);
    WOut(L"[4/5] Disabling tracking services...");
    const wchar_t* svcs[] = {
        L"DiagTrack", L"dmwappushservice", L"CDPSvc", L"CDPUserSvc",
        L"OneSyncSvc", L"MapsBroker", L"WerSvc", L"PcaSvc", L"RetailDemo",
        L"XblAuthManager", L"XblGameSave", L"XboxGipSvc", L"XboxNetApiSvc",
        L"wlidsvc", L"TokenBroker"
    };
    int svcOk = 0;
    for (auto* s : svcs) if (DisableServiceIfExists(s)) svcOk++;
    GotoXY(4, y + 1); SetColor(svcOk > 0 ? C_GREEN : C_YEL);
    WOut(L"      " + std::to_wstring(svcOk) + L" services disabled");
    y += 3;

    GotoXY(4, y); SetColor(C_WHITE);
    WOut(L"[5/5] Enabling real-time monitoring...");
    StartMonitoring();
    GotoXY(4, y + 1); SetColor(C_GREEN);
    WOut(L"      Monitoring active (process + registry)");
    y += 3;

    GotoXY(4, y); SetColor(C_GREEN);
    WOut(L"Block applied.  Reboot for all changes to take effect.");
    GotoXY(4, y + 1); SetColor(C_WHITE);
    WOut(L"Press any key...");
    _getwch();
}

static void RemoveBlock() {
    ClearScreen(); Banner();
    GotoXY(4, 6); SetColor(C_YEL);
    WOut(L"Removing all ANTI-applied blocks...");
    int y = 8;

    GotoXY(4, y); SetColor(C_WHITE);
    WOut(L"[1/3] Removing hosts block...");
    bool ok = RemoveHostsBlock();
    GotoXY(4, y + 1); SetColor(ok ? C_GREEN : C_RED);
    WOut(ok ? L"      Done" : L"      Failed");
    y += 3;

    GotoXY(4, y); SetColor(C_WHITE);
    WOut(L"[2/3] Re-enabling telemetry scheduled tasks...");
    int n = 0;
    for (auto* t : g_telemetryTasks) if (EnableTaskIfExists(t)) n++;
    GotoXY(4, y + 1); SetColor(C_GREEN);
    WOut(L"      " + std::to_wstring(n) + L" tasks re-enabled");
    y += 3;

    GotoXY(4, y); SetColor(C_WHITE);
    WOut(L"[3/3] Removing privacy registry policies...");
    RemovePrivacyPolicies();
    GotoXY(4, y + 1); SetColor(C_GREEN);
    WOut(L"      Policies removed");

    GotoXY(4, y + 3); SetColor(C_WHITE);
    WOut(L"Press any key...");
    _getwch();
}

static void Export() {
    std::string out;
    out += "ANTI v5.0 Report\r\n================\r\n\r\n";
    out += "Findings: " + std::to_string(g_find.size()) + "\r\n";
    out += "Credentials: " + std::to_string(g_creds.size()) + "\r\n\r\n";

    auto ToUtf8 = [](const std::wstring& w) -> std::string {
        if (w.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
            NULL, 0, NULL, NULL);
        std::string s(len, 0);
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
            &s[0], len, NULL, NULL);
        return s;
        };

    for (const auto& f : g_find) {
        out += ToUtf8(std::wstring(SevTag(f.sev)) + L" [" + CatName(f.cat) + L"] " + f.title) + "\r\n";
        out += "  Path:   " + ToUtf8(f.path) + "\r\n";
        out += "  Value:  " + ToUtf8(f.value) + "\r\n";
        out += "  Detail: " + ToUtf8(f.detail) + "\r\n";
        out += "  Action: " + ToUtf8(f.action) + "\r\n\r\n";
    }
    out += "\r\n--- Stored MSA credentials ---\r\n";
    for (const auto& c : g_creds)
        out += ToUtf8(c.target + L"  (user=" + c.user + L")\r\n");

    out += "\r\n--- External tools ---\r\n";
    for (const auto& t : g_extTools) {
        std::wstring dir = g_toolsDir + L"\\" + t.name;
        out += ToUtf8(std::wstring(t.name) + L"  [" +
            (DirectoryExists(dir) ? L"CLONED" : L"NOT CLONED") + L"]\r\n");
    }

    std::wstring reportPath = g_exeDir + L"\\anti_report.txt";
    std::ofstream of(reportPath.c_str(), std::ios::binary);
    bool ok = false;
    if (of) { of.write(out.data(), out.size()); ok = true; of.close(); }

    ClearScreen(); Banner();
    GotoXY(4, 7);
    SetColor(ok ? C_GREEN : C_RED);
    WOut(ok ? (L"Exported to: " + reportPath) : std::wstring(L"Failed to write report"));
    GotoXY(4, 9); SetColor(C_WHITE);
    WOut(L"Press any key...");
    _getwch();
}

static void ShowAutoStartMenu() {
    ClearScreen(); Banner();
    GotoXY(4, 6); SetColor(C_WHITE);
    WOut(L"Auto-Start Settings");
    GotoXY(4, 8); SetColor(C_GRAY);
    WOut(L"Current status: ");
    bool enabled = IsAutoStartEnabled();
    SetColor(enabled ? C_GREEN : C_RED);
    WOut(enabled ? L"ENABLED" : L"DISABLED");
    GotoXY(4, 10); SetColor(C_WHITE);
    WOut(L"[1] Enable auto-start (runs on login, minimizes to tray)");
    GotoXY(4, 11); WOut(L"[2] Disable auto-start");
    GotoXY(4, 12); WOut(L"[0] Back");

    GotoXY(4, 14); SetColor(C_YEL); WOut(L"Select: ");
    wchar_t c = (wchar_t)_getwch();
    if (c == L'1') {
        bool ok = EnableAutoStart();
        GotoXY(4, 16); SetColor(ok ? C_GREEN : C_RED);
        WOut(ok ? L"Auto-start enabled." : L"Failed to enable auto-start.");
    }
    else if (c == L'2') {
        bool ok = DisableAutoStart();
        GotoXY(4, 16); SetColor(ok ? C_GREEN : C_RED);
        WOut(ok ? L"Auto-start disabled." : L"Failed to disable auto-start.");
    }
    else {
        return;
    }
    GotoXY(4, 18); SetColor(C_WHITE); WOut(L"Press any key...");
    _getwch();
}

static void ShowMenu() {
    ClearScreen();
    Banner();

    bool monitorActive = g_monitorRunning.load();
    bool autoStart = IsAutoStartEnabled();

    GotoXY(4, 6);  SetColor(C_WHITE);
    WOut(L"[1]  SCAN         Full privacy & identity scan");
    GotoXY(4, 7);  WOut(L"[2]  REVIEW       Browse findings, delete items");
    GotoXY(4, 8);  WOut(L"[3]  BLOCK        Apply hosts + tasks + policies + monitor");
    GotoXY(4, 9);  WOut(L"[4]  UNBLOCK      Remove all blocks");
    GotoXY(4, 10); WOut(L"[5]  WIPE         Delete all MSA credentials");
    GotoXY(4, 11); WOut(L"[6]  EXPORT       Write anti_report.txt");
    GotoXY(4, 12); WOut(L"[7]  TOOLS        External privacy tools (clone/run)");
    GotoXY(4, 13); WOut(L"[8]  MONITOR      Toggle real-time monitoring");
    GotoXY(4, 14); WOut(L"[9]  AUTOSTART    Configure boot persistence");
    GotoXY(4, 15); WOut(L"[0]  EXIT");

    GotoXY(4, 17); SetColor(C_GRAY);
    WOut(L"Monitor: ");
    SetColor(monitorActive ? C_GREEN : C_GRAY);
    WOut(monitorActive ? L"ACTIVE" : L"INACTIVE");
    WOut(L"   |   AutoStart: ");
    SetColor(autoStart ? C_GREEN : C_GRAY);
    WOut(autoStart ? L"ON" : L"OFF");
    WOut(L"   |   Tools dir: " + g_toolsDir);

    GotoXY(4, 19); SetColor(C_YEL);
    WOut(L"Select [0-9]: ");
    SetColor(C_WHITE);
}

// =====================================================================
//  TRAY MODE (background)
// =====================================================================
static void RunTrayMode() {
    // Start monitoring
    StartMonitoring();

    // Hide console window
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // Create hidden window for tray messages
    g_hWnd = CreateHiddenWindow(g_hInst);
    if (!g_hWnd) return;

    InitTrayIcon(g_hWnd);

    // Balloon notification
    NOTIFYICONDATAW nid = g_nid;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = NIIF_INFO;
    wcscpy_s(nid.szInfoTitle, L"ANTI Privacy Monitor");
    wcscpy_s(nid.szInfo, L"Running in background. Real-time monitoring active.");
    Shell_NotifyIconW(NIM_MODIFY, &nid);

    // Message loop
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
        if (g_exitRequested) break;
    }

    StopMonitoring();
    RemoveTrayIcon();
}

// =====================================================================
//  MAIN
// =====================================================================
int main(int argc, char* argv[]) {
    g_hInst = GetModuleHandleW(NULL);

    // Check for --tray argument (auto-start mode)
    bool trayMode = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tray") == 0) trayMode = true;
    }

    // Initialize paths
    {
        wchar_t exePath[MAX_PATH] = { 0 };
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        g_exeDir = exePath;
        size_t slash = g_exeDir.find_last_of(L"\\/");
        if (slash != std::wstring::npos) g_exeDir = g_exeDir.substr(0, slash);
        g_toolsDir = g_exeDir + L"\\tools";
    }

    // Auto-elevate
    EnsureElevatedAndWt();

    // Init console
    g_hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleW(L"ANTI v5.0 - Windows Privacy Toolkit");

    DWORD mode = 0;
    if (GetConsoleMode(g_hOut, &mode))
        SetConsoleMode(g_hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    // If tray mode, run background monitor
    if (trayMode) {
        RunTrayMode();
        return 0;
    }

    // Check admin
    if (!IsElevated()) {
        ClearScreen();
        SetColor(C_RED);
        WOut(L"[!] Not running as Administrator. Some actions will fail.\r\n\r\n");
        SetColor(C_DEF);
        WOut(L"Press any key to continue anyway...");
        _getwch();
    }

    // Main loop
    while (true) {
        ShowMenu();
        wchar_t c = (wchar_t)_getwch();

        if (c == L'1') RunScan();
        else if (c == L'2') ReviewFindings();
        else if (c == L'3') ApplyBlock();
        else if (c == L'4') RemoveBlock();
        else if (c == L'5') {
            DeleteAllCredentials();
            ClearScreen(); Banner();
            GotoXY(4, 7); SetColor(C_GREEN);
            WOut(L"All detected MSA credentials deleted.");
            GotoXY(4, 9); SetColor(C_WHITE);
            WOut(L"Press any key...");
            _getwch();
        }
        else if (c == L'6') Export();
        else if (c == L'7') ShowExternalTools();
        else if (c == L'8') {
            if (g_monitorRunning) {
                StopMonitoring();
            }
            else {
                StartMonitoring();
            }
        }
        else if (c == L'9') ShowAutoStartMenu();
        else if (c == L'0' || c == 27) break;
    }

    StopMonitoring();
    ShowCursor();
    return 0;
}
