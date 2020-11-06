/*++

Module Name:

    FsFilter1.c

Abstract:

    This is the main module of the FsFilter1 miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <ntstrsafe.h>
#include <dontuse.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#include "FsFilter1.h"

struct CompleteMessage {
    FILTER_MESSAGE_HEADER header;
    struct Message message;
};
static_assert (sizeof(struct CompleteMessage)  == MESSAGE_TOTAL_SIZE_WITH_HEADER, "CompleteMessage is wrong size");

PFLT_FILTER gFilterHandle;
PFLT_PORT gServerPort;
PFLT_PORT gClientPort;
LARGE_INTEGER PortTimeout = { .QuadPart = -100 };
// #define TRACK_THREADS
#define BUFFER_LENGTH (1024 - 96)

#define TRACE_FILENAMES            0x00000001
#define TRACE_INIT    0x00000002
#define TRACE_COMMS    0x00000004
#define TRACE_ERRORS    0x00000008
#define TRACE_THREADING            0x00000010
#define TRACE_PROC            0x00000020
#define TRACE_ALWAYS    0xFFFFFFFF

ULONG gTraceFlags = TRACE_INIT|TRACE_COMMS;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
FsFilter1InstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
FsFilter1InstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
FsFilter1InstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
FsFilter1Unload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
FsFilter1InstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );


EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsFilter1Unload)
#pragma alloc_text(PAGE, FsFilter1InstanceQueryTeardown)
#pragma alloc_text(PAGE, FsFilter1InstanceSetup)
#pragma alloc_text(PAGE, FsFilter1InstanceTeardownStart)
#pragma alloc_text(PAGE, FsFilter1InstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_READ,
      0,
      FsFilter1PreOperation,
      NULL },
    { IRP_MJ_WRITE,
      0,
      FsFilter1PreOperation,
      NULL },
    { IRP_MJ_CREATE,
      0,
      FsFilter1PreOperation,
      NULL },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    FsFilter1Unload,                           //  MiniFilterUnload

    FsFilter1InstanceSetup,                    //  InstanceSetup
    FsFilter1InstanceQueryTeardown,            //  InstanceQueryTeardown
    FsFilter1InstanceTeardownStart,            //  InstanceTeardownStart
    FsFilter1InstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
FsFilter1InstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( TRACE_INIT,
                  ("FsFilter1!FsFilter1InstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
FsFilter1InstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( TRACE_INIT,
                  ("FsFilter1!FsFilter1InstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
FsFilter1InstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( TRACE_INIT,
                  ("FsFilter1!FsFilter1InstanceTeardownStart: Entered\n") );
}


VOID
FsFilter1InstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( TRACE_INIT,
                  ("FsFilter1!FsFilter1InstanceTeardownComplete: Entered\n") );
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/
NTSTATUS PortConnectNotify (
      _In_ PFLT_PORT ClientPort,
      _In_ PVOID ServerPortCookie,
      _In_ PVOID ConnectionContext,
      _In_ ULONG SizeOfContext,
      _Out_ PVOID *ConnectionPortCookie
      )
{
    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext );
    UNREFERENCED_PARAMETER( ConnectionPortCookie );
    PT_DBG_PRINT( TRACE_COMMS,
                    ("FsFilter1!PortConnectNotify\n") );
    gClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID PortDisconnectNotify (
      _In_ PVOID ConnectionCookie
      )
{
    UNREFERENCED_PARAMETER( ConnectionCookie );
    PT_DBG_PRINT( TRACE_COMMS,
                    ("FsFilter1!PortDisconnectNotify\n") );
    FltCloseClientPort(gFilterHandle,&gClientPort);
}

void ProcessCreateCallback(
  _In_ HANDLE HParentId,
  _In_ HANDLE HProcessId,
  _In_ BOOLEAN Create
) {
    NTSTATUS status;
    struct Message message;
    unsigned long ProcessId = 0, ParentId = 0;
    ProcessId += (long long) HProcessId & 0xFFFFFFFF;
    ParentId += (long long) HParentId & 0xFFFFFFFF;

    PT_DBG_PRINT( TRACE_PROC,
                    ("FsFilter1!ProcessCreateCallback ParentId= %6d/%6d ProcessId=%6d/%6d Create=%d\n", HParentId, ParentId, HProcessId, ProcessId, Create) );

    if (gClientPort != NULL) {
        message.Kind = MessageKind_Process;

        message.Data.process.ProcessId = ProcessId;
        message.Data.process.ParentId = ParentId;
        message.Data.process.Create = Create;
        for (int i = 0; i < 3; i++) {
            status = FltSendMessage(
                gFilterHandle,
                &gClientPort,
                &message, // SenderBuffer
                MESSAGE_TOTAL_SIZE, // SenderBufferLength
                NULL, // ReplyBuffer
                0, // ReplyLength
                &PortTimeout // Timeout in 100 nanoseconds. Negative is a relative timeout
            );
            if (status == STATUS_THREAD_IS_TERMINATING) {
                PT_DBG_PRINT( TRACE_COMMS, (
                    "FsFilter1!ProcCreate: Failed to send message to client. Might retry (Thread is terminating)\n"
                ));
                // Retry if this error code is received
                continue;
            }
            break;
        }
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_THREAD_IS_TERMINATING) {
                PT_DBG_PRINT( TRACE_COMMS, (
                    "FsFilter1!ProcCreate: Failed to send message to client (Thread is terminating)\n"
                ));
            } else {
                PT_DBG_PRINT( TRACE_COMMS, (
                    "FsFilter1!ProcCreate: Failed to send message to client (0x%08x)\n",
                    status
                ));
            }
        }
    }
}


#ifdef TRACK_THREADS
void ThreadCreateCallback(
  _In_ HANDLE ProcessId,
  _In_ HANDLE ThreadId,
  _In_ BOOLEAN Create
) {
    PT_DBG_PRINT( TRACE_PROC,
                    ("FsFilter1!ThreadCreateCallback  ProcessId=%6d ThreadId= %6d Create=%d\n", ProcessId, ThreadId, Create) );
}
#endif

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    // TODO Not Sure if this should be on stack
    UNICODE_STRING port_name;
    OBJECT_ATTRIBUTES attrs;
    PSECURITY_DESCRIPTOR SecurityDescriptor;

    UNREFERENCED_PARAMETER( RegistryPath );
    PT_DBG_PRINT( TRACE_INIT,
                ("FsFilter1!DriverEntry: Entered\n") );

    status = RtlUnicodeStringInit(&port_name,L"\\sdv_comms_port\0");
    if (!NT_SUCCESS(status)) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error initializing port name ({})\n", status) );
        goto e_end;
    }

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error registering filter ({})\n", status) );
        goto e_end;
    }

    status = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error building security descriptor ({})\n", status) );
        goto e_filter;
    }

    InitializeObjectAttributes(
        &attrs,
        &port_name,
        OBJ_KERNEL_HANDLE,
        NULL, // RootDirectory (I think with leading '\' port name is full qualified)
        SecurityDescriptor // Security Descriptor (Not currently dealing with security)
    );

    status = FltCreateCommunicationPort(
        gFilterHandle,
        &gServerPort,
        &attrs,
        NULL, // ServerPortCookie
        &PortConnectNotify,
        &PortDisconnectNotify,
        NULL, // MessageNotifyCallback,
        1 // MaxConnections
    );
    FltFreeSecurityDescriptor(SecurityDescriptor);
    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error creating communication port ({})\n", status) );
        goto e_filter;
    }

    status = PsSetCreateProcessNotifyRoutine( ProcessCreateCallback, FALSE );
    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error registering process callback ({})\n", status) );
        goto e_port;
    }

#ifdef TRACK_THREADS
    status = PsSetCreateThreadNotifyRoutine( ThreadCreateCallback );
    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error registering thread callback ({})\n", status) );
        goto e_process;
    }
#endif

    status = FltStartFiltering( gFilterHandle );

    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error staring filter ({})\n", status) );
#ifdef TRACK_THREADS
        goto e_thread;
#else
        goto e_process;
#endif
    }

    return status;

#ifdef TRACk_THREADdd
e_thread: 
    status = PsRemoveCreateThreadNotifyRoutine( ThreadCreateCallback );
    if (!NT_SUCCESS (status) ) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                    ("FsFilter1!FsFilter1Unload: Failed to unregistrer thread create callback\n") );
    }
#endif

e_process:
    status = PsSetCreateProcessNotifyRoutine( ProcessCreateCallback, TRUE );
    if (!NT_SUCCESS (status) ) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                    ("FsFilter1!FsFilter1Unload: Failed to unregistrer process create callback\n") );
    }
e_port:
    FltCloseCommunicationPort( gServerPort );
e_filter:
    FltUnregisterFilter( gFilterHandle );
e_end:
    return status;
}

NTSTATUS
FsFilter1Unload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( TRACE_INIT,
                  ("FsFilter1!FsFilter1Unload: Entered\n") );

#ifdef TRACK_THREADS
    status = PsRemoveCreateThreadNotifyRoutine( ThreadCreateCallback );
    if (!NT_SUCCESS (status) ) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                    ("FsFilter1!FsFilter1Unload: Failed to unregistrer thread create callback\n") );
    }
#endif
    
    status = PsSetCreateProcessNotifyRoutine( ProcessCreateCallback, TRUE );
    if (!NT_SUCCESS (status) ) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                    ("FsFilter1!FsFilter1Unload: Failed to unregistrer process create callback\n") );
    }

    FltCloseCommunicationPort( gServerPort );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PEPROCESS pProcess;
    HANDLE ThreadId, ProcessId;
    struct Message message;
    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    FLT_FILE_NAME_OPTIONS Options;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext ); 

    Options = FLT_FILE_NAME_NORMALIZED 
        // Not Sure about this option
        // It says it will query if safe not sure the circumstances when its not safe
        | FLT_FILE_NAME_QUERY_DEFAULT;

    ThreadId    = PsGetThreadId(Data->Thread);
    // For MajorFunction meaning look at https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_parameters
    // The value corresponds to the index into the union
    PT_DBG_PRINT( TRACE_THREADING,
                  ("FsFilter1!Pre(Op=%d) Start ThreadId=%6d\n",
                    Data->Iopb->MajorFunction,
                    ThreadId) );
    status = FltGetFileNameInformation( Data, Options, &FileNameInfo );
    if (NT_SUCCESS(status)) {
        
        pProcess = IoThreadToProcess( Data->Thread );
        ProcessId = PsGetProcessId(pProcess);

        PT_DBG_PRINT( TRACE_FILENAMES,
                        ("FsFilter1!Pre(Op=%d): ThreadId=%6d ProcessId=%6d Name=%wZ\n",
                        Data->Iopb->MajorFunction,
                        ThreadId,
                        ProcessId,
                        FileNameInfo->Name) );
        if (gClientPort != NULL) {
            message.Kind = MessageKind_File;
            unsigned int n = min(FileNameInfo->Name.Length,MESSAGE_FILE_BUFFER_SIZE);
            message.Data.file.WideLength = (unsigned short) n / 2;
            errno_t err = memcpy_s(message.Data.file.Buffer, MESSAGE_FILE_BUFFER_SIZE, FileNameInfo->Name.Buffer, n);
            if (err == 0) {
                status = FltSendMessage(
                    gFilterHandle,
                    &gClientPort,
                    &message, // SenderBuffer
                    MESSAGE_TOTAL_SIZE, // SenderBufferLength
                    NULL, // ReplyBuffer
                    0, // ReplyLength
                    &PortTimeout // Timeout in 100 nanoseconds. Negative is a relative timeout
                );
                if (!NT_SUCCESS(status)) {
                    PT_DBG_PRINT( TRACE_COMMS,
                                    ("FsFilter1!Pre(Op=%d): Failed to send message to client (0x%08x)\n",
                                    Data->Iopb->MajorFunction,
                                    status
                                    ) );
                }
            } else {
                PT_DBG_PRINT( TRACE_ALWAYS,
                                ("FsFilter1!Pre(Op=%d): Failed to copy filename to message buffer (0x%08x)\n",
                                Data->Iopb->MajorFunction,
                                status
                                ) );

            }
        }
        FltReleaseFileNameInformation(FileNameInfo);
    } else {
        switch (status) {
            case STATUS_FLT_INVALID_NAME_REQUEST:
                PT_DBG_PRINT( TRACE_FILENAMES,
                                ("FsFilter1!Pre(Op=%d): OpFltGetFileNameInformation Failed, STATUS_FLT_INVALID_NAME_REQUEST\n",
                                Data->Iopb->MajorFunction
                                ) );
                break;
            default:
                PT_DBG_PRINT( TRACE_FILENAMES,
                                ("FsFilter1!Pre(Op=%d): FltGetFileNameInformation Failed, status=0x%08x\n",
                                Data->Iopb->MajorFunction,
                                status) );
        }
    }
    PT_DBG_PRINT( TRACE_THREADING,
        ("FsFilter1!Pre(Op=%d) End Thread=%p\n",
        Data->Iopb->MajorFunction,
        Data->Thread) );

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
