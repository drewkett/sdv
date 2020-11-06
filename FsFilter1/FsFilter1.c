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


PFLT_FILTER gFilterHandle;
PFLT_PORT gServerPort;
PFLT_PORT gClientPort;
LARGE_INTEGER PortTimeout = { .QuadPart = -100 };
#define BUFFER_LENGTH (1024 - 96)

#define TRACE_FILENAMES            0x00000001
#define TRACE_INIT    0x00000002
#define TRACE_COMMS    0x00000004
#define TRACE_ERRORS    0x00000008
#define TRACE_THREADING            0x00000010
#define TRACE_PROC            0x00000020
#define TRACE_ALWAYS    0xFFFFFFFF

ULONG gTraceFlags = TRACE_INIT|TRACE_COMMS|TRACE_PROC|TRACE_FILENAMES;


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
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
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
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
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
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
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
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
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
  _In_ HANDLE ParentId,
  _In_ HANDLE ProcessId,
  _In_ BOOLEAN Create
) {
    PT_DBG_PRINT( TRACE_PROC,
                    ("FsFilter1!ProcessCreateCallback ParentId= %6d ProcessId=%6d Create=%d\n", ParentId, ProcessId, Create) );
}


void ThreadCreateCallback(
  _In_ HANDLE ProcessId,
  _In_ HANDLE ThreadId,
  _In_ BOOLEAN Create
) {
    PT_DBG_PRINT( TRACE_PROC,
                    ("FsFilter1!ThreadCreateCallback  ProcessId=%6d ThreadId= %6d Create=%d\n", ProcessId, ThreadId, Create) );
}

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
        return status;
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

    status = PsSetCreateThreadNotifyRoutine( ThreadCreateCallback );
    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error registering thread callback ({})\n", status) );
        goto e_process;
    }

    status = FltStartFiltering( gFilterHandle );

    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error staring filter ({})\n", status) );
        goto e_thread;
    }

    return status;

e_thread: 
    status = PsRemoveCreateThreadNotifyRoutine( ThreadCreateCallback );
    if (!NT_SUCCESS (status) ) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                    ("FsFilter1!FsFilter1Unload: Failed to unregistrer thread create callback\n") );
    }
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

    status = PsRemoveCreateThreadNotifyRoutine( ThreadCreateCallback );
    if (!NT_SUCCESS (status) ) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                    ("FsFilter1!FsFilter1Unload: Failed to unregistrer thread create callback\n") );
    }
    
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
    unsigned char buffer[BUFFER_LENGTH];

    UNREFERENCED_PARAMETER( FltObjects ); UNREFERENCED_PARAMETER( CompletionContext ); 

    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    FLT_FILE_NAME_OPTIONS Options = FLT_FILE_NAME_NORMALIZED 
        // Not Sure about this option
        // It says it will query if safe not sure the circumstances when its not safe
        | FLT_FILE_NAME_QUERY_DEFAULT;

    HANDLE ThreadId    = PsGetThreadId(Data->Thread);
    // For MajorFunction meaning look at https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_parameters
    // The value corresponds to the index into the union
    PT_DBG_PRINT( TRACE_THREADING,
                  ("FsFilter1!Pre(Op=%d) Start ThreadId=%6d\n",
                    Data->Iopb->MajorFunction,
                    ThreadId) );
    status = FltGetFileNameInformation( Data, Options, &FileNameInfo );
    if (NT_SUCCESS(status)) {
        
        PEPROCESS objCurProcess = IoThreadToProcess( Data->Thread );
        HANDLE iCurProcID    = PsGetProcessId(objCurProcess);

        PT_DBG_PRINT( TRACE_FILENAMES,
                        ("FsFilter1!Pre(Op=%d): ThreadId=%6d ProcessId=%6d Name=%wZ\n",
                        Data->Iopb->MajorFunction,
                        ThreadId,
                        iCurProcID,
                        FileNameInfo->Name) );
        if (gClientPort != NULL) {
            status = RtlStringCbCopyUnicodeString((NTSTRSAFE_PWSTR) buffer,BUFFER_LENGTH,&FileNameInfo->Name);
            if (NT_SUCCESS(status)) {
                status = FltSendMessage(
                    gFilterHandle,
                    &gClientPort,
                    buffer, // SenderBuffer
                    BUFFER_LENGTH, // SenderBufferLength
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
