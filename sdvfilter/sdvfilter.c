/*++

Module Name:

    sdvfilter.c

Abstract:

    This is the main module of the sdvfilter miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <ntstrsafe.h>
#include <dontuse.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#include "sdvfilter.h"

// This is struct used to pass data from mini-filter to rust code. The struct size is a fixed
// size of MESSAGE_WITH_HEADER_SIZE
struct MessageWithHeader {
    FILTER_MESSAGE_HEADER header;
    struct Message message;
};

// Assert to make sure the compiler calculates the struct message size to be the same as the 
// the defined constant in the header
static_assert (sizeof(struct MessageWithHeader)  == MESSAGE_WITH_HEADER_SIZE, "MessageWithHeader is wrong size");
// Asserts to validate user defined constants match those from win api
static_assert (IRP_MJ_CREATE  == MajorFunction_Create, "MajorFunction_Create is incorrect");
static_assert (IRP_MJ_CLOSE  == MajorFunction_Close, "MajorFunction_Close is incorrect");
static_assert (IRP_MJ_READ  == MajorFunction_Read, "MajorFunction_Read is incorrect");
static_assert (IRP_MJ_WRITE  == MajorFunction_Write, "MajorFunction_Write is incorrect");
static_assert (IRP_MJ_SET_INFORMATION  == MajorFunction_SetInfo, "MajorFunction_SetInfo is incorrect");
static_assert (IRP_MJ_CLEANUP  == MajorFunction_Cleanup, "MajorFunction_Cleanup is incorrect");

#define POOL_TAG 'FSTR'
PFLT_FILTER gFilterHandle;
PDEVICE_OBJECT gDeviceObject;
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

ULONG gTraceFlags = TRACE_INIT;


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
IoOperationCallback (
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

// Used when registering callback operations
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_READ,
      0,
      IoOperationCallback,
      NULL },
    { IRP_MJ_WRITE,
      0,
      IoOperationCallback,
      NULL },
    // { IRP_MJ_CREATE,
    //   0,
    //   IoOperationCallback,
    //   NULL },
    // { IRP_MJ_SET_INFORMATION,
    //   0,
    //   IoOperationCallback,
    //   NULL },
    // { IRP_MJ_CLOSE,
    //   0,
    //   IoOperationCallback,
    //   NULL },
    // { IRP_MJ_CLEANUP,
    //   0,
    //   IoOperationCallback,
    //   NULL },

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

struct WorkItemContext {
    struct Message Message;
    PIO_WORKITEM PWorkItem;
};

void WorkItemSendMessage(
    PDEVICE_OBJECT DeviceObject,
    PVOID PRawContext
)
{
    UNREFERENCED_PARAMETER( DeviceObject );
    struct WorkItemContext *PContext = (struct WorkItemContext*) PRawContext;
    NTSTATUS status;
    status = FltSendMessage(
        gFilterHandle,
        &gClientPort,
        &PContext->Message, // SenderBuffer
        MESSAGE_SIZE, // SenderBufferLength
        NULL, // ReplyBuffer
        0, // ReplyLength
        &PortTimeout // Timeout in 100 nanoseconds. Negative is a relative timeout
    );
    if (!NT_SUCCESS(status)) {
        PT_DBG_PRINT( TRACE_ALWAYS, (
            "FsFilter1!WorkItemSendMessage: Failed to send message to client (0x%08x)\n",
            status
        ));
    }
    IoFreeWorkItem(PContext->PWorkItem);
    ExFreePoolWithTag(PContext, POOL_TAG);
}

unsigned long IdFromHandle(HANDLE HId) 
{
    unsigned long Id = 0;
    Id += (long long) HId & 0xFFFFFFFF;
    return Id;
}

// This function is called at the start of a process. The pid of the process and its parent
// are sent to the userspace process
void ProcessCreateCallback(
    _In_ HANDLE HParentId,
    _In_ HANDLE HProcessId,
    _In_ BOOLEAN Create
) {
    NTSTATUS status;
    PIO_WORKITEM PWorkItem;
    struct WorkItemContext *PContext;
    unsigned long ProcessId = IdFromHandle(HProcessId);
    unsigned long ParentId = IdFromHandle(HParentId);

    PT_DBG_PRINT( TRACE_PROC,
                    ("FsFilter1!ProcessCreateCallback ParentId= %6d/%6d ProcessId=%6d/%6d Create=%d\n", HParentId, ParentId, HProcessId, ProcessId, Create) );

    if (gClientPort != NULL) {
        PContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct WorkItemContext), POOL_TAG);
        if (PContext == NULL) {
            PT_DBG_PRINT( TRACE_ALWAYS, (
                "FsFilter1!ProcCreate: Failed to alloc context\n"
            ));
            return;
        }
        PContext->Message.Kind = MessageKind_Process;

        PContext->Message.Data.Process.ProcessId = ProcessId;
        PContext->Message.Data.Process.ParentId = ParentId;
        PContext->Message.Data.Process.Create = Create;
        status = FltSendMessage(
            gFilterHandle,
            &gClientPort,
            PContext, // SenderBuffer
            MESSAGE_SIZE, // SenderBufferLength
            NULL, // ReplyBuffer
            0, // ReplyLength
            &PortTimeout // Timeout in 100 nanoseconds. Negative is a relative timeout
        );
        if (NT_SUCCESS(status)){
            ExFreePoolWithTag(PContext, POOL_TAG);
        } else {
            if (status == STATUS_THREAD_IS_TERMINATING) {
                PWorkItem = IoAllocateWorkItem(gDeviceObject);
                if (PWorkItem == NULL) {
                    PT_DBG_PRINT( TRACE_ALWAYS, (
                        "FsFilter1!ProcCreate: Failed to alloc work item after failing to send message to client (Thread is terminating)\n"
                    ));
                } else {
                    PContext->PWorkItem = PWorkItem;
                    IoQueueWorkItem(
                        PWorkItem,
                        &WorkItemSendMessage,
                        DelayedWorkQueue,
                        PContext
                    );
                    PT_DBG_PRINT( TRACE_COMMS, (
                        "FsFilter1!ProcCreate: Queued message for later\n"
                    ));
                }
            } else {
                PT_DBG_PRINT( TRACE_ALWAYS, (
                    "FsFilter1!ProcCreate: Failed to send message to client (0x%08x)\n",
                    status
                ));
            }
        }
    }
}

// This is called when a module is loaded associated which is typically the 
// executable file for a process
void ImageLoadCallback(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE HProcessId,
    _In_ PIMAGE_INFO ImageInfo
) {
    UNREFERENCED_PARAMETER( ImageInfo );
    NTSTATUS status;
    struct WorkItemContext *PContext;
    unsigned long ProcessId = IdFromHandle(HProcessId);

    PT_DBG_PRINT( TRACE_PROC, (
        "FsFilter1!ImageLoad: ProcessId=%6d/%6d ImageName=%wZ\n",
        HProcessId,
        ProcessId,
        FullImageName
    ));

    if (gClientPort != NULL) {
        PContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct WorkItemContext), POOL_TAG);
        if (PContext == NULL) {
            PT_DBG_PRINT( TRACE_ALWAYS, (
                "FsFilter1!ImageLoad: Failed to alloc context\n"
            ));
            return;
        }
        PContext->Message.Kind = MessageKind_Image;
        PContext->Message.Data.Image.Attr.ProcessId = ProcessId;
        errno_t err = 0;
        if (FullImageName != NULL) {
	    // Pass the full image name as windows WTF encoding
            unsigned int n = min(FullImageName->Length,MESSAGE_IMAGE_BUFFER_SIZE);
            PContext->Message.Data.Image.Attr.WideLength = (unsigned short) n / 2;
            err = memcpy_s(PContext->Message.Data.Image.Buffer, MESSAGE_IMAGE_BUFFER_SIZE, FullImageName->Buffer, n);
        } else {
            PContext->Message.Data.Image.Attr.WideLength = 0;
        }
        if (err == 0) {
            status = FltSendMessage(
                gFilterHandle,
                &gClientPort,
                PContext, // SenderBuffer
                MESSAGE_SIZE, // SenderBufferLength
                NULL, // ReplyBuffer
                0, // ReplyLength
                &PortTimeout // Timeout in 100 nanoseconds. Negative is a relative timeout
            );
            if (!NT_SUCCESS(status)) {
                PT_DBG_PRINT( TRACE_ALWAYS, (
                    "FsFilter1!ImageLoad: Failed to send message to client (0x%08x)\n",
                    status
                ));
            }
        } else {
            PT_DBG_PRINT( TRACE_ALWAYS, (
                "FsFilter1!ImageLoad: Failed to copy filename to message buffer (%d)\n",
                err
            ));

        }
        ExFreePoolWithTag(PContext, POOL_TAG);
    }
}



#ifdef TRACK_THREADS
void ThreadCreateCallback(
  _In_ HANDLE ProcessId,
  _In_ HANDLE ThreadId,
  _In_ BOOLEAN Create
) {
    PT_DBG_PRINT( TRACE_PROC, (
        "FsFilter1!ThreadCreateCallback  ProcessId=%6d ThreadId= %6d Create=%d\n",
        ProcessId,
        ThreadId,
        Create
    ) );
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

    status = IoCreateDevice(
        DriverObject,
        0, // This is probably wrong DeviceExtensionSize,
        NULL, // Device Name
        0x00000015, // FILE_DEVICE_NULL
        FILE_DEVICE_SECURE_OPEN, // DeviceCharacteristics
        FALSE,  // Exclusive?
        &gDeviceObject
    );
    if (!NT_SUCCESS(status)) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error creating device ({})\n", status) );
        goto e_end;
    }

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error registering filter ({})\n", status) );
        goto e_device;
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

    status = PsSetLoadImageNotifyRoutine( ImageLoadCallback );
    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error registering image load callback ({})\n", status) );
        goto e_process;
    }

#ifdef TRACK_THREADS
    status = PsSetCreateThreadNotifyRoutine( ThreadCreateCallback );
    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error registering thread callback ({})\n", status) );
        goto e_image;
    }
#endif

    status = FltStartFiltering( gFilterHandle );

    if (!NT_SUCCESS( status )) {
        PT_DBG_PRINT( TRACE_ALWAYS,
                        ("FsFilter1!DriverEntry: Error staring filter ({})\n", status) );
#ifdef TRACK_THREADS
        goto e_thread;
#else
        goto e_image;
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

e_image:
    status = PsRemoveLoadImageNotifyRoutine( ImageLoadCallback );
    if (!NT_SUCCESS (status) ) {
        PT_DBG_PRINT( TRACE_ALWAYS, (
            "FsFilter1!FsFilter1Unload: Failed to unregistrer image load callback\n"
        ));
    }
e_process:
    status = PsSetCreateProcessNotifyRoutine( ProcessCreateCallback, TRUE );
    if (!NT_SUCCESS (status) ) {
        PT_DBG_PRINT( TRACE_ALWAYS, (
            "FsFilter1!FsFilter1Unload: Failed to unregistrer process create callback\n"
        ));
    }
e_port:
    FltCloseCommunicationPort( gServerPort );
e_filter:
    FltUnregisterFilter( gFilterHandle );
e_device:
    IoDeleteDevice( gDeviceObject );
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

    status = PsRemoveLoadImageNotifyRoutine( ImageLoadCallback );
    if (!NT_SUCCESS (status) ) {
        PT_DBG_PRINT( TRACE_ALWAYS, (
            "FsFilter1!FsFilter1Unload: Failed to unregistrer image load callback\n"
        ));
    }
    
    status = PsSetCreateProcessNotifyRoutine( ProcessCreateCallback, TRUE );
    if (!NT_SUCCESS (status) ) {
        PT_DBG_PRINT( TRACE_ALWAYS, (
            "FsFilter1!FsFilter1Unload: Failed to unregistrer process create callback\n"
        ));
    }

    FltCloseCommunicationPort( gServerPort );

    FltUnregisterFilter( gFilterHandle );

    IoDeleteDevice( gDeviceObject );

    return STATUS_SUCCESS;
}


// This is the callback for I/O operations. This currently sends a message to user space
// with the operation type and the PID
FLT_PREOP_CALLBACK_STATUS
IoOperationCallback (
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
    PT_DBG_PRINT( TRACE_THREADING, (
        "FsFilter1!Pre(Op=%d) Start ThreadId=%6d\n",
        Data->Iopb->MajorFunction,
        ThreadId
    ));
    status = FltGetFileNameInformation( Data, Options, &FileNameInfo );
    if (NT_SUCCESS(status)) {
        
        pProcess = IoThreadToProcess( Data->Thread );
        ProcessId = PsGetProcessId(pProcess);

        PT_DBG_PRINT( TRACE_FILENAMES, (
            "FsFilter1!Pre(Op=%d): ThreadId=%6d ProcessId=%6d Name=%wZ\n",
            Data->Iopb->MajorFunction,
            ThreadId,
            ProcessId,
            FileNameInfo->Name
        ));
        if (gClientPort != NULL) {
            message.Kind = MessageKind_File;
            message.Data.File.Attr.ProcessId = IdFromHandle(ProcessId);
            message.Data.File.Attr.MajorFunction = Data->Iopb->MajorFunction;
            if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
            } else if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
            // } else if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
            //     message.Data.File.Attr.DeleteOnClose = (Data->Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE) != 0;
            // } else if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
            //     // Probably won't try to track deletions this way
            //     FILE_INFORMATION_CLASS Class = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
            //     if (Class == FileDispositionInformation ) {
            //         message.Data.File.Attr.DeleteOnClose = ((PFILE_DISPOSITION_INFORMATION) Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile;
            //     } else if (Class == FileDispositionInformationEx ){
            //         message.Data.File.Attr.DeleteOnClose = (((PFILE_DISPOSITION_INFORMATION_EX) Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->Flags & FILE_DISPOSITION_DELETE) != 0;
            //     } else {
            //         FltReleaseFileNameInformation(FileNameInfo);
            //         return FLT_PREOP_SUCCESS_NO_CALLBACK;
            //     }
            // } else if (Data->Iopb->MajorFunction == IRP_MJ_CLOSE) {
            // } else if (Data->Iopb->MajorFunction == IRP_MJ_CLEANUP) {
            } else {
                PT_DBG_PRINT( TRACE_ALWAYS, (
                    "FsFilter1!Pre(Op=%d): Unknown Major Function ThreadId=%6d ProcessId=%6d Name=%wZ\n",
                    Data->Iopb->MajorFunction,
                    ThreadId,
                    ProcessId,
                    FileNameInfo->Name
                ));
                FltReleaseFileNameInformation(FileNameInfo);
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
            unsigned int n = min(FileNameInfo->Name.Length,MESSAGE_FILE_BUFFER_SIZE);
            message.Data.File.Attr.WideLength = (unsigned short) n / 2;
            errno_t err = memcpy_s(message.Data.File.Buffer, MESSAGE_FILE_BUFFER_SIZE, FileNameInfo->Name.Buffer, n);
            if (err == 0) {
                status = FltSendMessage(
                    gFilterHandle,
                    &gClientPort,
                    &message, // SenderBuffer
                    MESSAGE_SIZE, // SenderBufferLength
                    NULL, // ReplyBuffer
                    0, // ReplyLength
                    &PortTimeout // Timeout in 100 nanoseconds. Negative is a relative timeout
                );
                if (!NT_SUCCESS(status)) {
                    PT_DBG_PRINT( TRACE_ALWAYS, (
                        "FsFilter1!Pre(Op=%d): Failed to send message to client (0x%08x)\n",
                        Data->Iopb->MajorFunction,
                        status
                    ));
                }
            } else {
                PT_DBG_PRINT( TRACE_ALWAYS, (
                    "FsFilter1!Pre(Op=%d): Failed to copy filename to message buffer (%d)\n",
                    Data->Iopb->MajorFunction,
                    err
                ));
            }
        }
        FltReleaseFileNameInformation(FileNameInfo);
    } else {
        switch (status) {
            case STATUS_FLT_INVALID_NAME_REQUEST:
                // FltGetFileNameInformation cannot get file name information in certain following circumstances. Seems 
                // safe to ignore this for now
                PT_DBG_PRINT( TRACE_FILENAMES, (
                    "FsFilter1!Pre(Op=%d): OpFltGetFileNameInformation Failed, STATUS_FLT_INVALID_NAME_REQUEST\n",
                    Data->Iopb->MajorFunction
                ) );
                break;
            default:
                PT_DBG_PRINT( TRACE_ALWAYS, (
                    "FsFilter1!Pre(Op=%d): FltGetFileNameInformation Failed, status=0x%08x\n",
                    Data->Iopb->MajorFunction,
                    status
                ));
        }
    }
    PT_DBG_PRINT( TRACE_THREADING, (
        "FsFilter1!Pre(Op=%d) End Thread=%p\n",
        Data->Iopb->MajorFunction,
        Data->Thread
    ));

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
