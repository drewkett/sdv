/*++

Module Name:

    FsFilter1.c

Abstract:

    This is the main module of the FsFilter1 miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = PTDBG_TRACE_ROUTINES;


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

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
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

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
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

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
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

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("FsFilter1!FsFilter1InstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("FsFilter1!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS
FsFilter1Unload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("FsFilter1!FsFilter1Unload: Entered\n") );

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

    UNREFERENCED_PARAMETER( FltObjects ); UNREFERENCED_PARAMETER( CompletionContext ); 

    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    FLT_FILE_NAME_OPTIONS Options = FLT_FILE_NAME_NORMALIZED 
      // Not Sure about this option
      // It says it will query if safe not sure the circumstances when its not safe
      | FLT_FILE_NAME_QUERY_DEFAULT;

    // For MajorFunction meaning look at https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_parameters
    // The value corresponds to the index into the union
    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilter1!Pre(Op=%d) Start Thread=%08x\n",
                    Data->Iopb->MajorFunction,
                    Data->Thread) );
    status = FltGetFileNameInformation( Data, Options, &FileNameInfo );
    if (NT_SUCCESS(status)) {
      PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                    ("FsFilter1!Pre(Op=%d): Name=%wZ\n",
                    Data->Iopb->MajorFunction,
                    FileNameInfo->Name) );
      FltReleaseFileNameInformation(FileNameInfo);
    } else {
      switch (status) {
        case STATUS_FLT_INVALID_NAME_REQUEST:
          PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                        ("FsFilter1!Pre(Op=%d): OpFltGetFileNameInformation Failed, STATUS_FLT_INVALID_NAME_REQUEST\n",
                          Data->Iopb->MajorFunction
                        ) );
          break;
        default:
          PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                        ("FsFilter1!Pre(Op=%d): FltGetFileNameInformation Failed, status=%08x\n",
                          Data->Iopb->MajorFunction,
                          status) );
      }
    }
    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilter1!Pre(Op=%d) End Thread=%08x\n",
                    Data->Iopb->MajorFunction,
                    Data->Thread) );

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
