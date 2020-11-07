use std::convert::TryFrom;
use std::ffi::OsStr;

use thiserror::Error;
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror;
use winapi::um::fltuser;

#[allow(non_snake_case)]
#[allow(dead_code)]
#[allow(non_upper_case_globals)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Debug, Error)]
enum Error {
    #[error("Failed to start filter (0x{0:x})")]
    FailedToStartFilter(i32),
    #[error("Insufficient Privileges (0x{0:x})")]
    InsufficientPrivileges(i32),
    #[error("Port Connection Error (0x{0:x})")]
    ConnectError(i32),
    #[error("Access Denied")]
    AccessDenied,
    #[error("Get Message Error (0x{0:x})")]
    GetMessageError(i32),
    #[error("Invalid Message Variant)")]
    InvalidMessageVariant,
    #[error("Unknown Message Variant ({0})")]
    UnknownMessageVariant(i32),
    #[error("Invalid Message Filename Length ({0})")]
    InvalidMessageFileNameLength(usize),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
enum Message {
    Empty,
    File(String),
    Process {
        process_id: u32,
        parent_id: u32,
        create: bool,
    },
}

impl TryFrom<bindings::Message> for Message {
    type Error = Error;
    fn try_from(m: bindings::Message) -> Result<Self> {
        match m.Kind {
            bindings::MessageKind_MessageKind_Invalid => Err(Error::InvalidMessageVariant),
            bindings::MessageKind_MessageKind_Empty => Ok(Message::Empty),
            bindings::MessageKind_MessageKind_File => {
                let f = unsafe { m.Data.file };
                let n = f.WideLength as usize;
                let buffer = f.Buffer;
                if n > buffer.len() {
                    Err(Error::InvalidMessageFileNameLength(n))
                } else {
                    let s = unsafe { widestring::U16Str::from_ptr(buffer.as_ptr(), n) }
                        .to_string_lossy();
                    Ok(Message::File(s))
                }
            }
            bindings::MessageKind_MessageKind_Process => {
                let p = unsafe { m.Data.process };
                Ok(Message::Process {
                    process_id: p.ProcessId,
                    parent_id: p.ParentId,
                    create: p.Create != 0,
                })
            }
            _ => Err(Error::UnknownMessageVariant(m.Kind)),
        }
    }
}

#[repr(C)]
struct CompleteMessage {
    header: fltuser::FILTER_MESSAGE_HEADER,
    message: bindings::Message,
}

#[test]
fn test_sizes() {
    assert_eq!(
        ::std::mem::size_of::<CompleteMessage>(),
        bindings::MESSAGE_TOTAL_SIZE_WITH_HEADER as usize,
        concat!("Size of: ", stringify!(CompleteMessage))
    );
}

impl CompleteMessage {
    fn as_header(&mut self) -> *mut fltuser::FILTER_MESSAGE_HEADER {
        self as *mut Self as *mut fltuser::FILTER_MESSAGE_HEADER
    }
}

struct Port {
    handle: HANDLE,
}

impl Drop for Port {
    fn drop(&mut self) {
        // unsafe {}
        let _res = unsafe { winapi::um::handleapi::CloseHandle(self.handle) };
    }
}

impl Port {
    fn connect(port_name: impl AsRef<OsStr>) -> Result<Self> {
        use std::os::windows::prelude::*;
        let port_name: Vec<_> = port_name.as_ref().encode_wide().chain(Some(0)).collect();
        // Not sure about this one
        let options = 0;
        let context = std::ptr::null();
        let context_size = 0;
        let security_attributes = std::ptr::null_mut();
        let mut handle = std::ptr::null_mut();
        let result = unsafe {
            fltuser::FilterConnectCommunicationPort(
                port_name.as_ptr(),
                options,
                context,
                context_size,
                security_attributes,
                &mut handle,
            )
        };
        if winerror::SUCCEEDED(result) {
            Ok(Self { handle })
        } else {
            match result {
                winerror::E_ACCESSDENIED => Err(Error::AccessDenied),
                _ => Err(Error::ConnectError(result)),
            }
        }
    }

    fn get_message(&mut self) -> Result<Message> {
        let mut raw_message: Box<CompleteMessage> = Box::new(unsafe { std::mem::zeroed() });
        let overlapped = std::ptr::null_mut();
        debug_assert!(std::mem::size_of::<Message>() < u32::MAX as usize);
        let result = unsafe {
            fltuser::FilterGetMessage(
                self.handle,
                raw_message.as_header(),
                std::mem::size_of::<CompleteMessage>() as u32,
                overlapped,
            )
        };
        if winerror::SUCCEEDED(result) {
            Message::try_from(raw_message.message)
        } else {
            Err(Error::GetMessageError(result))
        }
    }
}

struct Filter {
    name: Vec<u16>,
}

impl Filter {
    fn load(filter_name: impl AsRef<OsStr>) -> Result<Self> {
        use std::os::windows::prelude::*;
        let name: Vec<_> = filter_name.as_ref().encode_wide().chain(Some(0)).collect();
        let result = unsafe { fltuser::FilterLoad(name.as_ptr()) };
        if winerror::SUCCEEDED(result) {
            Ok(Self { name })
        } else {
            let code = winerror::HRESULT_CODE(result);
            match code as u32 {
                winerror::ERROR_PRIVILEGE_NOT_HELD => Err(Error::InsufficientPrivileges(result)),
                _ => Err(Error::FailedToStartFilter(result)),
            }
        }
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        // unsafe {}
        let _res = unsafe { fltuser::FilterUnload(self.name.as_ptr()) };
    }
}

fn _main() -> Result<()> {
    // Needs SeLoadDriverPrivilege permission on account to use, which just admin doesn't seem to have
    // let _filter = Filter::load("fsfilter1")?;
    let mut port = Port::connect(r"\sdv_comms_port")?;
    loop {
        let message = port.get_message()?;
        if let Message::Process {
            process_id,
            parent_id,
            create,
        } = message
        {
            println!(
                "Process : parent_id={:5} process_id={:5} create={}",
                process_id, parent_id, create
            );
        }
        // println!("MSG : {:?}", message);
    }
}

fn main() {
    if let Err(e) = _main() {
        eprintln!("error : {}", e)
    }
}
