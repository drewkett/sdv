use std::ffi::OsStr;

use thiserror::Error;
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror;
use winapi::um::fltuser;

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
}

type Result<T> = std::result::Result<T, Error>;

const BUFFER_TOTAL_SIZE: usize = 1024;
const BUFFER_MSG_SIZE: usize =
    BUFFER_TOTAL_SIZE - std::mem::size_of::<fltuser::FILTER_MESSAGE_HEADER>();
const BUFFER_MSG_WSIZE: usize = BUFFER_MSG_SIZE / 2;
struct Message {
    header: fltuser::FILTER_MESSAGE_HEADER,
    buffer: [u16; BUFFER_MSG_WSIZE],
}

impl Message {
    fn empty() -> Self {
        Self {
            header: fltuser::FILTER_MESSAGE_HEADER {
                ReplyLength: 0,
                MessageId: 0,
            },
            buffer: [0; BUFFER_MSG_WSIZE],
        }
    }

    fn as_header(&mut self) -> *mut fltuser::FILTER_MESSAGE_HEADER {
        self as *mut Self as *mut fltuser::FILTER_MESSAGE_HEADER
    }

    fn buffer(&self) -> String {
        unsafe { widestring::U16CStr::from_ptr_str(self.buffer.as_ptr()) }.to_string_lossy()
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

    fn get_message(&mut self) -> Result<Box<Message>> {
        let mut message: Box<Message> = Box::new(Message::empty());
        let overlapped = std::ptr::null_mut();
        debug_assert!(std::mem::size_of::<Message>() < u32::MAX as usize);
        let result = unsafe {
            fltuser::FilterGetMessage(
                self.handle,
                message.as_header(),
                std::mem::size_of::<Message>() as u32,
                overlapped,
            )
        };
        if winerror::SUCCEEDED(result) {
            Ok(message)
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
        println!("MSG : {:?}", message.buffer());
    }
}

fn main() {
    if let Err(e) = _main() {
        eprintln!("error : {}", e)
    }
}
