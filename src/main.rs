use std::ffi::OsStr;

use thiserror::Error;
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror;
use winapi::um::fltuser;

#[derive(Debug, Error)]
enum Error {
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
struct Message {
    header: fltuser::FILTER_MESSAGE_HEADER,
    buffer: [u8; BUFFER_MSG_SIZE],
}

impl Message {
    fn empty() -> Self {
        Self {
            header: fltuser::FILTER_MESSAGE_HEADER {
                ReplyLength: 0,
                MessageId: 0,
            },
            buffer: [0; BUFFER_MSG_SIZE],
        }
    }

    fn as_header(&mut self) -> *mut fltuser::FILTER_MESSAGE_HEADER {
        self as *mut Self as *mut fltuser::FILTER_MESSAGE_HEADER
    }

    fn buffer(&self) -> Option<&[u8]> {
        if self.header.ReplyLength == 0 {
            None
        } else {
            let mut n = std::cmp::min(self.header.ReplyLength as usize, BUFFER_TOTAL_SIZE);
            n = std::cmp::max(n, std::mem::size_of::<fltuser::FILTER_MESSAGE_HEADER>());
            n -= std::mem::size_of::<fltuser::FILTER_MESSAGE_HEADER>();
            Some(&self.buffer[..n])
        }
    }
}

struct Port {
    handle: HANDLE,
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

fn _main() -> Result<()> {
    use bstr::ByteSlice;
    let mut port = Port::connect(r"\sdv_comms_port")?;
    loop {
        let message = port.get_message()?;
        match message.buffer() {
            Some(m) => println!("MSG: {}", m.as_bstr()),
            None => println!("EMPTY MSG"),
        }
    }
}

fn main() {
    if let Err(e) = _main() {
        eprintln!("error : {}", e)
    }
}
