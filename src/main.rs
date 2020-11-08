use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::ffi::{OsStr, OsString};
use std::os::windows::prelude::*;
use std::path::PathBuf;

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
    #[error("Unknown Major Function ({0})")]
    UnknownMajorFunction(u8),
    #[error("Invalid Message Filename Length ({0})")]
    InvalidMessageFileNameLength(usize),
    #[error("Invalid Image Filename Length ({0})")]
    InvalidImageFileNameLength(usize),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[repr(u8)]
enum MajorFunction {
    Create = bindings::MajorFunction_Create as u8,
    Read = bindings::MajorFunction_Read as u8,
    Write = bindings::MajorFunction_Write as u8,
}

impl TryFrom<u8> for MajorFunction {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            x if x == Self::Create as u8 => Ok(Self::Create),
            x if x == Self::Read as u8 => Ok(Self::Read),
            x if x == Self::Write as u8 => Ok(Self::Write),
            _ => Err(Error::UnknownMajorFunction(v)),
        }
    }
}

#[derive(Debug)]
enum Message {
    Empty,
    File {
        process_id: u32,
        major_function: MajorFunction,
        filename: PathBuf,
    },
    Process {
        process_id: u32,
        parent_id: u32,
        create: bool,
    },
    Image {
        process_id: u32,
        filename: PathBuf,
    },
}

impl TryFrom<bindings::Message> for Message {
    type Error = Error;
    fn try_from(m: bindings::Message) -> Result<Self> {
        match m.Kind {
            bindings::MessageKind_MessageKind_Invalid => Err(Error::InvalidMessageVariant),
            bindings::MessageKind_MessageKind_Empty => Ok(Message::Empty),
            bindings::MessageKind_MessageKind_File => {
                let f = unsafe { m.Data.File };
                let n = f.Attr.WideLength as usize;
                let buffer = f.Buffer;
                if n > buffer.len() {
                    Err(Error::InvalidMessageFileNameLength(n))
                } else {
                    let filename = OsString::from_wide(&buffer[..n]).into();
                    Ok(Message::File {
                        process_id: f.Attr.ProcessId,
                        major_function: f.Attr.MajorFunction.try_into()?,
                        filename,
                    })
                }
            }
            bindings::MessageKind_MessageKind_Process => {
                let p = unsafe { m.Data.Process };
                Ok(Message::Process {
                    process_id: p.ProcessId,
                    parent_id: p.ParentId,
                    create: p.Create != 0,
                })
            }
            bindings::MessageKind_MessageKind_Image => {
                let f = unsafe { m.Data.Image };
                let n = f.Attr.WideLength as usize;
                if n == 0 {
                    Ok(Message::Image {
                        process_id: f.Attr.ProcessId,
                        filename: PathBuf::new(),
                    })
                } else {
                    let buffer = f.Buffer;
                    if n > buffer.len() {
                        Err(Error::InvalidImageFileNameLength(n))
                    } else {
                        let filename = OsString::from_wide(&buffer[..n]).into();

                        Ok(Message::Image {
                            process_id: f.Attr.ProcessId,
                            filename,
                        })
                    }
                }
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

    fn get_message(&mut self) -> Result<Box<CompleteMessage>> {
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
            Ok(raw_message)
        } else {
            Err(Error::GetMessageError(result))
        }
    }
}

struct Filter {
    name: Vec<u16>,
}

impl Filter {
    #[allow(dead_code)]
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

#[derive(Debug, Default)]
struct ProcessMapValue {
    track: bool,
    parent_id: Option<u32>,
    process_name: Option<PathBuf>,
    filemap: HashMap<PathBuf, FileMapValue>,
}

#[derive(Debug, Default)]
struct FileMapValue {
    read: bool,
    write: bool,
}

fn worker(rcv: crossbeam::channel::Receiver<Box<CompleteMessage>>) {
    let mut map = HashMap::<u32, ProcessMapValue>::new();
    while let Ok(raw_message) = rcv.recv() {
        let message = match raw_message.message.try_into() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Error receiving message : {}", e);
                continue;
            }
        };
        match message {
            Message::File {
                process_id,
                major_function,
                filename,
            } => {
                // println!(
                //     "File {:?} : process_id={:5} filename={}",
                //     major_function, process_id, filename
                // );
                match map.get_mut(&process_id) {
                    Some(ProcessMapValue { filemap, .. }) => {
                        let mut entry = filemap.entry(filename).or_default();
                        match major_function {
                            MajorFunction::Read => (entry.read = true),
                            MajorFunction::Write => (entry.write = true),
                            MajorFunction::Create => {}
                        }
                    }
                    None => {
                        // eprintln!(
                        //     "Process {} not found in map for file operation {}",
                        //     process_id, filename
                        // )
                    }
                }
            }
            Message::Process {
                process_id,
                parent_id,
                create,
            } => {
                println!(
                    "Process : parent_id={:5} process_id={:5} create={}",
                    process_id, parent_id, create
                );
                if create {
                    match map.insert(
                        process_id,
                        ProcessMapValue {
                            parent_id: Some(parent_id),
                            ..Default::default()
                        },
                    ) {
                        // Not sure if i shoudl replace the existing or not
                        Some(ProcessMapValue { parent_id, .. }) => eprintln!(
                            "Process {} already in map (Parent {:?})",
                            process_id, parent_id
                        ),
                        None => {}
                    }
                } else {
                    match map.remove(&process_id) {
                        Some(ProcessMapValue {
                            parent_id,
                            process_name,
                            filemap,
                            ..
                        }) => {
                            let parent_id = parent_id.map(|p| p as isize).unwrap_or(-1);
                            println!(
                                "Process {} finished (Parent {:?}) {:?}",
                                process_id, parent_id, process_name
                            );
                            let mut filenames: Vec<_> = filemap.keys().collect();
                            filenames.sort();
                            for filename in filenames {
                                let FileMapValue { read, write } = filemap.get(filename).unwrap();
                                if *read && *write {
                                    println!("IO : {}", filename.display());
                                } else if *read {
                                    println!("I  : {}", filename.display());
                                } else if *write {
                                    println!(" O : {}", filename.display());
                                } else {
                                    println!("   : {}", filename.display());
                                }
                            }
                        }
                        None => eprintln!("Process {} not found in map", process_id),
                    }
                }
            }
            Message::Image {
                process_id,
                filename,
            } => {
                // TODO This should check for exe
                let mut value = map.entry(process_id).or_insert(ProcessMapValue {
                    process_name: Some(filename.clone()),
                    ..Default::default()
                });
                if value.process_name.is_none() {
                    value.process_name = Some(filename)
                }
            }
            _ => println!("MSG : {:?}", message),
        }
    }
}

fn _main() -> Result<()> {
    // Needs SeLoadDriverPrivilege permission on account to use, which just admin doesn't seem to have
    // let _filter = Filter::load("fsfilter1")?;
    let mut port = Port::connect(r"\sdv_comms_port")?;
    let (snd, rcv) = crossbeam::channel::unbounded();
    let thread = std::thread::spawn(|| {
        worker(rcv);
    });
    loop {
        let message = port.get_message()?;
        if let Err(e) = snd.send(message) {
            eprintln!("Failed to send to worker thread : {} ", e);
            break;
        }
    }
    let _ = thread.join();
    Ok(())
}

fn main() {
    if let Err(e) = _main() {
        eprintln!("error : {}", e)
    }
}
