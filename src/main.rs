use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::ffi::{OsStr, OsString};
use std::os::windows::prelude::*;
use std::path::{Path, PathBuf};

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
    #[error("Invalid Message File Path Length ({0})")]
    InvalidMessageFilePathLength(usize),
    #[error("Invalid Image File Path Length ({0})")]
    InvalidImageFilePathLength(usize),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[repr(u8)]
enum MajorFunction {
    Create = bindings::MajorFunction_Create as u8,
    Read = bindings::MajorFunction_Read as u8,
    Write = bindings::MajorFunction_Write as u8,
    SetInfo = bindings::MajorFunction_SetInfo as u8,
    Close = bindings::MajorFunction_Close as u8,
    Cleanup = bindings::MajorFunction_Cleanup as u8,
}

impl TryFrom<u8> for MajorFunction {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            x if x == Self::Create as u8 => Ok(Self::Create),
            x if x == Self::Read as u8 => Ok(Self::Read),
            x if x == Self::Write as u8 => Ok(Self::Write),
            x if x == Self::SetInfo as u8 => Ok(Self::SetInfo),
            x if x == Self::Close as u8 => Ok(Self::Close),
            x if x == Self::Cleanup as u8 => Ok(Self::Cleanup),
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
        filepath: PathBuf,
    },
    Process {
        process_id: u32,
        parent_id: u32,
        create: bool,
    },
    Image {
        process_id: u32,
        filepath: PathBuf,
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
                    Err(Error::InvalidMessageFilePathLength(n))
                } else {
                    let filepath = OsString::from_wide(&buffer[..n]).into();
                    Ok(Message::File {
                        process_id: f.Attr.ProcessId,
                        major_function: f.Attr.MajorFunction.try_into()?,
                        filepath,
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
                        filepath: PathBuf::new(),
                    })
                } else {
                    let buffer = f.Buffer;
                    if n > buffer.len() {
                        Err(Error::InvalidImageFilePathLength(n))
                    } else {
                        let filepath = OsString::from_wide(&buffer[..n]).into();

                        Ok(Message::Image {
                            process_id: f.Attr.ProcessId,
                            filepath,
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
    parent_id: Option<u32>,
    children_ids: Vec<u32>,
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
    let mut child_map = HashMap::new();
    let tracked_process_names = vec![
        OsStr::new("nastran.exe").to_owned(),
        OsStr::new("create_file.exe").to_owned(),
    ];
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
                filepath,
            } => {
                // println!(
                //     "File {:?} : process_id={:5} filepath={}",
                //     major_function, process_id, filepath
                // );
                if let Some(tracked_id) = child_map.get(&process_id) {
                    match map.get_mut(&tracked_id) {
                        Some(ProcessMapValue { filemap, .. }) => {
                            // println!("Attaching to {} : {}", tracked_id, filepath.display());
                            let mut entry = filemap.entry(filepath.clone()).or_default();
                            match major_function {
                                MajorFunction::Read => (entry.read = true),
                                MajorFunction::Write => (entry.write = true),
                                MajorFunction::Create => {}
                                MajorFunction::SetInfo => {
                                    println!("SetInfo File {}", filepath.display());
                                }
                                MajorFunction::Close => {
                                    println!("Close File {}", filepath.display());
                                }
                                MajorFunction::Cleanup => {
                                    println!("Cleanup File {}", filepath.display());
                                }
                            }
                        }
                        None => eprintln!(
                            "Process {} (Tracked {}) not found in map for file operation {}",
                            process_id,
                            tracked_id,
                            filepath.display()
                        ),
                    }
                }
            }
            Message::Process {
                process_id,
                parent_id,
                create,
            } => {
                // println!(
                //     "Process : parent_id={:5} process_id={:5} create={}",
                //     process_id, parent_id, create
                // );
                if create {
                    let tracked_id_from_parent = child_map.get(&parent_id).copied();
                    if tracked_id_from_parent.is_none() {
                        // println!("Process started {} (Parent {})", process_id, parent_id);
                        // Need to insert in case the process name matches later
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
                        let tracked_id = tracked_id_from_parent.unwrap();
                        child_map.insert(process_id, tracked_id);
                        map.get_mut(&tracked_id)
                            .map(|v| v.children_ids.push(process_id));
                    }
                } else {
                    let tracked_id = child_map.get(&process_id).copied();
                    if tracked_id.is_none() {
                        let _ = map.remove(&process_id);
                    } else {
                        let tracked_id = tracked_id.unwrap();
                        if tracked_id != process_id {
                            continue;
                        }
                        match map.remove(&process_id) {
                            Some(ProcessMapValue {
                                parent_id,
                                process_name,
                                children_ids,
                                filemap,
                                ..
                            }) => {
                                for child_id in children_ids {
                                    let _ = child_map.remove(&child_id);
                                }
                                let _ = child_map.remove(&process_id);
                                let parent_id = parent_id.map(|p| p as isize).unwrap_or(-1);
                                println!(
                                    "Process {} finished (Parent {:?}) {:?}",
                                    process_id, parent_id, process_name
                                );
                                let mut filepaths: Vec<_> = filemap.keys().cloned().collect();
                                filepaths.sort();
                                for mut filepath in filepaths {
                                    let FileMapValue { read, write } =
                                        filemap.get(&filepath).unwrap();
                                    if !(*read || *write) {
                                        continue;
                                    }
                                    // I think all local files will start with device. Replacing \Device with \\?\
                                    // causes the path to work for looking up files from rust
                                    if let Ok(fileend) = filepath.strip_prefix("/Device") {
                                        filepath = Path::new(r"\\?\").join(fileend);
                                        // canonicalize to get drive letter.
                                        if let Ok(new_filepath) = filepath.canonicalize() {
                                            filepath = new_filepath;
                                        } else {
                                            // canonicalize only works on files that exists
                                            // If the file no longer exists we're assuming that it was a temporary file
                                            continue;
                                        }
                                    }
                                    if *read {
                                        print!("I");
                                    } else {
                                        print!(" ");
                                    }
                                    if *write {
                                        print!("O");
                                    } else {
                                        print!(" ");
                                    }
                                    println!(": {}", filepath.display());
                                }
                            }
                            None => eprintln!("Process {} not found in map", process_id),
                        }
                    }
                }
            }
            Message::Image {
                process_id,
                filepath,
            } => {
                // Tracking checking is done here because we need to know process name first
                let tracked = child_map.contains_key(&process_id);
                if !tracked {
                    if let Some(filename) = filepath.file_name() {
                        if tracked_process_names.contains(&filename.to_owned()) {
                            // println!("Tracking Process {}", process_id);
                            child_map.insert(process_id, process_id);
                        } else {
                            // Remove the process from the map if its not tracked
                            map.remove(&process_id);
                            continue;
                        }
                    }
                    // TODO This should check for exe
                    let mut value = map.entry(process_id).or_default();
                    if value.process_name.is_none() {
                        value.process_name = Some(filepath)
                    }
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
