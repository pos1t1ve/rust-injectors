use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};
use windows::Win32::Foundation::{HANDLE, CloseHandle};
use windows::Win32::System::Diagnostics::ToolHelp::{PROCESSENTRY32,CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS,
    Process32First, Process32Next, THREADENTRY32, TH32CS_SNAPTHREAD, Thread32First, Thread32Next};
use crate::utils::string;

pub struct ProcessData{
    handle: HANDLE,
}

impl ProcessData{
    pub fn name(process_name: &str) -> Option<Self>{
        if let Some(pid) = Self::pid(process_name) {
            let handle = unsafe {
                OpenProcess(
                    PROCESS_ALL_ACCESS,
                    false,
                    pid
                )
            };

            match handle{
                Err(error) => panic!("Open process failed {}", error),
                Ok(handle) => Some( Self { handle } ),
            }

        } else {
            panic!("Process not found");
        }
    }

    pub fn pid(process_name: &str) -> Option<u32>{
        let mut pe32: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
        
        pe32.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        let snapshot = match unsafe{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }{
            Err(error) => panic!("Snapshot failed: {}", error),
            Ok(snap) => snap,
        };

        match unsafe{ Process32First(snapshot, &mut pe32) }.as_bool(){
            false => todo!(),
            true => {
                if string(pe32.szExeFile) == process_name {
                    return Some(pe32.th32ProcessID as u32);
                }
            }
        }

        loop{
            match unsafe{ Process32Next(snapshot, &mut pe32) }.as_bool(){
                false => todo!(),
                true => {
                    if string(pe32.szExeFile) == process_name {
                        return Some(pe32.th32ProcessID as u32);
                    }
                }
            }
        }

    }

    pub fn tids(pid: Option<u32>) -> Vec<u32> {
        let mut tids: Vec<u32> = Vec::new();
    
        let mut te32: THREADENTRY32 = unsafe { std::mem::zeroed() };
    
        te32.dwSize = std::mem::size_of_val(&te32) as u32;
    
        let handle_snapshot = unsafe{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).unwrap() };

        if unsafe{ Thread32First(handle_snapshot, &mut te32) } != false {
            loop {
                if pid == Some(te32.th32OwnerProcessID) {
                    tids.push(te32.th32ThreadID);
                }
    
                if unsafe{ Thread32Next(handle_snapshot, &mut te32) } == false {
                    break;
                }
            }
        }
    
        if tids.is_empty() {
            return tids;
        }
    
        unsafe{ CloseHandle(handle_snapshot) };
        tids
    }

    pub fn process_handle(&self) -> HANDLE {
        self.handle
    }
}