use windows::Win32::Foundation::{INVALID_HANDLE_VALUE, CloseHandle};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{MEM_RESERVE, MEM_RELEASE, MEM_COMMIT, PAGE_EXECUTE_READWRITE, VirtualAllocEx, VirtualFreeEx};
use windows::Win32::System::Threading::{WaitForSingleObject, GetExitCodeThread, QueueUserAPC, OpenThread,
    THREAD_SET_CONTEXT, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME};
use windows::Win32::System::LibraryLoader::{GetProcAddress, GetModuleHandleA, FreeLibrary};
use windows::Win32::System::WindowsProgramming::INFINITE;
use windows::s;
use crate::data;

pub fn injector(process_name:&str, dll_location: &str){

    let dll_path_size = dll_location.as_bytes().len();

    let name = data::ProcessData::name(process_name).unwrap();
    let proc_handle = name.process_handle();

    let tids = data::ProcessData::tids(data::ProcessData::pid(process_name));

    if proc_handle == INVALID_HANDLE_VALUE{
        panic!("{:?}", "[-] Error: Invalid handle value");
    }

    let adress = unsafe{
        VirtualAllocEx(
            proc_handle,
            Some(std::ptr::null()),
            dll_path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    if adress.is_null(){
        unsafe { CloseHandle(proc_handle) };
        panic!("{:?}", "[-] Error: failed to allocate memory in the process");
    }

    let w_process = unsafe {
        WriteProcessMemory(
            proc_handle,
            adress,
            dll_location.as_ptr() as *const std::ffi::c_void,
            dll_path_size,
            Some(std::ptr::null_mut())
        )
    };

    if w_process == false{
        unsafe { VirtualFreeEx(proc_handle, adress, 0, MEM_RELEASE) };
        unsafe { CloseHandle(proc_handle) };
        panic!("{:?}", "[-] Error: failed to write to process memory");
    }
    
    let k32_address = unsafe{ GetModuleHandleA(s!("kernel32.dll")).unwrap() };

    if k32_address.is_invalid(){
        unsafe { VirtualFreeEx(proc_handle, adress, 0, MEM_RELEASE) };
        panic!("{:?}", "[-] Error: failed to kernel32 handle");
    }

    let proc_address = unsafe{ GetProcAddress(k32_address, s!("LoadLibraryA")) };

    for tid in &tids {
        let process_thread = unsafe {
            OpenThread(
                THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                false,
                *tid,
            ).unwrap()
        };

        if process_thread.is_invalid(){
            unsafe { FreeLibrary(k32_address) };
            unsafe { VirtualFreeEx(proc_handle, adress, 0, MEM_RELEASE) };
            unsafe { CloseHandle(proc_handle) };
        }

        let start_routine = unsafe{ std::mem::transmute(proc_address) };

        unsafe{ QueueUserAPC(start_routine, process_thread, adress as usize) };

        unsafe { WaitForSingleObject(process_thread, INFINITE) };

        let mut exit_code = 0;
        if unsafe{ GetExitCodeThread(process_thread, &mut exit_code) } == false{
            unsafe { CloseHandle(process_thread) };
        }
    }
    unsafe { FreeLibrary(k32_address) };
    unsafe { VirtualFreeEx(proc_handle, adress, 0, MEM_RELEASE) };
    unsafe { CloseHandle(proc_handle) };

    println!("Injection successful!");

}

