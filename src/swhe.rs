use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::UI::WindowsAndMessaging::{FindWindowA, GetWindowThreadProcessId, PostThreadMessageA, SetWindowsHookExA, HOOKPROC, WH_GETMESSAGE, WM_NULL};
use windows::Win32::Foundation::{WPARAM, LPARAM};
use windows::core::PCSTR;

pub fn injector(dll_location:&str){

    let dll_path_str = std::ffi::CString::new(dll_location).unwrap();
    let hw = unsafe{ FindWindowA(PCSTR(std::ptr::null()), PCSTR("title\0".as_ptr())) };
    let mut process_id = 0;
    let tid = unsafe { GetWindowThreadProcessId(hw, Some(&mut process_id)) };

    if tid == 0 {
        panic!("{}","Failed to get thread id");
    }

    let stub_module = unsafe { LoadLibraryA(PCSTR(dll_path_str.as_ptr() as *const u8)).unwrap() };
    let stub_callback: HOOKPROC = unsafe { std::mem::transmute(GetProcAddress(stub_module, PCSTR("GetMsgProc".as_ptr()))) };

    unsafe{ SetWindowsHookExA(WH_GETMESSAGE, stub_callback, stub_module, tid) };

    for _ in 0..100{
        unsafe { PostThreadMessageA(tid, WM_NULL, WPARAM(0), LPARAM(0)) };
    }

    loop{};
}