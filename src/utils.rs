use windows::Win32::Foundation::CHAR;

pub fn string(base:[CHAR; 260])-> &'static str{
    unsafe{ std::ffi::CStr::from_ptr(base.as_ptr() as _).to_str().unwrap() }
}