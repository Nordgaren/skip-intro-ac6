#![feature(naked_functions)]
#![allow(non_snake_case)]

mod dinput8;
mod util;

use std::ffi::c_void;
use std::os::windows::raw::HANDLE;
use fisherman::scanner::signature::Signature;
use fisherman::scanner::simple_scanner::SimpleScanner;
use fisherman::util::get_module_slice;
use crate::dinput8::init_dinput8;
use windows::Win32::Foundation::{HMODULE, MAX_PATH};
#[cfg(feature = "Console")]
use windows::Win32::System::Console::{AllocConsole, AttachConsole};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameA, GetModuleHandleA};
use windows::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

#[no_mangle]
#[allow(unused)]
pub extern "stdcall" fn DllMain(hinstDLL: isize, dwReason: u32, lpReserved: *mut usize) -> i32 {
    match dwReason {
        DLL_PROCESS_ATTACH => unsafe {
            #[cfg(feature = "Console")]
            {
                AllocConsole();
                AttachConsole(u32::MAX);
            }
            init(hinstDLL);
            init_hooks();
            1
        },
        _ => 0,
    }
}

const SKIP_OFFSET: isize = 0x9;
unsafe fn init_hooks() {
    let base = GetModuleHandleA(None).unwrap().0 as usize;
    let module_slice = get_module_slice(base);
     let signature = Signature::from_ida_pattern("33 FF 40 38 BE ?? ?? ?? ?? 74").unwrap();
    let offset = SimpleScanner
         .scan(module_slice, &signature)
         .expect("Could not find signature.");
    let jump_addr = base as isize + offset as isize + SKIP_OFFSET;
    let jump_bytes = jump_addr as *mut u16;
    let mut oldProtect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(jump_bytes as *const c_void, 0x2, PAGE_EXECUTE_READWRITE, &mut oldProtect);
    *jump_bytes = 0x9090;
    VirtualProtect(jump_bytes as *const c_void, 0x2, oldProtect, &mut oldProtect);

}

unsafe fn init(hinstDLL: isize) -> String {
    let mut buffer = [0u8; MAX_PATH as usize + 1];
    let name_size = GetModuleFileNameA(
        HMODULE(hinstDLL),
        &mut buffer
    ) as usize;
    let name = &buffer[..name_size];
    let name_str = std::str::from_utf8(name).unwrap_or_default();
    if name_str.to_lowercase().ends_with("dinput8.dll") {
        init_dinput8();
    }

    name_str.to_string()
}
