#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_d_path, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
};
use aya_ebpf::{
    bindings::path,
    macros::{lsm, map},
    maps::RingBuf,
    programs::LsmContext,
};
use aya_log_ebpf::info;
use lsm_file_open_common::Buffer;

#[allow(
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    dead_code,
    unnecessary_transmutes,
    improper_ctypes_definitions
)]
mod vmlinux;

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(4096u32, 0);

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    try_file_open(ctx);
    0
}

fn try_file_open(ctx: LsmContext) {
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };

    let path = unsafe { &(*file).f_path as *const _ as *mut path };

    match RING_BUF.reserve::<Buffer>(0) {
        Some(mut event) => {
            let ptr = event.as_mut_ptr();
            unsafe {
                core::ptr::write_bytes((*ptr).data.as_mut_ptr(), 0, (*ptr).data.len());
                let ret = bpf_d_path(
                    path,
                    (*ptr).data.as_mut_ptr() as *mut i8,
                    (*ptr).data.len() as u32,
                );
                if ret < 0 {
                    event.discard(0);
                    return;
                }
                (*ptr).len = ret as usize;
                let pid_tgid = bpf_get_current_pid_tgid();
                (*ptr).pid = (pid_tgid >> 32) as u32;

                let uid_gid = bpf_get_current_uid_gid();
                (*ptr).uid = uid_gid as u32;

                let comm = bpf_get_current_comm();
                match comm {
                    Ok(comm) => {
                        core::ptr::copy_nonoverlapping(comm.as_ptr(), (*ptr).comm.as_mut_ptr(), 16)
                    }
                    Err(_) => core::ptr::write_bytes((*ptr).comm.as_mut_ptr(), 0, 16),
                }
            }
            event.submit(0);
        }
        None => {
            info!(&ctx, "Cannot reserve space in ring buffer.");
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
