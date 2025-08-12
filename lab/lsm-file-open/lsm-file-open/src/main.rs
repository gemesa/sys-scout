use aya::{programs::Lsm, Btf};
use aya::{include_bytes_aligned, Bpf};
use aya::maps::RingBuf;
use aya_log::BpfLogger;
use log::{info, warn, debug};
// use tokio::signal;

use lsm_file_open_common::Buffer;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/lsm-file-open"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/lsm-file-open"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("file_open").unwrap().try_into()?;
    program.load("file_open", &btf)?;
    program.attach()?;

    let mut ring = RingBuf::try_from(bpf.map("RING_BUF").unwrap())?;

    info!("Waiting for Ctrl-C...");

    loop {
        if let Some(item) = ring.next() {
            let buf: &Buffer = unsafe { &*(item.as_ptr() as *const Buffer) };
            if let Ok(str) = std::str::from_utf8(&buf.data[..buf.len]) {
                if str == "/etc/passwd\0" {
                    //let username = get_username(buf.uid);
                    //info!("/etc/passwd opened, pid: {}, uid: {}, user: {}", buf.pid, buf.uid, username);
                    info!("/etc/passwd opened, pid: {}, uid: {}", buf.pid, buf.uid);
                }
            }
            else {
                info!("invalid utf8");
            }
        }
    }

    // signal::ctrl_c().await?;
    // info!("Exiting...");

    // Ok(())
}

fn _get_username(uid: u32) -> String {
    unsafe {
        let passwd = libc::getpwuid(uid);
        if passwd.is_null() {
            return "unknown".to_string();
        }
        let name_ptr = (*passwd).pw_name;
        if name_ptr.is_null() {
            return "unknown".to_string();
        }
        let name_cstr = std::ffi::CStr::from_ptr(name_ptr);
        match name_cstr.to_str() {
            Ok(name) => name.to_string(),
            Err(_) => "unknown".to_string(),
        }
    }
}