use aya::maps::RingBuf;
use aya::{include_bytes_aligned, Bpf};
use aya::{programs::Lsm, Btf};
use aya_log::BpfLogger;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs;
use std::io;
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
    let users = get_users().unwrap();
    program.load("file_open", &btf)?;
    program.attach()?;

    let mut ring = RingBuf::try_from(bpf.map("RING_BUF").unwrap())?;

    info!("Waiting for Ctrl-C...");

    loop {
        if let Some(item) = ring.next() {
            let buf: &Buffer = unsafe { &*(item.as_ptr() as *const Buffer) };
            if let Ok(str) = std::str::from_utf8(&buf.data[..buf.len]) {
                if str == "/etc/passwd\0" || str == "/etc/shadow\0" || str == "/etc/hosts\0" {
                    info!(
                        "{} opened, pid: {}, uid: {}, user: {}",
                        str,
                        buf.pid,
                        buf.uid,
                        users.get(&buf.uid).unwrap()
                    );
                }
            } else {
                info!("invalid utf8");
            }
        }
    }

    // signal::ctrl_c().await?;
    // info!("Exiting...");

    // Ok(())
}

fn get_users() -> io::Result<HashMap<u32, String>> {
    let mut users = HashMap::new();
    let contents = fs::read_to_string("/etc/passwd")?;
    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 {
            let username = fields[0].to_string();
            let uid = fields[2].parse::<u32>().unwrap();
            users.insert(uid, username);
        }
    }
    Ok(users)
}
