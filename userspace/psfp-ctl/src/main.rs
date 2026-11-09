use std::path::Path;
use std::thread::sleep;
use std::time::Duration;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use libbpf_rs::{MapCore, MapFlags, ObjectBuilder};
use nix::net::if_::if_nametoindex;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct StreamRule {
    gate_open: u32,
    max_sdu_size: u32,
    rx_packets: u64,
    rx_bytes: u64,
    dropped_packets: u64,
}

#[derive(Debug, Parser)]
#[command(name = "psfp-ctl")]
#[command(about = "Rust / libbpf-rs IEEE 802.1Qci PSFP TSN Stream Controller & Monitor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Load eBPF XDP program and attach to interface, monitoring stream table
    Attach {
        #[arg(short, long, default_value = "veth-sub")]
        interface: String,

        #[arg(short, long, default_value = "src/xdp_psfp_kern.o")]
        bpf_obj: String,
    },
    /// Dump the current PSFP stream table from active BPF map
    Show,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Attach { interface, bpf_obj } => {
            let ifidx = if_nametoindex(interface.as_str())
                .with_context(|| format!("Failed to find interface '{interface}'"))? as i32;

            println!("================================================================================");
            println!(" Rust libbpf-rs PSFP Loader & Stream Controller");
            println!(" Target Interface: {} (ifindex {})", interface, ifidx);
            println!(" BPF ELF Object  : {}", bpf_obj);
            println!("================================================================================");

            let mut open_obj = ObjectBuilder::default()
                .open_file(Path::new(&bpf_obj))
                .context("Failed to open BPF ELF object")?;

            let mut obj = open_obj.load().context("Kernel verifier rejected BPF program")?;
            println!("[+] Kernel verifier accepted bytecode. BPF object loaded successfully.");

            let prog = obj.prog_mut("xdp_psfp_filter").context("Program 'xdp_psfp_filter' not found")?;
            let _link = prog.attach_xdp(ifidx).context("Failed to attach XDP hook")?;
            println!("[+] XDP program attached to '{}'. Link active.", interface);

            let map = obj.map_mut("stream_map").context("Map 'stream_map' not found")?;

            println!("[*] Monitoring IEEE 802.1Qci PSFP Stream Map (Press Ctrl+C to detach)...");

            loop {
                println!("\x1B[2J\x1B[1;1H"); // ANSI clear screen
                println!("=========================================================================================");
                println!(" IEEE 802.1Qci PSFP Real-Time Stream Table (Rust / libbpf-rs)");
                println!(" Interface: {} | Active Hook: XDP", interface);
                println!("=========================================================================================");
                println!(" {:<12} | {:<12} | {:<12} | {:<14} | {:<14} | {:<16}",
                         "Stream ID", "Gate State", "Max SDU (B)", "RX Packets", "RX Bytes", "Dropped Packets");
                println!("-----------------------------------------------------------------------------------------");

                let streams = [(100u32, "100 (OPC UA)"), (200u32, "200 (Rogue)"), (0u32, "0 (Untagged)")];
                for (stream_id, label) in streams {
                    let key = stream_id.to_ne_bytes();
                    if let Ok(Some(val_bytes)) = map.lookup(&key, MapFlags::ANY) {
                        if val_bytes.len() >= std::mem::size_of::<StreamRule>() {
                            let rule: StreamRule = unsafe {
                                std::ptr::read_unaligned(val_bytes.as_ptr() as *const StreamRule)
                            };
                            let gate_str = if rule.gate_open == 1 { "OPEN (Pass)" } else { "CLOSED (Drop)" };
                            let sdu_str = if rule.max_sdu_size > 0 {
                                format!("{} B", rule.max_sdu_size)
                            } else {
                                "Unlimited".to_string()
                            };

                            println!(" {:<12} | {:<12} | {:<12} | {:<14} | {:<14} | {:<16}",
                                     label, gate_str, sdu_str, rule.rx_packets, rule.rx_bytes, rule.dropped_packets);
                        }
                    }
                }
                println!("=========================================================================================");
                println!(" [Running Rust libbpf-rs monitor] Ctrl+C to drop RAII Link and detach XDP cleanly.");
                sleep(Duration::from_secs(1));
            }
        }
        Commands::Show => {
            println!("Use 'attach' to load and continuously monitor.");
        }
    }

    Ok(())
}
