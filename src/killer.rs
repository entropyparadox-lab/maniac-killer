use crate::protection::Protection;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::time::Duration;
use sysinfo::{Pid as SysPid, System};

#[derive(Debug, Clone, serde::Serialize)]
pub struct KillResult {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub memory_freed_mb: u64,
    pub forced_kill: bool,
    pub success: bool,
    pub message: String,
}

pub struct Executioner;

impl Executioner {
    pub fn execute(pid: u32, custom_whitelist: &[String]) -> Result<KillResult, String> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let sys_pid = SysPid::from(pid as usize);
        let proc = sys
            .process(sys_pid)
            .ok_or_else(|| format!("PID {} not found in running processes", pid))?;

        let name = proc.name().to_string_lossy().to_string();
        let cmdline_vec: Vec<String> = proc
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        let cmdline = cmdline_vec.join(" ");
        let mem_mb = proc.memory() / (1024 * 1024);

        // Double security check before sending signals
        if Protection::is_protected(pid, &name, &cmdline_vec, custom_whitelist) {
            return Err(format!(
                "🛡️ PID {} ({}) is IMMUNE/PROTECTED and cannot be terminated!",
                pid, name
            ));
        }

        let nix_pid = Pid::from_raw(pid as i32);

        // Step 1: Send graceful SIGTERM
        let _ = kill(nix_pid, Signal::SIGTERM);
        std::thread::sleep(Duration::from_millis(1200));

        // Step 2: Check if still alive
        let mut forced = false;
        let mut sys2 = System::new_all();
        sys2.refresh_all();

        if sys2.process(sys_pid).is_some() {
            // Still alive -> Send SIGKILL
            forced = true;
            let _ = kill(nix_pid, Signal::SIGKILL);
            std::thread::sleep(Duration::from_millis(500));
        }

        Ok(KillResult {
            pid,
            name,
            cmdline,
            memory_freed_mb: mem_mb,
            forced_kill: forced,
            success: true,
            message: if forced {
                format!(
                    "🩸 Process ignored SIGTERM -> force killed via SIGKILL (Freed {}MB)",
                    mem_mb
                )
            } else {
                format!(
                    "✅ Process gracefully terminated via SIGTERM (Freed {}MB)",
                    mem_mb
                )
            },
        })
    }
}
