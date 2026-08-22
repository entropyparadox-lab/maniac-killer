use crate::protection::Protection;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::collections::HashSet;
use std::time::Duration;
use sysinfo::{Pid as SysPid, System};

#[derive(Debug, Clone, serde::Serialize)]
pub struct KillResult {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub memory_freed_mb: u64,
    pub killed_pids: Vec<u32>,
    pub forced_kill: bool,
    pub success: bool,
    pub message: String,
}

pub struct Executioner;

impl Executioner {
    /// Recursively discover all child/descendant PIDs belonging to the target process tree
    fn find_process_tree(sys: &System, root_pid: u32) -> Vec<u32> {
        let mut tree = Vec::new();
        let mut queue = vec![root_pid];
        let mut visited = HashSet::new();
        visited.insert(root_pid);

        while let Some(current_parent) = queue.pop() {
            tree.push(current_parent);
            for (pid, proc) in sys.processes() {
                let pid_u32 = pid.as_u32();
                if let Some(ppid) = proc.parent() {
                    if ppid.as_u32() == current_parent && !visited.contains(&pid_u32) {
                        visited.insert(pid_u32);
                        queue.push(pid_u32);
                    }
                }
            }
        }

        tree
    }

    pub async fn execute(
        pid: u32,
        expected_start_time: Option<u64>,
        custom_whitelist: &[String],
    ) -> Result<KillResult, String> {
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
        let current_start_time = proc.start_time();

        // 1. TOCTOU Protection: Ensure PID wasn't recycled to an innocent process
        if let Some(expected_st) = expected_start_time {
            if expected_st != current_start_time {
                return Err(format!(
                    "🛡️ TOCTOU Guard: PID {} has been recycled! (Expected start_time {}, but found {}). Aborting kill.",
                    pid, expected_st, current_start_time
                ));
            }
        }

        // 2. Strict Agent & System Immunity Check
        if Protection::is_protected(pid, &name, &cmdline_vec, custom_whitelist) {
            return Err(format!(
                "🛡️ Immunity Guard: PID {} ({}) is PROTECTED and cannot be terminated!",
                pid, name
            ));
        }

        // 3. Discover entire process tree (Parent + Child workers)
        let target_tree = Self::find_process_tree(&sys, pid);

        let mut total_mem_mb = 0;
        for &tree_pid in &target_tree {
            if let Some(p) = sys.process(SysPid::from(tree_pid as usize)) {
                total_mem_mb += p.memory() / (1024 * 1024);
            }
        }

        // 4. Send graceful SIGTERM to all processes in tree (bottom-up / reverse)
        for &tree_pid in target_tree.iter().rev() {
            let nix_pid = Pid::from_raw(tree_pid as i32);
            let _ = kill(nix_pid, Signal::SIGTERM);
        }

        // 5. Non-blocking asynchronous sleep (Tokio)
        tokio::time::sleep(Duration::from_millis(1200)).await;

        // 6. Check for any stubborn survivors in the tree
        let mut sys2 = System::new_all();
        sys2.refresh_all();

        let mut forced = false;
        for &tree_pid in &target_tree {
            let sys_check = SysPid::from(tree_pid as usize);
            if sys2.process(sys_check).is_some() {
                forced = true;
                let nix_pid = Pid::from_raw(tree_pid as i32);
                let _ = kill(nix_pid, Signal::SIGKILL);
            }
        }

        if forced {
            tokio::time::sleep(Duration::from_millis(400)).await;
        }

        let count = target_tree.len();
        Ok(KillResult {
            pid,
            name,
            cmdline,
            memory_freed_mb: total_mem_mb,
            killed_pids: target_tree,
            forced_kill: forced,
            success: true,
            message: if forced {
                format!(
                    "🩸 Tree-Kill: Terminated {} process(es) via SIGTERM/SIGKILL (Freed {}MB)",
                    count, total_mem_mb
                )
            } else {
                format!(
                    "✅ Tree-Kill: Gracefully terminated {} process(es) via SIGTERM (Freed {}MB)",
                    count, total_mem_mb
                )
            },
        })
    }
}
