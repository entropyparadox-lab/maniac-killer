use crate::config::Config;
use crate::protection::Protection;
use chrono::{DateTime, Duration, Local};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sysinfo::{Pid, System};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedProcess {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub cwd: String,
    pub ppid: Option<u32>,
    pub user_id: String,
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub cpu_streak: u32,
    pub start_time: u64,
    pub first_detected: DateTime<Local>,
    pub alert_sent: bool,
    pub last_alert_time: Option<DateTime<Local>>,
    pub muted_until: Option<DateTime<Local>>,
    pub reason: String,
}

pub struct Detector {
    pub sys: System,
    pub tracked: HashMap<u32, TrackedProcess>,
    pub whitelist: Vec<String>,
}

impl Detector {
    pub fn new(whitelist: Vec<String>) -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self {
            sys,
            tracked: HashMap::new(),
            whitelist,
        }
    }

    /// Check if a process is part of a legitimate active build pipeline (e.g. Xcode, Cargo, Clang, Next.js build, Webpack)
    fn is_build_compiler(&self, name: &str, cmdline: &str, ppid: Option<u32>) -> bool {
        let name_lower = name.to_lowercase();
        let cmd_lower = cmdline.to_lowercase();

        let compiler_names = [
            "rustc",
            "swiftc",
            "clang",
            "clang++",
            "cc1",
            "cc1plus",
            "tsc",
            "esbuild",
            "swc",
            "next-server",
            "webpack",
            "rollup",
            "vite",
            "turbo",
            "turbopack",
            "javac",
            "kotlinc",
            "go",
            "ld",
            "ld64",
            "lld",
        ];

        let is_compiler = compiler_names
            .iter()
            .any(|&c| name_lower == c || name_lower.starts_with(c));

        // Check if parent process is a known build orchestration tool
        if let Some(parent_pid) = ppid {
            if let Some(parent_proc) = self.sys.process(Pid::from(parent_pid as usize)) {
                let parent_name = parent_proc.name().to_string_lossy().to_lowercase();
                let build_tools = [
                    "cargo",
                    "xcodebuild",
                    "make",
                    "ninja",
                    "cmake",
                    "gradle",
                    "mvn",
                    "swift-build",
                    "pnpm",
                    "npm",
                    "yarn",
                    "bun",
                    "docker",
                    "podman",
                ];
                if build_tools.iter().any(|&b| parent_name.contains(b)) {
                    return true;
                }
            }
        }

        // Also check command line context
        if cmd_lower.contains("xcodebuild")
            || cmd_lower.contains("cargo build")
            || cmd_lower.contains("pnpm build")
            || cmd_lower.contains("npm run build")
            || cmd_lower.contains("next build")
            || cmd_lower.contains("docker build")
        {
            return true;
        }

        is_compiler
    }

    pub fn scan(&mut self, config: &Config) -> Vec<TrackedProcess> {
        self.sys.refresh_all();
        let now = Local::now();
        let mut suspects = Vec::new();
        let mut current_pids = HashMap::new();

        for (pid, proc) in self.sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = proc.name().to_string_lossy().to_string();
            let cmdline_vec: Vec<String> = proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect();
            let cmdline = cmdline_vec.join(" ");
            let cpu = proc.cpu_usage();
            let mem_mb = proc.memory() / (1024 * 1024);
            let ppid = proc.parent().map(|p| p.as_u32());
            let cwd = proc
                .cwd()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let user = proc
                .user_id()
                .map(|u| u.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let start_time = proc.start_time();

            // 1. Skip if immune or whitelisted (using deep inspection)
            if Protection::is_process_protected(pid_u32, proc, &self.whitelist) {
                continue;
            }

            current_pids.insert(
                pid_u32,
                (
                    name.clone(),
                    cmdline.clone(),
                    cwd.clone(),
                    ppid,
                    user.clone(),
                    cpu,
                    mem_mb,
                    start_time,
                ),
            );

            // Compiler / Build Pipeline Intelligence
            let is_compiler = self.is_build_compiler(&name, &cmdline, ppid);

            // Criteria 1: Sustained High CPU (Build tools get higher streak threshold to prevent false positives)
            let required_streak = if is_compiler {
                config.cpu_streak.max(18) // 18 checks = ~3 mins of sustained max CPU for compilers
            } else {
                config.cpu_streak
            };

            let is_high_cpu = cpu >= config.cpu_threshold;

            // Criteria 2: Orphaned background daemons with High Memory/CPU (PPID 1)
            let is_orphan_daemon = ppid == Some(1)
                && (name.contains("daemon")
                    || name.contains("chromium")
                    || name.contains("node")
                    || cmdline.contains("agent-browser"))
                && (cpu > 20.0 || mem_mb > 500);

            // Criteria 3: Extreme Memory Hog (> configured MB)
            let is_memory_hog = mem_mb >= config.mem_threshold_mb && cpu >= 30.0;

            if is_high_cpu || is_orphan_daemon || is_memory_hog {
                let entry = self.tracked.entry(pid_u32).or_insert_with(|| {
                    let reason = if is_high_cpu {
                        format!("CPU {:.1}% threshold exceeded", cpu)
                    } else if is_orphan_daemon {
                        format!("Orphan daemon (PPID 1, CPU {:.1}%, {}MB)", cpu, mem_mb)
                    } else {
                        format!(
                            "Memory leak / excessive footprint ({}MB, CPU {:.1}%)",
                            mem_mb, cpu
                        )
                    };
                    TrackedProcess {
                        pid: pid_u32,
                        name: name.clone(),
                        cmdline: cmdline.clone(),
                        cwd: cwd.clone(),
                        ppid,
                        user_id: user.clone(),
                        cpu_percent: cpu,
                        memory_mb: mem_mb,
                        cpu_streak: 0,
                        start_time,
                        first_detected: now,
                        alert_sent: false,
                        last_alert_time: None,
                        muted_until: None,
                        reason,
                    }
                });

                // Update metrics
                entry.cpu_percent = cpu;
                entry.memory_mb = mem_mb;
                entry.cpu_streak += 1;
                entry.start_time = start_time;

                // Determine if we should trigger an alert
                let streak_met = entry.cpu_streak >= required_streak || is_orphan_daemon;
                let alert_cooldown_ok = match entry.last_alert_time {
                    Some(t) => (now - t).num_minutes() >= 15,
                    None => true,
                };
                let not_muted_ok = match entry.muted_until {
                    Some(m) => now > m,
                    None => true,
                };

                if streak_met && not_muted_ok && alert_cooldown_ok {
                    entry.reason = if is_orphan_daemon {
                        format!("Orphan daemon (PPID 1, CPU {:.1}%, {}MB)", cpu, mem_mb)
                    } else if is_memory_hog {
                        format!("Memory hog ({}MB, CPU {:.1}%)", mem_mb, cpu)
                    } else if is_compiler {
                        format!(
                            "Stuck Compiler loop (CPU {:.1}% sustained for {} checks)",
                            cpu, entry.cpu_streak
                        )
                    } else {
                        format!("CPU {:.1}% sustained for {} checks", cpu, entry.cpu_streak)
                    };
                    entry.alert_sent = true;
                    entry.last_alert_time = Some(now);
                    suspects.push(entry.clone());
                }
            } else {
                // If CPU dropped below threshold, decay streak
                if let Some(entry) = self.tracked.get_mut(&pid_u32) {
                    if entry.cpu_streak > 0 {
                        entry.cpu_streak -= 1;
                    }
                }
            }
        }

        // Clean up dead processes from tracking
        self.tracked.retain(|pid, proc| {
            if let Some((_, _, _, _, _, _, _, st)) = current_pids.get(pid) {
                *st == proc.start_time
            } else {
                false
            }
        });

        suspects
    }

    pub fn mute(&mut self, pid: u32, hours: i64) -> bool {
        if let Some(proc) = self.tracked.get_mut(&pid) {
            proc.muted_until = Some(Local::now() + Duration::hours(hours));
            true
        } else {
            false
        }
    }

    pub fn add_whitelist(&mut self, keyword: String) {
        if !self.whitelist.contains(&keyword) {
            self.whitelist.push(keyword);
        }
    }
}
