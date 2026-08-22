pub struct Protection;

impl Protection {
    /// Built-in immune keywords for AI coding tools, developer shells, OS daemons, and databases.
    pub const IMMUNE_KEYWORDS: &'static [&'static str] = &[
        // AI Coding CLI & Agent Sessions (STRICTLY IMMUNE)
        "claude",
        "claude-code",
        "anthropic",
        "codex",
        "cursor",
        "aider",
        "hermes",
        "opencode",
        "grok",
        "ollama",
        "llama-server",
        "serena",
        "maniac-killer",
        // Developer Terminals & Multiplexers
        "tmux",
        "screen",
        "iterm2",
        "alacritty",
        "kitty",
        "wezterm",
        "gnome-terminal",
        "konsole",
        "terminal",
        // System Daemons & OS Runtimes
        "launchd",
        "kernel_task",
        "windowserver",
        "dock",
        "finder",
        "fseventsd",
        "mds",
        "mdworker",
        "loginwindow",
        "systemd",
        "sshd",
        "syslogd",
        "opendirectoryd",
        "securityd",
        "distnoted",
        "cfprefsd",
        "tccd",
        "coreservicesd",
        "init",
        "kthreadd",
        // Databases & Container Infrastructure
        "postgres",
        "mysqld",
        "mariadbd",
        "redis-server",
        "docker",
        "dockerd",
        "containerd",
        "orbstack",
        "virtualization",
        "tailscaled",
        "caddy",
        "nginx",
    ];

    pub fn is_protected(
        pid: u32,
        name: &str,
        cmdline: &[String],
        custom_whitelist: &[String],
    ) -> bool {
        // PIDs <= 100 are OS kernel/system root level
        if pid <= 100 {
            return true;
        }

        let name_lower = name.to_lowercase();
        let cmd_lower = cmdline.join(" ").to_lowercase();

        // 1. First-class AI Agent Immunity Check
        if name_lower.contains("claude")
            || cmd_lower.contains("claude --")
            || name_lower.contains("hermes")
        {
            return true;
        }

        // 2. Built-in Immune list
        for &kw in Self::IMMUNE_KEYWORDS {
            if name_lower.contains(kw) || cmd_lower.contains(kw) {
                return true;
            }
        }

        // 3. User-defined Custom Whitelist
        for kw in custom_whitelist {
            let kw_lower = kw.to_lowercase();
            if name_lower.contains(&kw_lower) || cmd_lower.contains(&kw_lower) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_pid_protected() {
        assert!(Protection::is_protected(1, "systemd", &[], &[]));
        assert!(Protection::is_protected(50, "kthreadd", &[], &[]));
    }

    #[test]
    fn test_ai_agent_immunity() {
        assert!(Protection::is_protected(
            1234,
            "claude",
            &["claude".to_string()],
            &[]
        ));
        assert!(Protection::is_protected(
            1235,
            "node",
            &["claude --dangerously-skip-permissions".to_string()],
            &[]
        ));
        assert!(Protection::is_protected(
            1236,
            "hermes",
            &["hermes agent".to_string()],
            &[]
        ));
    }

    #[test]
    fn test_unprotected_runaway() {
        assert!(!Protection::is_protected(
            2000,
            "next-server",
            &["next-server dev".to_string()],
            &[]
        ));
        assert!(!Protection::is_protected(
            2001,
            "bun",
            &["bun test".to_string()],
            &[]
        ));
    }

    #[test]
    fn test_custom_whitelist() {
        let wl = vec!["special-batch".to_string()];
        assert!(Protection::is_protected(3000, "special-batch", &[], &wl));
        assert!(Protection::is_protected(
            3001,
            "python3",
            &["python3 run_special-batch.py".to_string()],
            &wl
        ));
    }
}
