use std::sync::Mutex;
use tauri::{
    AppHandle, Emitter, Manager, State,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use tauri_plugin_notification::NotificationExt;

// ─── State ───────────────────────────────────────────────────────────────────

#[derive(Debug, Default, PartialEq, Clone, serde::Serialize)]
pub enum InstallStatus {
    #[default]
    Idle,
    Installing,
    Done,
    Failed,
}

pub struct AppState {
    pub status: Mutex<InstallStatus>,
    pub sudo_password: Mutex<Option<String>>,
}

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct ComponentStatus {
    pub name: &'static str,
    pub installed: bool,
    pub version: Option<String>,
    pub path: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct AdminConfig {
    pub wazuh_agent_version: Option<String>,
    pub wops_version: Option<String>,
    pub wazuh_yara_version: Option<String>,
    pub wazuh_snort_version: Option<String>,
    pub wazuh_suricata_version: Option<String>,
    pub wazuh_agent_status_version: Option<String>,
    pub wazuh_agent_repo_version: Option<String>,
    pub wazuh_agent_repo_ref: Option<String>,
    pub wazuh_cert_oauth2_repo_ref: Option<String>,
    pub wazuh_yara_repo_ref: Option<String>,
    pub wazuh_snort_repo_ref: Option<String>,
    pub wazuh_suricata_repo_ref: Option<String>,
    pub wazuh_trivy_repo_ref: Option<String>,
    pub wazuh_agent_status_repo_ref: Option<String>,
}

#[derive(Debug, serde::Deserialize, Clone)]
pub struct InstallConfig {
    pub wazuh_manager: String,
    pub nids_engine: String,
    pub install_trivy: bool,
    pub version_overrides: Option<AdminConfig>,
}

// ─── Tauri Commands ───────────────────────────────────────────────────────────

#[tauri::command]
fn get_platform() -> String {
    #[cfg(target_os = "windows")]
    return "windows".to_string();
    #[cfg(target_os = "macos")]
    return "macos".to_string();
    #[cfg(target_os = "linux")]
    return "linux".to_string();
}

#[tauri::command]
fn is_root() -> bool {
    #[cfg(target_os = "windows")]
    {
        false
    }
    #[cfg(not(target_os = "windows"))]
    {
        unsafe { libc::geteuid() == 0 }
    }
}

#[tauri::command]
fn get_script_path(app: AppHandle) -> Result<String, String> {
    let resource_path = app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?;

    #[cfg(target_os = "windows")]
    let script = resource_path.join("scripts").join("setup-agent.ps1");
    #[cfg(target_os = "macos")]
    let script = resource_path.join("scripts").join("setup-agent.sh");
    #[cfg(target_os = "linux")]
    let script = resource_path.join("scripts").join("setup-agent.sh");

    Ok(script.to_string_lossy().to_string())
}

/// Check which Wazuh components are installed on this system
#[tauri::command]
fn check_components() -> Vec<ComponentStatus> {
    fn try_version(path: &str) -> Option<String> {
        for flag in &["--version", "-V", "-v"] {
            if let Ok(out) = std::process::Command::new(path)
                .arg(flag)
                .output()
            {
                let s = String::from_utf8(out.stdout).ok()
                    .or_else(|| String::from_utf8(out.stderr).ok())
                    .unwrap_or_default();
                let first = s.lines().next().unwrap_or("").to_string();
                if !first.is_empty() {
                    return Some(first);
                }
            }
        }
        None
    }

    fn file_exists_sudo(path: &str) -> bool {
        std::process::Command::new("sudo")
            .args(["-n", "test", "-f", path])
            .output()
            .ok()
            .map_or(false, |o| o.status.success())
    }

    fn binary_ver(paths: &[&str]) -> (bool, Option<String>, String) {
        for p in paths {
            if std::path::Path::new(p).exists() {
                let ver = try_version(p);
                return (true, ver, p.to_string());
            }
            // If direct access fails, try via sudo -n (uses cached credentials)
            if file_exists_sudo(p) {
                let ver = std::process::Command::new("sudo")
                    .args(["-n", p, "--version"])
                    .output()
                    .ok()
                    .and_then(|o| {
                        String::from_utf8(o.stdout).ok()
                            .or_else(|| String::from_utf8(o.stderr).ok())
                    })
                    .and_then(|s| s.lines().next().map(|l| l.to_string()))
                    .filter(|s| !s.is_empty());
                return (true, ver, p.to_string());
            }
        }
        (false, None, paths[0].to_string())
    }

    fn process_running(name: &str) -> bool {
        std::process::Command::new("pgrep")
            .arg(name)
            .output()
            .ok()
            .map_or(false, |o| o.status.success())
    }

    fn service_active(name: &str) -> bool {
        std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", name])
            .output()
            .ok()
            .map_or(false, |o| o.status.success())
    }

    fn path_ver(name: &str) -> (bool, Option<String>) {
        which::which(name).ok().and_then(|p| {
            let p_str = p.to_str().unwrap_or("").to_string();
            try_version(&p_str)
                .map(|v| (true, Some(v)))
        }).unwrap_or((false, None))
    }

    let mut components = Vec::new();

    // Wazuh Agent — try binary paths, then fall back to process/service check
    #[cfg(target_os = "linux")]
    let agent_paths = &["/var/ossec/bin/wazuh-agent", "/var/ossec/bin/wazuh-agentd", "/var/ossec/bin/wazuh-control"][..];
    #[cfg(target_os = "macos")]
    let agent_paths = &["/Library/Ossec/bin/wazuh-agent", "/Library/Ossec/bin/wazuh-agentd", "/Library/Ossec/bin/wazuh-control"][..];
    #[cfg(target_os = "windows")]
    let agent_paths = &[r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"][..];
    let (mut installed, ver, mut found_path) = binary_ver(agent_paths);
    if !installed {
        let running = process_running("wazuh-agentd") || service_active("wazuh-agent");
        if running {
            installed = true;
            found_path = "wazuh-agentd (running)".to_string();
        }
    }
    components.push(ComponentStatus { name: "Wazuh Agent", installed, version: ver, path: found_path });

    // OAuth2 Client
    #[cfg(target_os = "linux")]
    let oauth_paths = &["/var/ossec/bin/wazuh-cert-oauth2-client"][..];
    #[cfg(target_os = "macos")]
    let oauth_paths = &["/Library/Ossec/bin/wazuh-cert-oauth2-client"][..];
    #[cfg(target_os = "windows")]
    let oauth_paths = &[r"C:\Program Files (x86)\ossec-agent\wazuh-cert-oauth2-client.exe"][..];
    let (installed, ver, found_path) = binary_ver(oauth_paths);
    components.push(ComponentStatus { name: "OAuth2 Client", installed, version: ver, path: found_path });

    // Yara
    let (installed, ver) = path_ver("yara");
    components.push(ComponentStatus { name: "Yara", installed, version: ver, path: "yara".to_string() });

    // Suricata
    let (installed, ver) = path_ver("suricata");
    components.push(ComponentStatus { name: "Suricata", installed, version: ver, path: "suricata".to_string() });

    // Snort
    let (installed, ver) = path_ver("snort");
    components.push(ComponentStatus { name: "Snort", installed, version: ver, path: "snort".to_string() });

    // Trivy
    let (installed, ver) = path_ver("trivy");
    components.push(ComponentStatus { name: "Trivy", installed, version: ver, path: "trivy".to_string() });

    // USB DLP Scripts
    #[cfg(target_os = "linux")]
    let usb_paths = &[
        "/var/ossec/active-response/bin/disable-usb-storage.sh",
        "/var/ossec/active-response/bin/disable-usb-storage",
    ][..];
    #[cfg(target_os = "macos")]
    let usb_paths = &["/Library/Ossec/active-response/bin/disable-usb-storage-macos.sh"][..];
    #[cfg(target_os = "windows")]
    let usb_paths = &[r"C:\Program Files (x86)\ossec-agent\active-response\bin\disable-usb-storage.ps1"][..];
    let (installed, ver, found_path) = binary_ver(usb_paths);
    components.push(ComponentStatus {
        name: "USB DLP Scripts",
        installed,
        version: ver,
        path: found_path,
    });

    components
}

/// Load saved admin version overrides
#[tauri::command]
fn load_admin_config(app: AppHandle) -> AdminConfig {
    let path = app.path().app_config_dir()
        .map(|p| p.join("admin-config.json"))
        .ok();
    if let Some(path) = path {
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(config) = serde_json::from_str(&data) {
                return config;
            }
        }
    }
    AdminConfig {
        wazuh_agent_version: None,
        wops_version: None,
        wazuh_yara_version: None,
        wazuh_snort_version: None,
        wazuh_suricata_version: None,
        wazuh_agent_status_version: None,
        wazuh_agent_repo_version: None,
        wazuh_agent_repo_ref: None,
        wazuh_cert_oauth2_repo_ref: None,
        wazuh_yara_repo_ref: None,
        wazuh_snort_repo_ref: None,
        wazuh_suricata_repo_ref: None,
        wazuh_trivy_repo_ref: None,
        wazuh_agent_status_repo_ref: None,
    }
}

/// Save admin version overrides
#[tauri::command]
fn save_admin_config(app: AppHandle, config: AdminConfig) -> Result<(), String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let data = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("admin-config.json"), data).map_err(|e| e.to_string())?;
    Ok(())
}

/// Run the install script, streaming output back to the frontend line by line
#[tauri::command]
async fn run_install(
    app: AppHandle,
    config: InstallConfig,
    password: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    {
        let mut s = state.status.lock().unwrap();
        *s = InstallStatus::Installing;
        let mut p = state.sudo_password.lock().unwrap();
        *p = password;
    }
    update_tray_icon(&app, InstallStatus::Installing);

    let script_path = get_script_path(app.clone())?;

    let manager = config.wazuh_manager.trim().to_string();
    let (ids_engine, suricata_mode) = match config.nids_engine.as_str() {
        "suricata-ids" => ("suricata".to_string(), Some("ids".to_string())),
        "suricata-ips" => ("suricata".to_string(), Some("ips".to_string())),
        "snort"        => ("snort".to_string(),    None),
        _              => ("suricata".to_string(), Some("ids".to_string())),
    };

    let _ = app.emit("install-log", "🛡️  GuardPost starting installation...\n");

    let result = run_script_with_streaming(
        &app,
        &state,
        &script_path,
        &manager,
        &ids_engine,
        suricata_mode.as_deref(),
        config.install_trivy,
        config.version_overrides.as_ref(),
    )
    .await;

    match result {
        Ok(_) => {
            {
                let mut s = state.status.lock().unwrap();
                *s = InstallStatus::Done;
            }
            update_tray_icon(&app, InstallStatus::Done);
            let _ = app.emit("install-done", true);

            let _ = app
                .notification()
                .builder()
                .title("GuardPost")
                .body("✅ Wazuh agent enrolled successfully!")
                .show();

            Ok(())
        }
        Err(e) => {
            {
                let mut s = state.status.lock().unwrap();
                *s = InstallStatus::Failed;
            }
            update_tray_icon(&app, InstallStatus::Failed);
            let _ = app.emit("install-done", false);
            let _ = app.emit("install-log", format!("\n❌ Error: {}\n", e));

            let _ = app
                .notification()
                .builder()
                .title("GuardPost")
                .body("❌ Installation failed. Check the log for details.")
                .show();

            Err(e)
        }
    }
}

// ─── OAuth2 Enrollment ────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
const OAUTH2_BIN: &str = "/var/ossec/bin/wazuh-cert-oauth2-client";
#[cfg(target_os = "macos")]
const OAUTH2_BIN: &str = "/Library/Ossec/bin/wazuh-cert-oauth2-client";
#[cfg(target_os = "windows")]
const OAUTH2_BIN: &str = r"C:\Program Files (x86)\ossec-agent\wazuh-cert-oauth2-client.exe";

#[tauri::command]
async fn run_oauth_enrollment(
    app: AppHandle,
    #[allow(unused_variables)] state: State<'_, AppState>,
    issuer: String,
    endpoint: String,
    password: Option<String>,
) -> Result<(), String> {
    if let Some(p) = password {
        *state.sudo_password.lock().unwrap() = Some(p);
    }
    use std::process::Stdio;
    use tokio::io::AsyncBufReadExt;

    let _ = app.emit("oauth-output", format!("🔍 Using: {}\n", OAUTH2_BIN));
    let _ = app.emit("oauth-output", format!("🌐 Issuer: {}\n", issuer));
    let _ = app.emit("oauth-output", format!("🔗 Endpoint: {}\n\n", endpoint));

    #[cfg(unix)]
    let mut child = {
        use tokio::io::AsyncWriteExt;

        let is_root = unsafe { libc::geteuid() == 0 };
        let mut cmd = tokio::process::Command::new("sudo");
        if !is_root {
            cmd.arg("-S");
            cmd.arg("-p");
            cmd.arg("");
        }
        cmd.arg(OAUTH2_BIN)
            .arg("o-auth2")
            .arg("--issuer").arg(&issuer)
            .arg("--endpoint").arg(&endpoint)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start OAuth2 enrollment: {}", e))?;

        if !is_root {
            if let Some(mut stdin) = child.stdin.take() {
                let pass = state.sudo_password.lock().unwrap().clone().unwrap_or_default();
                let _ = stdin.write_all(format!("{}\n", pass).as_bytes()).await;
                let _ = stdin.flush().await;
            }
        }
        child
    };

    #[cfg(windows)]
    let mut child = tokio::process::Command::new(OAUTH2_BIN)
        .arg("o-auth2")
        .arg("--issuer").arg(&issuer)
        .arg("--endpoint").arg(&endpoint)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start OAuth2 enrollment: {}", e))?;

    let _ = app.emit("oauth-output", "🔄 Opening browser for authentication...\n");

    if let Some(stdout) = child.stdout.take() {
        let ac = app.clone();
        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let _ = ac.emit("oauth-output", format!("{}\n", line));
            }
        });
    }

    if let Some(stderr) = child.stderr.take() {
        let ac = app.clone();
        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let _ = ac.emit("oauth-output", format!("⚠️  {}\n", line));
            }
        });
    }

    tokio::spawn(async move {
        let result = child.wait().await;
        match result {
            Ok(status) if status.success() => {
                let _ = app.emit("oauth-done", true);
                let _ = app.emit("oauth-output", "✅ Enrollment complete!\n");
            }
            Ok(status) => {
                let _ = app.emit("oauth-output", format!("❌ Enrollment exited with code {}\n", status.code().unwrap_or(-1)));
                let _ = app.emit("oauth-done", false);
            }
            Err(e) => {
                let _ = app.emit("oauth-output", format!("❌ Process error: {}\n", e));
                let _ = app.emit("oauth-done", false);
            }
        }
    });

    Ok(())
}

// ─── Script Runner ────────────────────────────────────────────────────────────

async fn run_script_with_streaming(
    app: &AppHandle,
    #[allow(unused_variables)] state: &State<'_, AppState>,
    script_path: &str,
    wazuh_manager: &str,
    ids_engine: &str,
    suricata_mode: Option<&str>,
    install_trivy: bool,
    version_overrides: Option<&AdminConfig>,
) -> Result<(), String> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};

    #[cfg(target_os = "windows")]
    let (cmd, args) = build_windows_command(script_path, wazuh_manager, ids_engine, suricata_mode, install_trivy);
    #[cfg(not(target_os = "windows"))]
    let (cmd, args) = build_unix_command(script_path, wazuh_manager, ids_engine, suricata_mode, install_trivy);

    let mut child_cmd = tokio::process::Command::new(&cmd);
    child_cmd.args(&args);
    child_cmd.env("WAZUH_MANAGER", wazuh_manager);

    // Determine the repo ref (branch/ref) for all wazuh-agent sub-repos.
    // All sub-repos (cert-oauth2, yara, snort, suricata, trivy, agent-status)
    // use the same refactor branch during development.  Admin can override
    // individual repos via AdminConfig fields.
    let default_ref = "main";
    let repo_ref = version_overrides
        .and_then(|ov| ov.wazuh_agent_repo_ref.clone())
        .unwrap_or_else(|| default_ref.to_string());
    child_cmd.env("WAZUH_AGENT_REPO_REF", &repo_ref);

    if let Some(ov) = version_overrides {
        if let Some(v) = &ov.wazuh_cert_oauth2_repo_ref { child_cmd.env("WAZUH_CERT_OAUTH2_REPO_REF", v); }
        if let Some(v) = &ov.wazuh_yara_repo_ref { child_cmd.env("WAZUH_YARA_REPO_REF", v); }
        if let Some(v) = &ov.wazuh_snort_repo_ref { child_cmd.env("WAZUH_SNORT_REPO_REF", v); }
        if let Some(v) = &ov.wazuh_suricata_repo_ref { child_cmd.env("WAZUH_SURICATA_REPO_REF", v); }
        if let Some(v) = &ov.wazuh_trivy_repo_ref { child_cmd.env("WAZUH_TRIVY_REPO_REF", v); }
        if let Some(v) = &ov.wazuh_agent_status_repo_ref { child_cmd.env("WAZUH_AGENT_STATUS_REPO_REF", v); }
    }

    if let Some(ov) = version_overrides {
        if let Some(v) = &ov.wazuh_agent_version { child_cmd.env("WAZUH_AGENT_VERSION", v); }
        if let Some(v) = &ov.wops_version { child_cmd.env("WOPS_VERSION", v); }
        if let Some(v) = &ov.wazuh_yara_version { child_cmd.env("WAZUH_YARA_VERSION", v); }
        if let Some(v) = &ov.wazuh_snort_version { child_cmd.env("WAZUH_SNORT_VERSION", v); }
        if let Some(v) = &ov.wazuh_suricata_version { child_cmd.env("WAZUH_SURICATA_VERSION", v); }
        if let Some(v) = &ov.wazuh_agent_status_version { child_cmd.env("WAZUH_AGENT_STATUS_VERSION", v); }
        if let Some(v) = &ov.wazuh_agent_repo_version { child_cmd.env("WAZUH_AGENT_REPO_VERSION", v); }
    }

    let mut child = child_cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start installer: {}", e))?;

    #[cfg(not(target_os = "windows"))]
    {
        use tokio::io::AsyncWriteExt;
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            if let Some(mut stdin) = child.stdin.take() {
                let pass = state.sudo_password.lock().unwrap().clone().unwrap_or_default();
                let _ = stdin.write_all(format!("{}\n", pass).as_bytes()).await;
                let _ = stdin.flush().await;
            }
        }
    }

    if let Some(stdout) = child.stdout.take() {
        let app_clone = app.clone();
        let mut reader = BufReader::new(stdout).lines();
        tokio::spawn(async move {
            while let Ok(Some(line)) = reader.next_line().await {
                let _ = app_clone.emit("install-log", format!("{}\n", line));
            }
        });
    }

    if let Some(stderr) = child.stderr.take() {
        let app_clone = app.clone();
        let mut reader = BufReader::new(stderr).lines();
        tokio::spawn(async move {
            while let Ok(Some(line)) = reader.next_line().await {
                let _ = app_clone.emit("install-log", format!("⚠️  {}\n", line));
            }
        });
    }

    let status = child.wait().await.map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "Script exited with code {}",
            status.code().unwrap_or(-1)
        ))
    }
}

#[cfg(not(target_os = "windows"))]
fn build_unix_command(
    _script_path: &str,
    wazuh_manager: &str,
    ids_engine: &str,
    suricata_mode: Option<&str>,
    install_trivy: bool,
) -> (String, Vec<String>) {
    let mut script_args = String::new();

    match ids_engine {
        "suricata" => {
            let mode = suricata_mode.unwrap_or("ids");
            script_args.push_str(" -s ");
            script_args.push_str(mode);
        }
        "snort" => {
            script_args.push_str(" -n");
        }
        _ => {}
    }

    if install_trivy {
        script_args.push_str(" -t");
    }

    let is_root = unsafe { libc::geteuid() == 0 };
    
    // We execute the whole chain inside bash -c.
    // If not root, we wrap the ENTIRE bash execution in sudo -S. 
    // This ensures sudo immediately reads the piped password on stdin,
    // avoiding issues on macOS where delayed sudo execution inside a bash 
    // script might lose the stdin buffer.
    let bash_command = format!(
        "curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/main/scripts/setup-agent.sh -o /tmp/setup-agent.sh && chmod +x /tmp/setup-agent.sh && env WAZUH_AGENT_REPO_REF='main' WAZUH_MANAGER='{}' bash /tmp/setup-agent.sh{}",
        wazuh_manager, script_args
    );

    if is_root {
        ("bash".to_string(), vec!["-c".to_string(), bash_command])
    } else {
        // -k forces sudo to ignore cached credentials and prompt (reading from stdin via -S)
        // -p '' removes the visual "Password:" prompt from stderr
        ("sudo".to_string(), vec![
            "-S".to_string(),
            "-p".to_string(),
            "".to_string(),
            "bash".to_string(),
            "-c".to_string(),
            bash_command
        ])
    }
}

#[cfg(target_os = "windows")]
fn build_windows_command(
    _script_path: &str,
    _wazuh_manager: &str,
    ids_engine: &str,
    suricata_mode: Option<&str>,
    install_trivy: bool,
) -> (String, Vec<String>) {
    let mut ps_script = format!(
        "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/refs/heads/main/scripts/setup-agent.ps1' -UseBasicParsing -OutFile \"$env:TEMP\\setup-agent.ps1\"; & \"$env:TEMP\\setup-agent.ps1\""
    );

    match ids_engine {
        "suricata" => {
            let mode = suricata_mode.unwrap_or("ids");
            ps_script.push_str(&format!(" -SuricataMode {}", mode));
        }
        "snort" => {
            ps_script.push_str(" -InstallSnort");
        }
        _ => {}
    }

    if install_trivy {
        ps_script.push_str(" -InstallTrivy");
    }

    (
        "powershell.exe".to_string(),
        vec![
            "-ExecutionPolicy".to_string(),
            "Bypass".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            ps_script,
        ],
    )
}

// ─── Tray Icon ────────────────────────────────────────────────────────────────

fn update_tray_icon(app: &AppHandle, status: InstallStatus) {
    if let Some(tray) = app.tray_by_id("main-tray") {
        let icon_name = match status {
            InstallStatus::Idle       => "icons/tray-idle.png",
            InstallStatus::Installing => "icons/tray-busy.png",
            InstallStatus::Done       => "icons/tray-ok.png",
            InstallStatus::Failed     => "icons/tray-err.png",
        };

        if let Ok(resource) = app.path().resource_dir() {
            let icon_path = resource.join(icon_name);
            if let Ok(icon) = tauri::image::Image::from_path(&icon_path) {
                let _ = tray.set_icon(Some(icon));
            }
        }

        let tooltip = match status {
            InstallStatus::Idle       => "GuardPost — Ready",
            InstallStatus::Installing => "GuardPost — Installing…",
            InstallStatus::Done       => "GuardPost — Enrolled ✅",
            InstallStatus::Failed     => "GuardPost — Failed ❌",
        };
        let _ = tray.set_tooltip(Some(tooltip));
    }
}

// ─── App Entry ────────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_process::init())
        .manage(AppState {
            status: Mutex::new(InstallStatus::Idle),
            sudo_password: Mutex::new(None),
        })
        .setup(|app| {
            let show  = MenuItem::with_id(app, "show",  "Open GuardPost", true, None::<&str>)?;
            let sep   = tauri::menu::PredefinedMenuItem::separator(app)?;
            let quit  = MenuItem::with_id(app, "quit",  "Quit",           true, None::<&str>)?;
            let menu  = Menu::with_items(app, &[&show, &sep, &quit])?;

            TrayIconBuilder::with_id("main-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("GuardPost — Ready")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_platform,
            is_root,
            get_script_path,
            check_components,
            load_admin_config,
            save_admin_config,
            run_install,
            run_oauth_enrollment,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running GuardPost");
}
