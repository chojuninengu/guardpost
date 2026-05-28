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
}

// ─── Tauri Commands ───────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, Clone)]
pub struct InstallConfig {
    pub wazuh_manager: String,
    pub nids_engine: String,      // "suricata-ids" | "suricata-ips" | "snort"
    pub install_trivy: bool,
}

/// Detect the current platform
#[tauri::command]
fn get_platform() -> String {
    #[cfg(target_os = "windows")]
    return "windows".to_string();
    #[cfg(target_os = "macos")]
    return "macos".to_string();
    #[cfg(target_os = "linux")]
    return "linux".to_string();
}

/// Return the path to the bundled script for this platform
#[tauri::command]
fn get_script_path(app: AppHandle) -> Result<String, String> {
    let resource_path = app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?;

    #[cfg(target_os = "windows")]
    let script = resource_path.join("scripts").join("setup-agent.ps1");
    #[cfg(not(target_os = "windows"))]
    let script = resource_path.join("scripts").join("setup-agent.sh");

    Ok(script.to_string_lossy().to_string())
}

/// Run the install script, streaming output back to the frontend line by line
#[tauri::command]
async fn run_install(
    app: AppHandle,
    config: InstallConfig,
    state: State<'_, AppState>,
) -> Result<(), String> {
    {
        let mut s = state.status.lock().unwrap();
        *s = InstallStatus::Installing;
    }
    update_tray_icon(&app, InstallStatus::Installing);

    let script_path = get_script_path(app.clone())?;

    // Build env vars
    let manager = config.wazuh_manager.trim().to_string();
    let (ids_engine, suricata_mode) = match config.nids_engine.as_str() {
        "suricata-ids" => ("suricata".to_string(), Some("ids".to_string())),
        "suricata-ips" => ("suricata".to_string(), Some("ips".to_string())),
        "snort"        => ("snort".to_string(),    None),
        _              => ("suricata".to_string(), Some("ids".to_string())),
    };

    // Emit start event
    let _ = app.emit("install-log", "🛡️  GuardPost starting installation...\n");

    let result = run_script_with_streaming(
        &app,
        &script_path,
        &manager,
        &ids_engine,
        suricata_mode.as_deref(),
        config.install_trivy,
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

            // System notification
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

// ─── Script Runner ────────────────────────────────────────────────────────────

async fn run_script_with_streaming(
    app: &AppHandle,
    script_path: &str,
    wazuh_manager: &str,
    ids_engine: &str,
    suricata_mode: Option<&str>,
    install_trivy: bool,
) -> Result<(), String> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};

    #[cfg(target_os = "windows")]
    let (cmd, args) = build_windows_command(script_path, wazuh_manager, ids_engine, suricata_mode, install_trivy);
    #[cfg(not(target_os = "windows"))]
    let (cmd, args) = build_unix_command(script_path, wazuh_manager, ids_engine, suricata_mode, install_trivy);

    let mut child = tokio::process::Command::new(&cmd)
        .args(&args)
        .env("WAZUH_MANAGER", wazuh_manager)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start installer: {}", e))?;

    // Stream stdout
    if let Some(stdout) = child.stdout.take() {
        let app_clone = app.clone();
        let mut reader = BufReader::new(stdout).lines();
        tokio::spawn(async move {
            while let Ok(Some(line)) = reader.next_line().await {
                let _ = app_clone.emit("install-log", format!("{}\n", line));
            }
        });
    }

    // Stream stderr
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
    script_path: &str,
    _wazuh_manager: &str,
    ids_engine: &str,
    suricata_mode: Option<&str>,
    install_trivy: bool,
) -> (String, Vec<String>) {
    let mut script_args: Vec<String> = vec![script_path.to_string()];

    match ids_engine {
        "suricata" => {
            let mode = suricata_mode.unwrap_or("ids");
            script_args.push("-s".to_string());
            script_args.push(mode.to_string());
        }
        "snort" => {
            script_args.push("-n".to_string());
        }
        _ => {}
    }

    if install_trivy {
        script_args.push("-t".to_string());
    }

    // Try pkexec first (GUI sudo), fall back to sudo
    // We wrap the whole thing: sudo bash <script> <args>
    let mut args = vec!["-E".to_string(), "bash".to_string()];
    args.extend(script_args);

    ("sudo".to_string(), args)
}

#[cfg(target_os = "windows")]
fn build_windows_command(
    script_path: &str,
    _wazuh_manager: &str,
    ids_engine: &str,
    suricata_mode: Option<&str>,
    install_trivy: bool,
) -> (String, Vec<String>) {
    let mut ps_args = format!(
        "-ExecutionPolicy Bypass -NoProfile -File \"{}\"",
        script_path
    );

    match ids_engine {
        "suricata" => {
            let mode = suricata_mode.unwrap_or("ids");
            ps_args.push_str(&format!(" -SuricataMode {}", mode));
        }
        "snort" => {
            ps_args.push_str(" -InstallSnort");
        }
        _ => {}
    }

    if install_trivy {
        ps_args.push_str(" -InstallTrivy");
    }

    (
        "powershell.exe".to_string(),
        vec![ps_args],
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
        })
        .setup(|app| {
            // Build tray menu
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
            get_script_path,
            run_install,
        ])
        .on_window_event(|window, event| {
            // Minimise to tray instead of closing
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running GuardPost");
}
