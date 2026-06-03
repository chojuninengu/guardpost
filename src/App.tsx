import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

type Tab = "install" | "enrollment" | "components" | "admin";
type Step = "welcome" | "config" | "installing" | "enrolling" | "done" | "failed";

interface InstallConfig {
  wazuh_manager: string;
  nids_engine: string;
  install_trivy: boolean;
  version_overrides: AdminConfig | null;
}

interface AdminConfig {
  wazuh_agent_version: string | null;
  wops_version: string | null;
  wazuh_yara_version: string | null;
  wazuh_snort_version: string | null;
  wazuh_suricata_version: string | null;
  wazuh_agent_status_version: string | null;
  wazuh_agent_repo_version: string | null;
  wazuh_agent_repo_ref: string | null;
  wazuh_cert_oauth2_repo_ref: string | null;
  wazuh_yara_repo_ref: string | null;
  wazuh_snort_repo_ref: string | null;
  wazuh_suricata_repo_ref: string | null;
  wazuh_trivy_repo_ref: string | null;
  wazuh_agent_status_repo_ref: string | null;
}

interface ComponentStatus {
  name: string;
  installed: boolean;
  version: string | null;
  path: string;
}

const NIDS_OPTIONS = [
  {
    id: "suricata-ids",
    label: "Suricata — Detection Mode",
    description: "Monitors your network traffic and alerts you when something suspicious is detected. Recommended for most users.",
    badge: "RECOMMENDED",
  },
  {
    id: "suricata-ips",
    label: "Suricata — Prevention Mode",
    description: "Actively blocks suspicious network traffic in real time. Best for high-security environments.",
    badge: "ADVANCED",
  },
  {
    id: "snort",
    label: "Snort",
    description: "A battle-tested network intrusion detection system. Great alternative if you already use Snort.",
    badge: null,
  },
];

const ADMIN_FIELDS: { key: keyof AdminConfig; label: string; default: string }[] = [
  { key: "wazuh_agent_version",       label: "Wazuh Agent Version",      default: "4.14.2-1" },
  { key: "wops_version",              label: "OAuth2 Client Version",    default: "0.4.2" },
  { key: "wazuh_yara_version",        label: "Yara Version",             default: "0.3.14" },
  { key: "wazuh_snort_version",       label: "Snort Version",            default: "0.2.4" },
  { key: "wazuh_suricata_version",    label: "Suricata Version",         default: "0.2.0" },
  { key: "wazuh_agent_status_version", label: "Agent Status Version",    default: "0.4.1-rc4-user" },
  { key: "wazuh_agent_repo_version",  label: "Agent Repo Tag",           default: "1.9.0-rc.1" },
  { key: "wazuh_agent_repo_ref",      label: "Agent Repo Ref (branch)",  default: "refs/heads/main" },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("install");
  const [step, setStep]       = useState<Step>("welcome");
  const [platform, setPlatform] = useState("");
  const [isRoot, setIsRoot]   = useState(true);
  const [sudoPassword, setSudoPassword] = useState("");
  const [hasSudo, setHasSudo] = useState(false);
  const [oauthIssuer, setOauthIssuer] = useState("https://login.dev.wazuh.adorsys.team/realms/test-adorsys");
  const [oauthEndpoint, setOauthEndpoint] = useState("https://cert.dev.wazuh.adorsys.team/api/register-agent");
  const [enrollLogs, setEnrollLogs] = useState<string[]>([]);
  const [enrollRunning, setEnrollRunning] = useState(false);
  const [enrollDone, setEnrollDone] = useState(false);
  const enrollLogRef = useRef<HTMLDivElement>(null);
  const [config, setConfig]   = useState<InstallConfig>({
    wazuh_manager: "",
    nids_engine: "suricata-ids",
    install_trivy: false,
    version_overrides: null,
  });
  const [logs, setLogs]       = useState<string[]>([]);
  const [error, setError]     = useState("");
  const [managerErr, setManagerErr] = useState("");
  const [oauthLogs, setOauthLogs] = useState<string[]>([]);
  const [oauthDone, setOauthDone] = useState(false);
  const [components, setComponents] = useState<ComponentStatus[]>([]);
  const [checking, setChecking] = useState(false);
  const [adminConfig, setAdminConfig] = useState<AdminConfig>({
    wazuh_agent_version: null,
    wops_version: null,
    wazuh_yara_version: null,
    wazuh_snort_version: null,
    wazuh_suricata_version: null,
    wazuh_agent_status_version: null,
    wazuh_agent_repo_version: null,
    wazuh_agent_repo_ref: null,
    wazuh_cert_oauth2_repo_ref: null,
    wazuh_yara_repo_ref: null,
    wazuh_snort_repo_ref: null,
    wazuh_suricata_repo_ref: null,
    wazuh_trivy_repo_ref: null,
    wazuh_agent_status_repo_ref: null,
  });
  const logRef = useRef<HTMLDivElement>(null);
  const oauthLogRef = useRef<HTMLDivElement>(null);
  // Refs so closures always see the latest issuer/endpoint values
  const issuerRef = useRef(oauthIssuer);
  const endpointRef = useRef(oauthEndpoint);
  useEffect(() => { issuerRef.current = oauthIssuer; }, [oauthIssuer]);
  useEffect(() => { endpointRef.current = oauthEndpoint; }, [oauthEndpoint]);

  useEffect(() => {
    invoke<string>("get_platform").then(setPlatform);
    invoke<boolean>("is_root").then(setIsRoot).catch(() => setIsRoot(true));
    invoke<AdminConfig>("load_admin_config").then((c) => {
      setAdminConfig(c);
      setConfig((prev) => ({ ...prev, version_overrides: c }));
    });
  }, []);

  useEffect(() => {
    const unlisten = listen<string>("install-log", (event) => {
      setLogs((prev) => [...prev, event.payload]);
      setTimeout(() => {
        logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
      }, 50);
    });

    const unlistenDone = listen<boolean>("install-done", (event) => {
      if (event.payload) {
        // Auto-navigate to Enrollment tab and kick off enrollment
        setEnrollLogs([]);
        setEnrollDone(false);
        setEnrollRunning(true);
        setActiveTab("enrollment");
        invoke("run_oauth_enrollment", {
          issuer: issuerRef.current,
          endpoint: endpointRef.current,
          password: sudoPassword || null
        }).catch((e: unknown) => {
          setEnrollLogs((prev) => [...prev, `❌ ${String(e)}\n`]);
          setEnrollRunning(false);
        });
      } else {
        setStep("failed");
      }
    });

    return () => {
      unlisten.then((f) => f());
      unlistenDone.then((f) => f());
    };
  }, []);

  // Listen for oauth events on the dedicated Enrollment tab
  useEffect(() => {
    const unlisten = listen<string>("oauth-output", (event) => {
      setEnrollLogs((prev) => [...prev, event.payload]);
      setOauthLogs((prev) => [...prev, event.payload]);
      setTimeout(() => {
        oauthLogRef.current?.scrollTo({ top: oauthLogRef.current.scrollHeight, behavior: "smooth" });
        enrollLogRef.current?.scrollTo({ top: enrollLogRef.current.scrollHeight, behavior: "smooth" });
      }, 50);
    });

    const unlistenDone = listen<boolean>("oauth-done", (event) => {
      setEnrollRunning(false);
      setEnrollDone(event.payload);
      setOauthDone(true);
    });

    return () => {
      unlisten.then((f) => f());
      unlistenDone.then((f) => f());
    };
  }, []);

  const validateManager = (val: string) => {
    if (!val.trim()) return "Wazuh manager address is required.";
    const hostPattern = /^[a-zA-Z0-9.\-]+$/;
    if (!hostPattern.test(val.trim())) return "Enter a valid hostname or IP address.";
    return "";
  };

  const handleCheck = async () => {
    setActiveTab("components");
    setChecking(true);
    try {
      const result = await invoke<ComponentStatus[]>("check_components");
      setComponents(result);
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    if (activeTab === "components" && components.length === 0) {
      handleCheck();
    }
  }, [activeTab]);

  const handleInstall = async () => {
    const err = validateManager(config.wazuh_manager);
    if (err) { setManagerErr(err); return; }
    if (!isRoot && platform !== "windows" && !sudoPassword) {
      setError("Sudo password is required for non-root users.");
      return;
    }
    setLogs([]);
    setError("");
    setOauthLogs([]);
    setOauthDone(false);
    setStep("installing");
    try {
      await invoke("run_install", { 
        config: { ...config, version_overrides: adminConfig },
        password: sudoPassword || null
      });
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleSaveAdmin = async () => {
    await invoke("save_admin_config", { config: adminConfig });
    setConfig((prev) => ({ ...prev, version_overrides: adminConfig }));
    setActiveTab("install");
  };

  const showSteps = step === "config" || step === "installing" || step === "enrolling" || step === "done" || step === "failed";

  const needsSudo = !isRoot && platform !== "" && platform !== "windows" && !hasSudo;

  if (needsSudo) {
    return (
      <SudoPromptScreen
        password={sudoPassword}
        setPassword={setSudoPassword}
        onSubmit={() => setHasSudo(true)}
      />
    );
  }

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <ShieldIcon />
          <span className="app-name">GuardPost</span>
        </div>
        <nav className="sidebar-nav">
          <button className={`nav-item ${activeTab === "install" ? "active" : ""}`} onClick={() => setActiveTab("install")}>
            <span className="nav-icon">🛡️</span> Setup
          </button>
          <button className={`nav-item ${activeTab === "enrollment" ? "active" : ""}`} onClick={() => setActiveTab("enrollment")}>
            <span className="nav-icon">🔑</span> Enrollment
          </button>
          <button className={`nav-item ${activeTab === "components" ? "active" : ""}`} onClick={() => setActiveTab("components")}>
            <span className="nav-icon">🔍</span> Components
          </button>
          <button className={`nav-item ${activeTab === "admin" ? "active" : ""}`} onClick={() => setActiveTab("admin")}>
            <span className="nav-icon">⚙️</span> Administrator
          </button>
        </nav>
        <div className="sidebar-footer">
          {platform && <span className="platform-badge">{platform.toUpperCase()} {isRoot ? "(ROOT)" : ""}</span>}
        </div>
      </aside>

      <main className="main-content">
        {activeTab === "install" && (
          <div className="tab-content">
            {showSteps && <StepIndicator current={step} />}
            {step === "welcome"   && (
              <WelcomeScreen
                onSetup={() => setStep("config")}
                onCheck={() => setActiveTab("components")}
                onAdmin={() => setActiveTab("admin")}
                checking={checking}
              />
            )}
            {step === "config"    && (
              <ConfigScreen
                config={config}
                setConfig={setConfig}
                managerErr={managerErr}
                setManagerErr={setManagerErr}
                validateManager={validateManager}
                onInstall={handleInstall}
                error={error}
              />
            )}
            {step === "installing" && <InstallingScreen logs={logs} logRef={logRef} />}
            {step === "enrolling"  && (
              <EnrollingScreen logs={oauthLogs} logRef={oauthLogRef} done={oauthDone} />
            )}
            {step === "done"      && <DoneScreen onReset={() => setStep("welcome")} />}
            {step === "failed"    && (
              <FailedScreen
                logs={logs}
                logRef={logRef}
                error={error}
                onRetry={() => setStep("config")}
                onHome={() => setStep("welcome")}
              />
            )}
          </div>
        )}
        {activeTab === "enrollment" && (
          <EnrollmentTab
            issuer={oauthIssuer}
            setIssuer={setOauthIssuer}
            endpoint={oauthEndpoint}
            setEndpoint={setOauthEndpoint}
            logs={enrollLogs}
            logRef={enrollLogRef}
            running={enrollRunning}
            done={enrollDone}
            onRun={async () => {
              setEnrollLogs([]);
              setEnrollDone(false);
              setEnrollRunning(true);
              try {
                await invoke("run_oauth_enrollment", {
                  issuer: oauthIssuer,
                  endpoint: oauthEndpoint,
                  password: sudoPassword || null
                });
              } catch (e: unknown) {
                setEnrollLogs((prev) => [...prev, `❌ ${String(e)}\n`]);
                setEnrollRunning(false);
              }
            }}
          />
        )}
        {activeTab === "components" && (
          <ComponentCheckScreen
            components={components}
            checking={checking}
            onRefresh={handleCheck}
          />
        )}
        {activeTab === "admin" && (
          <AdminSettingsScreen
            config={adminConfig}
            setConfig={setAdminConfig}
            onSave={handleSaveAdmin}
          />
        )}
      </main>
    </div>
  );
}

// ─── Welcome (Landing) ────────────────────────────────────────────────────────

function WelcomeScreen({
  onSetup, onCheck, onAdmin, checking,
}: {
  onSetup: () => void;
  onCheck: () => void;
  onAdmin: () => void;
  checking: boolean;
}) {
  return (
    <div className="screen welcome-screen" style={{ animation: "fadeUp 0.4s ease both" }}>
      <div className="welcome-glow" />
      <div className="welcome-icon-wrap">
        <div className="pulse-ring" />
        <ShieldLarge />
      </div>
      <h1 className="welcome-title">Security Agent Setup</h1>
      <p className="welcome-sub">
        GuardPost installs and enrolls the Wazuh security agent on this device.
      </p>

      <div className="landing-cards">
        <button className="landing-card" onClick={onSetup}>
          <span className="landing-icon">🛡️</span>
          <span className="landing-card-title">Full Setup</span>
          <span className="landing-card-desc">Install Wazuh agent, configure OAuth2 enrollment, and set up threat detection.</span>
        </button>

        <button className="landing-card" onClick={onCheck} disabled={checking}>
          <span className="landing-icon">🔍</span>
          <span className="landing-card-title">{checking ? "Checking…" : "Check Components"}</span>
          <span className="landing-card-desc">View currently installed Wazuh components.</span>
        </button>

        <button className="landing-card" onClick={onAdmin}>
          <span className="landing-icon">⚙️</span>
          <span className="landing-card-title">Administrator</span>
          <span className="landing-card-desc">Advanced settings and version overrides.</span>
        </button>
      </div>
    </div>
  );
}

// ─── Config ───────────────────────────────────────────────────────────────────

function ConfigScreen({
  config, setConfig, managerErr, setManagerErr, validateManager, onInstall, error
}: {
  config: InstallConfig;
  setConfig: React.Dispatch<React.SetStateAction<InstallConfig>>;
  managerErr: string;
  setManagerErr: (s: string) => void;
  validateManager: (s: string) => string;
  onInstall: () => void;
  error?: string;
}) {
  return (
    <div className="screen config-screen" style={{ animation: "fadeUp 0.4s ease both" }}>
      <div className="config-top">
        <button className="btn-ghost" onClick={() => window.history.length > 1 && window.history.back()}>
          ← Back
        </button>
        <h2 className="section-title">Configuration</h2>
      </div>

      <div className="field-group">
        <label className="field-label">
          Wazuh Manager Address
          <span className="field-required">*</span>
        </label>
        <p className="field-hint">The hostname or IP address of your Wazuh server. Ask your IT admin if unsure.</p>
        <input
          className={`field-input ${managerErr ? "field-input--error" : ""}`}
          type="text"
          placeholder="e.g. wazuh.company.com or 192.168.1.10"
          value={config.wazuh_manager}
          onChange={(e) => {
            setConfig((c) => ({ ...c, wazuh_manager: e.target.value }));
            setManagerErr(validateManager(e.target.value));
          }}
        />
        {managerErr && <span className="field-error">{managerErr}</span>}
      </div>

      <div className="field-group">
        <label className="field-label">Network Protection Engine</label>
        <p className="field-hint">Monitors network traffic for threats. Choose the option that fits your environment.</p>
        <div className="nids-list">
          {NIDS_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              className={`nids-card ${config.nids_engine === opt.id ? "nids-card--selected" : ""}`}
              onClick={() => setConfig((c) => ({ ...c, nids_engine: opt.id }))}
            >
              <div className="nids-card-top">
                <span className="nids-name">{opt.label}</span>
                {opt.badge && <span className={`nids-badge nids-badge--${opt.badge.toLowerCase()}`}>{opt.badge}</span>}
              </div>
              <p className="nids-desc">{opt.description}</p>
              <div className={`nids-radio ${config.nids_engine === opt.id ? "nids-radio--on" : ""}`} />
            </button>
          ))}
        </div>
      </div>

      <div className="field-group">
        <button
          className={`toggle-card ${config.install_trivy ? "toggle-card--on" : ""}`}
          onClick={() => setConfig((c) => ({ ...c, install_trivy: !c.install_trivy }))}
        >
          <div className="toggle-card-info">
            <span className="toggle-card-title">Vulnerability Scanner (Trivy)</span>
            <span className="toggle-card-desc">Scans installed packages for known security vulnerabilities. Optional but recommended.</span>
          </div>
          <div className={`toggle-switch ${config.install_trivy ? "toggle-switch--on" : ""}`}>
            <div className="toggle-knob" />
          </div>
        </button>
      </div>

      {error && <div className="field-error form-error">{error}</div>}

      <div className="config-actions">
        <button className="btn-secondary" onClick={() => { window.location.hash = ""; window.history.back(); }}>
          Cancel
        </button>
        <button className="btn-primary" onClick={onInstall} disabled={!config.wazuh_manager.trim()}>
          Install Now
          <ArrowRight />
        </button>
      </div>
    </div>
  );
}

// ─── Installing ───────────────────────────────────────────────────────────────

function InstallingScreen({ logs, logRef }: { logs: string[]; logRef: React.RefObject<HTMLDivElement> }) {
  return (
    <div className="screen installing-screen" style={{ animation: "fadeUp 0.4s ease both" }}>
      <div className="installing-header">
        <div className="spinner" />
        <div>
          <h2 className="installing-title">Installing…</h2>
          <p className="installing-sub">This may take a few minutes. Please keep this window open.</p>
        </div>
      </div>
      <div className="log-box" ref={logRef}>
        {logs.map((line, i) => (
          <div key={i} className="log-line" style={{ animationDelay: `${i * 0.02}s` }}>
            {line}
          </div>
        ))}
        <div className="log-cursor">▋</div>
      </div>
    </div>
  );
}

// ─── Enrolling ────────────────────────────────────────────────────────────────

function EnrollingScreen({ logs, logRef, done }: { logs: string[]; logRef: React.RefObject<HTMLDivElement>; done: boolean }) {
  return (
    <div className="screen enrolling-screen" style={{ animation: "fadeUp 0.4s ease both" }}>
      <div className="enrolling-header">
        <div className={done ? "spinner spinner--done" : "spinner"} />
        <div>
          <h2 className="enrolling-title">{done ? "Enrollment Complete" : "Enrolling with Wazuh Manager…"}</h2>
          <p className="enrolling-sub">
            {done ? "Finalizing…" : "A browser window will open for authentication. Complete the login there."}
          </p>
        </div>
      </div>
      <div className="log-box enrolling-log-box" ref={logRef}>
        {logs.map((line, i) => <div key={i} className="log-line">{line}</div>)}
        <div className="log-cursor">▋</div>
      </div>
    </div>
  );
}

// ─── Done ─────────────────────────────────────────────────────────────────────

function DoneScreen({ onReset }: { onReset: () => void }) {
  return (
    <div className="screen done-screen" style={{ animation: "fadeUp 0.4s ease both" }}>
      <div className="done-icon-wrap">
        <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
          <circle cx="32" cy="32" r="32" fill="var(--accent-glow)" />
          <circle cx="32" cy="32" r="24" fill="none" stroke="var(--accent)" strokeWidth="2" />
          <path d="M20 32l9 9 15-15" stroke="var(--accent)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
      <h2 className="done-title">Enrollment Complete</h2>
      <p className="done-sub">
        This device is now protected by Wazuh. The security agent is running in the background.
        GuardPost will remain in your system tray.
      </p>
      <div className="done-bullets">
        <Bullet icon="✅" text="Wazuh agent installed and running" />
        <Bullet icon="✅" text="OAuth2 authentication configured" />
        <Bullet icon="✅" text="Network monitoring active" />
      </div>
      <p className="done-tray-note">💡 GuardPost lives in your system tray. You can close this window safely.</p>
      <button className="btn-ghost" onClick={onReset}>Start Over</button>
    </div>
  );
}

// ─── Failed ───────────────────────────────────────────────────────────────────

function FailedScreen({ logs, logRef, error, onRetry, onHome }: {
  logs: string[];
  logRef: React.RefObject<HTMLDivElement>;
  error: string;
  onRetry: () => void;
  onHome: () => void;
}) {
  return (
    <div className="screen failed-screen" style={{ animation: "fadeUp 0.4s ease both" }}>
      <div className="failed-icon">
        <svg width="52" height="52" viewBox="0 0 52 52" fill="none">
          <circle cx="26" cy="26" r="26" fill="rgba(255,77,109,0.12)" />
          <circle cx="26" cy="26" r="20" fill="none" stroke="var(--danger)" strokeWidth="2" />
          <path d="M26 16v12M26 33v2" stroke="var(--danger)" strokeWidth="2.5" strokeLinecap="round" />
        </svg>
      </div>
      <h2 className="failed-title">Installation Failed</h2>
      {error && <p className="failed-error">{error}</p>}
      <div className="log-box log-box--short" ref={logRef}>
        {logs.map((line, i) => <div key={i} className="log-line">{line}</div>)}
      </div>
      <div className="failed-actions">
        <button className="btn-primary" onClick={onRetry}>Try Again</button>
        <button className="btn-ghost" onClick={onHome}>Back to Home</button>
        <p className="failed-hint">If the problem persists, contact your IT administrator and share the log above.</p>
      </div>
    </div>
  );
}

// ─── Enrollment Tab ───────────────────────────────────────────────────────────

function EnrollmentTab({
  issuer, setIssuer, endpoint, setEndpoint, logs, logRef, running, done, onRun,
}: {
  issuer: string;
  setIssuer: (s: string) => void;
  endpoint: string;
  setEndpoint: (s: string) => void;
  logs: string[];
  logRef: React.RefObject<HTMLDivElement>;
  running: boolean;
  done: boolean;
  onRun: () => void;
}) {
  return (
    <div className="screen admin-screen" style={{ animation: "fadeUp 0.4s ease both" }}>
      <div className="admin-header">
        <h2 className="section-title">🔑 OAuth2 Enrollment</h2>
      </div>
      <p className="field-hint">
        Runs <code style={{ background: "var(--surface-2)", padding: "2px 6px", borderRadius: 4 }}>wazuh-cert-oauth2-client o-auth2</code> to
        register this agent with your Wazuh certificate authority. A browser window will open for authentication.
      </p>

      <div className="admin-fields" style={{ marginTop: 16 }}>
        <div className="field-group">
          <label className="field-label">Issuer URL</label>
          <p className="field-hint">The Keycloak / OIDC issuer for your Wazuh deployment.</p>
          <input
            className="field-input"
            type="text"
            value={issuer}
            onChange={(e) => setIssuer(e.target.value)}
            disabled={running}
          />
        </div>

        <div className="field-group">
          <label className="field-label">Endpoint URL</label>
          <p className="field-hint">The cert-manager API endpoint for agent registration.</p>
          <input
            className="field-input"
            type="text"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            disabled={running}
          />
        </div>
      </div>

      <div className="admin-actions" style={{ marginBottom: 16 }}>
        <button className="btn-primary" onClick={onRun} disabled={running || !issuer || !endpoint}>
          {running ? (
            <><span className="spinner" style={{ width: 14, height: 14, marginRight: 8 }} />Enrolling…</>
          ) : done ? "✅ Re-run Enrollment" : "Run Enrollment"}
        </button>
        {done && <span style={{ color: "var(--accent)", marginLeft: 12, fontSize: 14 }}>✅ Last run succeeded</span>}
      </div>

      {logs.length > 0 && (
        <div className="log-box" ref={logRef} style={{ maxHeight: 280 }}>
          {logs.map((line, i) => (
            <div key={i} className="log-line">{line}</div>
          ))}
          {running && <div className="log-cursor">▋</div>}
        </div>
      )}
    </div>
  );
}

// ─── Component Check ──────────────────────────────────────────────────────────

function ComponentCheckScreen({ components, checking, onRefresh }: {
  components: ComponentStatus[];
  checking: boolean;
  onRefresh: () => void;
}) {
  return (
    <div className="screen check-screen" style={{ animation: "fadeUp 0.4s ease both" }}>
      <div className="check-header">
        <h2 className="section-title">Installed Components</h2>
        <button className="btn-ghost" onClick={onRefresh} disabled={checking}>
          {checking ? "Refreshing..." : "Refresh"}
        </button>
      </div>
      <p className="field-hint">These are the Wazuh-related components detected on this system.</p>

      <div className="check-list">
        {components.map((c) => (
          <div key={c.name} className={`check-card ${c.installed ? "check-card--ok" : "check-card--missing"}`}>
            <div className="check-card-left">
              <span className="check-card-icon">{c.installed ? "✅" : "❌"}</span>
              <div>
                <span className="check-card-name">{c.name}</span>
                {c.version && <span className="check-card-ver">{c.version}</span>}
                <span className="check-card-path">{c.path}</span>
              </div>
            </div>
            <span className={`check-badge ${c.installed ? "check-badge--ok" : "check-badge--missing"}`}>
              {c.installed ? "Installed" : "Missing"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Admin Settings ───────────────────────────────────────────────────────────

function AdminSettingsScreen({ config, setConfig, onSave }: {
  config: AdminConfig;
  setConfig: React.Dispatch<React.SetStateAction<AdminConfig>>;
  onSave: () => void;
}) {
  return (
    <div className="screen admin-screen" style={{ animation: "fadeUp 0.4s ease both" }}>
      <div className="admin-header">
        <h2 className="section-title">Administrator Settings</h2>
      </div>
      <p className="field-hint">Override version tags and repository branches used during installation. Leave blank for defaults.</p>

      <div className="admin-fields">
        {ADMIN_FIELDS.map((field) => (
          <div key={field.key} className="field-group">
            <label className="field-label">{field.label}</label>
            <input
              className="field-input"
              type="text"
              placeholder={field.default}
              value={config[field.key] ?? ""}
              onChange={(e) => setConfig((c) => ({ ...c, [field.key]: e.target.value || null }))}
            />
          </div>
        ))}
      </div>

      <div className="admin-actions">
        <button className="btn-primary" onClick={onSave}>Save Settings</button>
      </div>
    </div>
  );
}

// ─── Step Indicator ───────────────────────────────────────────────────────────

function StepIndicator({ current }: { current: Step }) {
  const steps = [
    { id: "config",     label: "Configure" },
    { id: "installing", label: "Install" },
    { id: "enrolling",  label: "Enroll" },
    { id: "done",       label: "Complete" },
  ];

  const errorStep = current === "failed" ? "installing" : null;

  const activeIdx = steps.findIndex((s) => {
    if (errorStep && s.id === errorStep) return true;
    if (current === "done") return s.id === "done";
    if (current === "enrolling") return s.id === "enrolling";
    return s.id === current;
  });

  const getDotContent = (i: number, s: typeof steps[0]) => {
    if (current === "failed" && s.id === errorStep) return "!";
    if (i < activeIdx || (i === activeIdx && current === "done")) return "✓";
    return i + 1;
  };

  return (
    <div className="step-indicator">
      {steps.map((s, i) => (
        <div key={s.id} className={`step-item ${i <= activeIdx ? "step-item--active" : ""} ${current === "failed" && s.id === errorStep ? "step-item--error" : ""}`}>
          <div className="step-dot">{getDotContent(i, s)}</div>
          <span className="step-label">{s.label}</span>
          {i < steps.length - 1 && <div className={`step-line ${i < activeIdx ? "step-line--done" : ""}`} />}
        </div>
      ))}
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function Bullet({ icon, text }: { icon: string; text: string }) {
  return <div className="bullet"><span>{icon}</span><span>{text}</span></div>;
}

function ShieldIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L4 6v6c0 5.25 3.5 10.14 8 11.35C16.5 22.14 20 17.25 20 12V6L12 2z" fill="var(--accent)" opacity="0.2" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M9 12l2 2 4-4" stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ShieldLarge() {
  return (
    <svg width="72" height="72" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L4 6v6c0 5.25 3.5 10.14 8 11.35C16.5 22.14 20 17.25 20 12V6L12 2z" fill="var(--accent)" opacity="0.15" stroke="var(--accent)" strokeWidth="1.2" strokeLinejoin="round" />
      <path d="M9 12l2 2 4-4" stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ArrowRight() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ marginLeft: 6 }}>
      <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ─── Sudo Prompt ──────────────────────────────────────────────────────────────

function SudoPromptScreen({ password, setPassword, onSubmit }: {
  password: string;
  setPassword: (s: string) => void;
  onSubmit: () => void;
}) {
  const [error, setError] = useState("");
  const [verifying, setVerifying] = useState(false);

  const handleSubmit = async () => {
    if (!password) return;
    setVerifying(true);
    setError("");
    try {
      const ok = await invoke<boolean>("verify_sudo", { password });
      if (ok) {
        onSubmit();
      } else {
        setError("Incorrect password, please try again.");
        setPassword("");
      }
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="app-layout" style={{ alignItems: "center", justifyContent: "center", display: "flex" }}>
      <div className="screen config-screen" style={{ animation: "fadeUp 0.4s ease both", maxWidth: "420px" }}>
        <div className="welcome-icon-wrap" style={{ margin: "0 auto", marginBottom: "20px" }}>
          <ShieldLarge />
        </div>
        <h2 className="section-title" style={{ textAlign: "center" }}>Authentication Required</h2>
        <p className="field-hint" style={{ textAlign: "center" }}>
          GuardPost needs administrative privileges to install Wazuh components.
        </p>

        {error && (
          <div style={{ color: "var(--danger)", textAlign: "center", marginBottom: "12px", fontSize: "14px", background: "var(--danger-bg, rgba(239, 68, 68, 0.1))", padding: "8px", borderRadius: "6px" }}>
            {error}
          </div>
        )}

        <div className="field-group" style={{ marginTop: "10px" }}>
          <input
            className="field-input"
            type="password"
            placeholder="Enter your system password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              setError("");
            }}
            onKeyDown={(e) => e.key === "Enter" && password && handleSubmit()}
            disabled={verifying}
            autoFocus
          />
        </div>

        <button 
          className="btn-primary" 
          onClick={handleSubmit} 
          disabled={!password || verifying}
          style={{ marginTop: "10px" }}
        >
          {verifying ? (
            <><span className="spinner" style={{ width: 14, height: 14, marginRight: 8 }} />Verifying…</>
          ) : "Continue"}
        </button>
      </div>
    </div>
  );
}
