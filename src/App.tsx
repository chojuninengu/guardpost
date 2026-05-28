import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

type Step = "welcome" | "config" | "installing" | "done" | "failed";

interface InstallConfig {
  wazuh_manager: string;
  nids_engine: string;
  install_trivy: boolean;
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

export default function App() {
  const [step, setStep]       = useState<Step>("welcome");
  const [platform, setPlatform] = useState("");
  const [config, setConfig]   = useState<InstallConfig>({
    wazuh_manager: "",
    nids_engine: "suricata-ids",
    install_trivy: false,
  });
  const [logs, setLogs]       = useState<string[]>([]);
  const [error, setError]     = useState("");
  const [managerErr, setManagerErr] = useState("");
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    invoke<string>("get_platform").then(setPlatform);
  }, []);

  // Stream install logs
  useEffect(() => {
    const unlisten = listen<string>("install-log", (event) => {
      setLogs((prev) => [...prev, event.payload]);
      setTimeout(() => {
        logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
      }, 50);
    });

    const unlistenDone = listen<boolean>("install-done", (event) => {
      setStep(event.payload ? "done" : "failed");
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

  const handleInstall = async () => {
    const err = validateManager(config.wazuh_manager);
    if (err) { setManagerErr(err); return; }
    setLogs([]);
    setError("");
    setStep("installing");
    try {
      await invoke("run_install", { config });
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  return (
    <div className="app">
      {/* Header bar */}
      <header className="app-header">
        <div className="header-left">
          <ShieldIcon />
          <span className="app-name">GuardPost</span>
        </div>
        <div className="header-right">
          {platform && <span className="platform-badge">{platform.toUpperCase()}</span>}
        </div>
      </header>

      {/* Steps indicator */}
      {(step === "config" || step === "installing" || step === "done" || step === "failed") && (
        <StepIndicator current={step} />
      )}

      {/* Content */}
      <main className="app-main">
        {step === "welcome"    && <WelcomeScreen onNext={() => setStep("config")} />}
        {step === "config"     && (
          <ConfigScreen
            config={config}
            setConfig={setConfig}
            managerErr={managerErr}
            setManagerErr={setManagerErr}
            validateManager={validateManager}
            onInstall={handleInstall}
          />
        )}
        {step === "installing" && <InstallingScreen logs={logs} logRef={logRef} />}
        {step === "done"       && <DoneScreen />}
        {step === "failed"     && <FailedScreen logs={logs} logRef={logRef} error={error} onRetry={() => setStep("config")} />}
      </main>
    </div>
  );
}

// ─── Welcome ──────────────────────────────────────────────────────────────────

function WelcomeScreen({ onNext }: { onNext: () => void }) {
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
        The process takes a few minutes and requires an internet connection.
      </p>
      <div className="welcome-bullets">
        <Bullet icon="🛡️" text="Installs Wazuh security agent" />
        <Bullet icon="🔐" text="Sets up certificate-based authentication" />
        <Bullet icon="🌐" text="Activates network intrusion detection" />
        <Bullet icon="🔍" text="Enables USB threat monitoring" />
      </div>
      <button className="btn-primary" onClick={onNext}>
        Get Started
        <ArrowRight />
      </button>
      <p className="welcome-note">Administrator privileges will be requested during installation.</p>
    </div>
  );
}

// ─── Config ───────────────────────────────────────────────────────────────────

function ConfigScreen({
  config, setConfig, managerErr, setManagerErr, validateManager, onInstall,
}: {
  config: InstallConfig;
  setConfig: React.Dispatch<React.SetStateAction<InstallConfig>>;
  managerErr: string;
  setManagerErr: (s: string) => void;
  validateManager: (s: string) => string;
  onInstall: () => void;
}) {
  return (
    <div className="screen config-screen" style={{ animation: "fadeUp 0.4s ease both" }}>
      <h2 className="section-title">Configuration</h2>

      {/* Manager URL */}
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

      {/* NIDS */}
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

      {/* Trivy */}
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

      <button
        className="btn-primary"
        onClick={onInstall}
        disabled={!config.wazuh_manager.trim()}
      >
        Install Now
        <ArrowRight />
      </button>
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

// ─── Done ─────────────────────────────────────────────────────────────────────

function DoneScreen() {
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
        <Bullet icon="✅" text="Authentication configured" />
        <Bullet icon="✅" text="Network monitoring active" />
      </div>
      <p className="done-tray-note">
        💡 GuardPost lives in your system tray. You can close this window safely.
      </p>
    </div>
  );
}

// ─── Failed ───────────────────────────────────────────────────────────────────

function FailedScreen({
  logs, logRef, error, onRetry,
}: {
  logs: string[];
  logRef: React.RefObject<HTMLDivElement>;
  error: string;
  onRetry: () => void;
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
        <p className="failed-hint">If the problem persists, contact your IT administrator and share the log above.</p>
      </div>
    </div>
  );
}

// ─── Step Indicator ───────────────────────────────────────────────────────────

function StepIndicator({ current }: { current: Step }) {
  const steps = [
    { id: "config",     label: "Configure" },
    { id: "installing", label: "Install" },
    { id: "done",       label: "Complete" },
  ];
  const activeIdx = steps.findIndex((s) =>
    current === "failed" ? s.id === "installing" : s.id === current
  );

  return (
    <div className="step-indicator">
      {steps.map((s, i) => (
        <div key={s.id} className={`step-item ${i <= activeIdx ? "step-item--active" : ""} ${i === activeIdx && current === "failed" ? "step-item--error" : ""}`}>
          <div className="step-dot">{i < activeIdx ? "✓" : i + 1}</div>
          <span className="step-label">{s.label}</span>
          {i < steps.length - 1 && <div className={`step-line ${i < activeIdx ? "step-line--done" : ""}`} />}
        </div>
      ))}
    </div>
  );
}

// ─── Tiny helpers ─────────────────────────────────────────────────────────────

function Bullet({ icon, text }: { icon: string; text: string }) {
  return (
    <div className="bullet">
      <span>{icon}</span>
      <span>{text}</span>
    </div>
  );
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
