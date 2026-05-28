# GuardPost

> A friendly desktop installer for the [Wazuh](https://wazuh.com) security agent — built with Tauri (Rust + React).

GuardPost wraps the ADORSYS-GIS `wazuh-agent` enrollment scripts in a polished, non-technical UI. Non-technical users open the app, enter their Wazuh manager address, pick their network protection engine, and click **Install Now**. GuardPost handles the rest in the background.

---

## Features

- 🛡️ Guided wizard — no terminal required
- 📺 Live installation log streamed to the UI
- 🔔 System tray icon with status (idle / installing / enrolled / failed)
- 🖥️ Cross-platform — Linux, macOS, Windows
- 📦 Distributed via APT, Homebrew, Chocolatey, and direct download

---

## Install

### Linux (Debian / Ubuntu)

```bash
curl -fsSL https://chojuninengu.github.io/guardpost/gpg.key | sudo apt-key add -
echo "deb https://chojuninengu.github.io/guardpost/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/guardpost.list
sudo apt update && sudo apt install guardpost
```

### macOS

```bash
brew tap chojuninengu/guardpost
brew install guardpost
```

### Windows

```powershell
choco install guardpost
```

### Direct download

Download the latest installer from [GitHub Releases](../../releases).

| Platform | File |
|----------|------|
| Linux    | `.deb` (Debian/Ubuntu) or `.AppImage` |
| macOS    | `.dmg` |
| Windows  | `.exe` (NSIS installer) |

---

## Development

### Prerequisites

- [Rust](https://rustup.rs) stable
- [Node.js](https://nodejs.org) 20+
- Platform build dependencies (see [Tauri prerequisites](https://tauri.app/start/prerequisites/))

### Linux extra dependencies

```bash
sudo apt-get install -y \
  libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf libgtk-3-dev
```

### Setup

```bash
# 1. Clone
git clone https://github.com/chojuninengu/guardpost
cd guardpost

# 2. Fetch the bundled agent scripts
bash scripts/fetch-scripts.sh

# 3. Install frontend dependencies
npm install

# 4. Run in development mode
npm run tauri dev
```

### Build release

```bash
npm run tauri build
```

Artifacts are placed in `src-tauri/target/release/bundle/`.

---

## Release process

1. Bump `version` in `package.json` and `src-tauri/tauri.conf.json`
2. Create and push a tag: `git tag v0.2.0 && git push origin v0.2.0`
3. GitHub Actions will:
   - Build installers for all three platforms
   - Create a draft GitHub Release with all artifacts attached
   - Publish the release
   - Push the `.deb` to the APT repo on `gh-pages`
   - Update the Homebrew tap formula
   - Push the package to Chocolatey

---

## Secrets required

| Secret | Description |
|--------|-------------|
| `APT_GPG_PRIVATE_KEY` | GPG private key for signing the APT repo |
| `APT_GPG_PASSPHRASE`  | Passphrase for the GPG key |
| `HOMEBREW_TAP_TOKEN`  | GitHub PAT with write access to `homebrew-guardpost` repo |
| `CHOCO_API_KEY`       | Chocolatey community API key |

---

## Repository companions

| Repo | Purpose |
|------|---------|
| `guardpost` | This repo — the app and all CI/CD |
| `homebrew-guardpost` | Homebrew tap (auto-updated by CI) |
| `ADORSYS-GIS/wazuh-agent` | The upstream agent scripts this app wraps |

---

## Architecture

```
guardpost/
├── src/                    # React frontend (wizard UI)
│   ├── App.tsx             # Main wizard component
│   ├── App.css             # Design system & component styles
│   └── index.css           # Global CSS variables & animations
├── src-tauri/
│   ├── src/
│   │   ├── main.rs         # Binary entry point
│   │   └── lib.rs          # Tauri commands, tray, install runner
│   └── tauri.conf.json     # Tauri configuration
├── scripts/
│   ├── fetch-scripts.sh    # Build-time script fetcher
│   ├── setup-agent.sh      # Bundled Linux/macOS installer (fetched at build)
│   └── setup-agent.ps1     # Bundled Windows installer (fetched at build)
└── .github/workflows/
    ├── ci.yml              # Build on every PR / push
    ├── release.yml         # Build & publish on tag
    └── publish.yml         # Push to APT / Homebrew / Chocolatey
```

---

## Credits

Built on top of [ADORSYS-GIS/wazuh-agent](https://github.com/ADORSYS-GIS/wazuh-agent).

---

## License

MIT
