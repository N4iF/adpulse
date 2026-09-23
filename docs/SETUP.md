# SETUP — preparing a machine to develop ADPulse نبض

Primary machine: **the lab domain controller `DC01`** (Windows Server 2022 in VMware, D30). The same steps
work on the host PC or the laptop. Commands are Windows PowerShell 5.1. Steps marked **[admin]** need an
elevated PowerShell; Naif does them, an AI session cannot.

## 1. Tools (Windows Server 2022 has no winget; use the official installers)

| Tool | Install | Check |
|---|---|---|
| Git for Windows (also gives Claude Code its Bash tool) | installer from https://git-scm.com/download/win, then `Git-<ver>-64-bit.exe /VERYSILENT /NORESTART` **[admin]** | `git --version` |
| Python **3.12** (not 3.13/3.14) | installer from https://www.python.org/downloads/, then `python-3.12.<x>-amd64.exe /quiet InstallAllUsers=1 PrependPath=1` **[admin]** | `py -3.12 --version` |
| uv | `irm https://astral.sh/uv/install.ps1 \| iex` (no admin) | `uv --version` |
| GitHub CLI | `.msi` from https://github.com/cli/cli/releases/latest, then `msiexec /i gh_<ver>_windows_amd64.msi /quiet` **[admin]** | `gh --version` |
| Claude Code | `irm https://claude.ai/install.ps1 \| iex` (native installer, no Node.js, no admin) | new window, `claude --version` |
| Node.js 24 LTS | only for the app repo after 15 Oct: https://nodejs.org | `node --version` |

Open a new PowerShell window after installing so PATH is refreshed. Set git identity once:

```powershell
git config --global user.name "Naif Al Anazi"
git config --global user.email "n4if.dev@gmail.com"
git config --global core.autocrlf false
```

If Windows Defender or a policy blocks a tool, replace the tool rather than adding an exclusion (D28).

## 2. Sign in (Naif)

```powershell
gh auth login        # GitHub.com, HTTPS, log in with a browser
claude               # first run opens the login flow in Edge on the VM
```

If the browser on the VM cannot finish the login, Claude Code shows a code or a URL to copy; complete it
in any browser and paste the code back.

## 3. Clone the workspace

```powershell
New-Item -ItemType Directory -Force C:\ADPulse | Out-Null
Set-Location C:\ADPulse
gh repo clone N4iF/adpulse
gh repo clone N4iF/adpulse-notes
Copy-Item adpulse-notes\workspace\CLAUDE.md, adpulse-notes\workspace\WORKSPACE.md C:\ADPulse\
```

The root `CLAUDE.md` carries Naif's working preferences to every session, because assistant memory does
not move between machines.

## 4. Python environment

```powershell
Set-Location C:\ADPulse\adpulse
uv sync             # installs adsnap and adrules (editable) + dev tools from uv.lock
uv run pytest       # exit code 5 = "no tests collected"; expected until the first test exists
uv run ruff check
```

## 5. `.env` at `C:\ADPulse\adpulse\.env` (git-ignored, never committed)

```
ADPULSE_DC=dc01.corp.local          # DNS name, not IP: LDAPS validates the hostname
ADPULSE_DOMAIN=corp.local
ADPULSE_USER=adpulse.reader@corp.local
ADPULSE_PASSWORD=...
ADPULSE_MODE=standard
ADPULSE_CA_CERT=lab/dc01-ldaps.cer  # the lab DC's self-signed certificate, exported by Seed.ps1
```

Use the real names from "Lab inventory" in `lab/README.md` if they differ.

## 6. Start working

```powershell
Set-Location C:\ADPulse
claude
```

Start Claude Code at the workspace root so it loads the root `CLAUDE.md`; it reads `adpulse/CLAUDE.md`
when it works inside that repo. The first message of every session: "read PROJECT-STATUS and continue".
Before stopping, follow `docs/HANDOFF.md`. Before Naif reverts a VMware snapshot, everything must be
pushed (`lab/README.md` → Snapshot discipline).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `claude` not found after install | open a new PowerShell window |
| `uv sync` fails copying a file with "virus or potentially unwanted software" | a dependency tripped Defender; replace it (D28), do not add an exclusion |
| LDAPS: certificate verify failed | use the DC's DNS name, set `ADPULSE_CA_CERT`, or pass `--insecure-lab` (lab only) |
| `&&` is not a valid statement separator | Windows PowerShell 5.1: use `;` or `if ($?) { … }` |
