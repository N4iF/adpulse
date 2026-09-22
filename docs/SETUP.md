# SETUP — developing ADPulse نبض on a new machine

Works on the 80 GB desktop (full lab) and the 16 GB laptop (lite lab). Windows 11 Pro assumed.

## 1. Tools

| Tool | Version | Install |
|------|---------|---------|
| git | 2.4x | https://git-scm.com — set `user.name` / `user.email` |
| GitHub CLI | 2.9x | `winget install GitHub.cli` then `gh auth login` |
| Python | **3.12** (not 3.13/3.14 — some AD libraries lack wheels) | `winget install Python.Python.3.12` |
| uv | latest | `pip install uv` or `winget install astral-sh.uv` |
| Node.js | **24 LTS** (Node 25 is EOL) | `winget install OpenJS.NodeJS.LTS` or `fnm install 24` |
| pnpm | 9+ | `npm i -g pnpm` |
| Hyper-V | Windows feature | `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All` (admin) |
| Playwright browsers (for PDF in apps) | — | `pnpm dlx playwright install chromium` (app repos only) |

## 2. Clone

```bash
mkdir -p /e/Projects/ADPulse && cd /e/Projects/ADPulse
gh repo clone N4iF/adpulse
gh repo clone N4iF/adpulse-notes      # private planning repo
```

## 3. Python environment

```bash
cd /e/Projects/ADPulse/adpulse
uv sync            # creates .venv with both packages installed editable
uv run pytest
uv run ruff check
```

## 4. Lab

See `lab/README.md`. Summary: Hyper-V Internal switch `LABNET` 10.10.10.0/24 (host 10.10.10.1),
`DC01` 10.10.10.10 (`corp.local`), optional `SRV01` (AD CS) and `WS01`. Windows Server 2022 evaluation ISO.
On the laptop import only the `DC01` checkpoint (`Export-LiteLab.ps1`).

Host name resolution for the lab: add to `C:\Windows\System32\drivers\etc\hosts`
```
10.10.10.10  dc01.corp.local corp.local
10.10.10.20  srv01.corp.local
```
or point the `LABNET` adapter's DNS at 10.10.10.10.

## 5. Per-host `.env` (never committed)

```
ADPULSE_DC=10.10.10.10
ADPULSE_DOMAIN=corp.local
ADPULSE_USER=standard.user@corp.local
ADPULSE_PASSWORD=...
ADPULSE_MODE=standard
```

## 6. Before you start working

Read `PROJECT-STATUS.md` and the last entries of `docs/BUILD-LOG.md`. Before you stop, follow
`docs/HANDOFF.md`.
