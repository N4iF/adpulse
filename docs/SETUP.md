# SETUP — developing ADPulse نبض on a new machine

Works on the 80 GB desktop (full lab) and the 16 GB laptop (lite lab). Windows 11 Pro assumed.
Steps marked **[admin]** need an elevated prompt; an AI session cannot do them.

## 1. Tools

| Tool | Version | Install |
|------|---------|---------|
| git | 2.4x | https://git-scm.com — set `user.name` / `user.email` |
| GitHub CLI | 2.9x | `winget install GitHub.cli` then `gh auth login` |
| Python | **3.12** (not 3.13/3.14 — some AD libraries lack wheels) | `winget install Python.Python.3.12` |
| uv | latest | `pip install uv` or `winget install astral-sh.uv` |
| Node.js | **24 LTS** (Node 25 is EOL) | `winget install OpenJS.NodeJS.LTS` or `fnm install 24` |
| pnpm | 9+ | `npm i -g pnpm` |
| Hyper-V | Windows feature | `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All` **[admin]** |
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
uv sync            # creates .venv with adsnap and adrules installed editable (from uv.lock)
uv run pytest      # exit code 5 = "no tests collected"; expected until the first test exists
uv run ruff check
```

## 4. Lab

See `lab/README.md`. Summary: Hyper-V Internal switch `LABNET` 10.10.10.0/24 (host 10.10.10.1), one VM
`DC01` 10.10.10.10 (`corp.local`, self-signed LDAPS certificate). On the laptop import the exported
`seeded` checkpoint.

Host name resolution for the lab: add to `C:\Windows\System32\drivers\etc\hosts`
```
10.10.10.10  dc01.corp.local corp.local
10.10.10.20  srv01.corp.local
```
or point the `LABNET` adapter's DNS at 10.10.10.10.

## 5. Per-host `.env` at the repo root (git-ignored, never committed)

```
ADPULSE_DC=dc01.corp.local        # DNS name, not IP: LDAPS validates the hostname
ADPULSE_DOMAIN=corp.local
ADPULSE_USER=adpulse.reader@corp.local
ADPULSE_PASSWORD=...
ADPULSE_MODE=standard             # or privileged
ADPULSE_CA_CERT=lab/dc01-ldaps.cer # the lab DC's self-signed certificate
```

## 6. Before you start working

Read `PROJECT-STATUS.md` and the last entries of `docs/BUILD-LOG.md`. Before you stop, follow
`docs/HANDOFF.md`.
