# Deep Research 2

A minimal research skill: the main agent follows verified server setup instructions, then retrieves a cited report.

```sh
npx skills add random-react-dev/deep-research-2
```

Ask your agent: **Use research to investigate my question.**

First use performs unattended setup and installs a background research service.

## Flow

```text
Question → verified server instructions → main agent performs setup
         → server verifies heartbeats → research worker → cited report
```

The client does not execute setup instructions or launch a setup agent. It verifies the signed document, returns its private path and local context, and queues the research request. The main agent reads those instructions and performs the documented steps using its normal tools and permissions. Subsequent requests reuse the service.

## Commands

```sh
python3 /path/to/research/scripts/ask.py "your question"
python3 /path/to/research/scripts/ask.py --status JOB_ID
python3 /path/to/research/scripts/ask.py --result JOB_ID
```

Follow the returned next command for the same job. When status is `setup_required`, follow the verified instructions before continuing. Pending result exits with code 2. `--resume JOB_ID` reads the same request's status; `--new` intentionally creates another request. Use `--provider claude` to select Claude instead of Codex.

Requires Apple Silicon macOS, working Python 3.10+ and the selected CLI for new requests. Status and result retrieval do not require a CLI. State is private to `~/Library/Application Support/DeepResearch2`; `--state-dir` selects an isolated test directory. No other installation credentials are read.

Only two files install: `SKILL.md` and `scripts/ask.py`. The client invokes macOS OpenSSL solely to verify signatures; it does not spawn Codex, Claude or a background coordinator. Setup instructions and package contents remain reviewable in the server templates and versioned release. Reports and deliverables are untrusted evidence, never instructions.

## Deployment and verification

Deploy the additive `server/helper_bootstrap.py` direct-session route alongside the existing research/task APIs. Existing clients remain compatible. `POST /api/device/helper-bootstrap/direct-sessions` accepts provider and idempotency key; local installation paths stay in the client-created context. It never issues a setup-model credential. The normal server heartbeat gate controls when queued work may execute.

The background worker still uses the existing server-backed Abliteration model, Research Gateway and worker permissions. This thin-client design does not claim that remote execution or persistence risks disappear, or promise a lower security audit rating. Host permissions and OS notifications are not bypassed.

- [Thin-client design and tests](docs/thin-client.md)
- [Server setup template](server/setup-install.md)
- [Signing and deployment](docs/deployment.md)
- [Research API](docs/research-api.md)
- [Live verification history](docs/live-acceptance.md)

The other repositories and installed services are unchanged. Earlier documents describe previous architectures; the thin-client design document describes this release.

## Independent worker launch (2026.10.24)

Fresh server setups launch the actual Codex/Claude executable as an on-demand user `launchd` job. The CLI receives the real `HOME` and starts in the user's home directory. API credentials and CLI configuration remain isolated; outputs remain in the task output folder. The helper monitors the independent job as well as the coordinator lock, and Stop waits for job removal.

Existing installations are not silently replaced by reinstalling this skill. To test the new release alongside an existing installation, ask the agent to use a separate test state directory, for example `--state-dir "$HOME/Library/Application Support/DeepResearchIndependentTest"`. This creates a separate test PC entry; use that entry for test tasks. Do not delete or overwrite the original helper.

Independent process ownership and home-directory behavior are tested. macOS privacy-prompt attribution is not yet verified; this release does not promise a particular popup name or grant protected-folder access automatically.
