# Testing deep-research-2

Run from the repository with the matching existing server source available:

```sh
RESEARCH_SERVER_SOURCE=/path/to/server PYTHONPATH="$PWD/server:/path/to/server" python3 -m pytest tests /path/to/server/tests -q
```

Set HELPER_RUNNER_TEST_RELEASE to the reviewed package ZIP to include actual Codex CLI schema fixtures. Without the optional server checkout or CLI fixture, those integrations are skipped rather than claimed verified.

Thin-client tests cover signature tampering, invalid/expired envelopes, instruction/context drift, linked files, foreign device ownership, stable task submission, lost acknowledgements, untrusted result metadata, checksum/path checks and pending large uploads. Static checks ensure the installed client has no Popen, eval, exec or agent-launch subprocess; only pinned OpenSSL signature verification runs locally.

Direct-session tests ensure only provider/idempotency key are accepted, unsigned setup is rejected, sessions are device-scoped, queued tasks stay gated until two fresh authenticated heartbeats, and no setup-model credential can be minted. Existing runner routes retain their tests.

The skill installs exactly SKILL.md and scripts/ask.py. Test the public command in a disposable project:

```sh
npx skills add random-react-dev/deep-research-2
```

Live acceptance is separate: client returns setup_required without installation; the main agent reads and executes verified server instructions; heartbeats unlock the backlog; Codex and Claude return real gateway-backed reports. Clean up test-owned state and LaunchAgents afterward. A full Mac reboot is a separate test, not implied by process or heartbeat checks.
