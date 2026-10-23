# Main-agent setup architecture

The public client contains API calls, private receipts, RSA verification and safe report retrieval. It has no agent-launch command, no detached coordinator and no code that executes downloaded instructions. OpenSSL verification is the only child process it invokes.

1. A new question creates/reuses an owned device and stable local job receipt.
2. The client creates/reuses a direct setup session with provider and idempotency key. It sends no local executable or installation paths in this request.
3. It verifies the pinned signing key, signature, model, validity period and release descriptor, saves a private instruction snapshot and locally constructed context, then queues research. The server prevents execution before fresh service heartbeats.
4. It returns setup_required with the verified path, hash, expiry, context path and next status command. It has not executed any setup.
5. The main agent reads the verified document, sets HELPER_RUNNER_CONTEXT for its commands, and performs the documented steps using normal host permissions.
6. Two authenticated service heartbeats at least 15 seconds apart open the task gate. The service starts the existing research worker.
7. Status/result read the same task; result downloads are size/SHA-256 checked, safe-path staged and returned as untrusted evidence. A lost submission acknowledgement is recovered by idempotency/lookup; result/status never create replacement work.

Direct sessions cannot request setup-model tokens. Existing runner sessions remain compatible. Server-authorized setup content is still executable behavior when the main agent follows it; signatures authenticate its provenance, not its safety. The persistent service and worker permissions remain visible and documented.

Tests cover no automatic execution, valid and tampered signatures, expiry, file/context drift, linked state files, owner isolation, duplicate/lost submissions, pending uploads, unsafe report paths, checksums and untrusted result metadata. Old tests for the removed coordinator and setup-agent launcher were retired; relevant safety checks were ported to thin-client tests. Full Mac reboot behavior is not claimed tested.
