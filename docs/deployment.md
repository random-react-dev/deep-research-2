# Deployment for deep-research-2

Use the existing Research Control service and signed release channel. Copy this repository's `server/helper_bootstrap.py` beside the deployed app module and restart the service after tests. It adds the authenticated `/api/device/helper-bootstrap/direct-sessions` route without changing existing runner sessions. The research API and helper package remain the tested deployed versions.

The new client uses one ask.py file. It verifies signed setup and returns instructions; the main agent performs the setup with normal host tools. No setup-model token is issued. Registration sends a random device ID, generic label and platform; direct setup sends provider and idempotency key. Local paths remain in private context for this setup route. Existing worker telemetry is unchanged and may include task run paths; this update does not claim to remove every metadata transfer.

Signed instruction maintenance is unchanged: keep the private RSA key off the server, review the templates and package, sign with tools/sign_setup.py, and deploy only the envelope. Validity defaults to 90 days. An expired pinned pending session requires renewed signed setup and owner repair; never bypass verification. Existing running services are independent of setup-envelope expiry.

The public release manifest and checksum-addressed package can be reviewed at https://ask-gateway.r95426882.workers.dev/api/public/helper-bootstrap/releases/current . The main agent installs that package only after signature and checksum checks. Background worker execution and its existing permission policy remain part of the disclosed system.

A normal user-scoped LaunchAgent does not run while a Mac is powered off or before its user session is available. macOS controls background-item notifications and permissions; this client does not suppress them. Tests use isolated state/labels and remove only test-owned resources.
