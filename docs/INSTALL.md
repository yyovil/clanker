# Install the Clanker runtime

Use the already-patched `hermes/` source bundled in this checkout. Dependency
versions are recorded in [hermes-baseline.json](../config/hermes-baseline.json)
and `hermes/uv.lock`.

Check for Git, uv, and Python 3.13. Install missing tools for the current operating
system. The recorded Python version is 3.13.13.

Create `.local/hermes-lab/`, then set `UV_PROJECT_ENVIRONMENT` to the absolute
path of `.local/hermes-lab/venv` using the current shell's environment-variable
syntax. From `hermes/`, run:

```sh
uv sync --locked --python 3.13.13 --extra slack --extra dev
```

Reuse an existing matching environment. The upstream test runner expects
`hermes/.venv` to resolve to this environment; create a platform-compatible link
when needed, preserving any unrelated environment.

From the repository root, check the project launcher in a compatible Bash shell:

```sh
scripts/hermes-lab --version
```

The launcher initializes the dedicated local home with
[hermes-defaults.yaml](../config/hermes-defaults.yaml) and keeps credentials in
the ignored local configuration. Platform-specific runtime support must be
verified before claiming the full application works on that machine.

The current execution boundary requires macOS Seatbelt. Install Node and the
`agent-browser` driver package on the trusted host for native Kernel control.
Requester profiles receive no browser CLI wrapper. Local Chromium, Browser Use
and Composio browser credentials are not runtime requirements. The foreground
Python/shell sandbox remains separate from the remote browser.

Continue with the [setup prompt](SETUP_PROMPT.md) or [operator setup](SETUP.md) to
configure inference, the Slack app, vault HTTPS and the reviewed Kernel provider,
then accept the execution fleet, start and verify Clanker. Card payment for INR
purchases up to ₹500 is part of the Kernel browser flow; see
[Kernel integration](KERNEL_BROWSER.md).
