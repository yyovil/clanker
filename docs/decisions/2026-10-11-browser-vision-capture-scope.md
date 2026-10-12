# Compare viewport and full-page screenshots through the guarded browser tool

## Finding

Finding `browser-vision-capture-scope` follows the [Nike benchmark thread](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791715389965779), run `r20261011-161310-add-one-pair-640d`, exact Hermes session `20261011_161316_7e706072`, Kernel browser `dkmhej5tgcy3votlt7nd0tgu`. At 16:34:22 and 16:35:38 IST, the saved screenshots showed a loading spinner and empty product area. A current DOM observation reported the requested single pair, total, loaded images and a complete document. Independent inspection of the saved PNGs confirmed the model's description. The annotated image contained current element boxes over loading pixels.

The installed official agent-browser 0.31.1 code injects the annotation overlay and calls `Page.captureScreenshot` using the same active CDP session. Hermes writes a new UUID screenshot and passes its bytes to vision. No evidence supports a stale local file or a different-tab fallback. The observed divergence could still arise from website layout/overlays, compositor state or full-page capture. The cause is unconfirmed. The model-facing tool exposed only question and annotation choices and unconditionally requested `--full`, so it could not compare capture scopes through its authorized route.

## Change

Add optional `full_page: boolean`, default true, to the existing `browser_vision` schema, registry adapter and capture helper. False omits `--full` and captures the current viewport using the same authenticated task, selected browser, screenshot command and observation guards. There is no raw CDP tool, alternate session selection, automatic retry, CSS manipulation or privacy bypass.

The Lightpanda-to-Chrome capture helper passes the selected scope to its existing screenshot command. Camofox explicitly refuses viewport selection before issuing a request because its existing API adapter does not expose that choice; its default route remains unchanged. The native Chrome default still captures the full page. Tool schemas change only with normal process/session activation, not by mutating a live conversation prefix.

## Validation and limits

The regression first produced five expected failures and four passes. The final six-file canonical run passed **100 tests, zero failures**, with zero file retries. Files: `verification/probes/test_browser_vision_capture_scope.py`, `verification/probes/test_vault_privacy_recovery.py`, and Hermes `tests/tools/test_browser_lightpanda.py`, `test_vision_native_fast_path.py`, `test_browser_private_page_action_guard.py`, `test_browser_camofox.py`.

The new tests invoke the real registry adapter and capture helper with fixture screenshot I/O. They compare CLI command arguments for omitted/default/full/viewport options while preserving the task and profile-local output path, prove private-page refusal before capture, verify sibling-backend handling, and execute the real Kernel document-privacy middleware for both scopes with fixture provider I/O. No live website is contacted by these tests. The final log is `.local/clanker-qa/findings/browser-vision-capture-scope/capture-green.log`.

This is a diagnostic capability, not a proven repair of Nike's screenshot rendering or login. A bounded same-owner QA comparison of both capture scopes and ordinary visible overlays is required after deployment. It must not submit login, request another code, mutate the bag, bypass privacy guards, or fabricate a successful screenshot. The original benchmark remains unsuccessful until its saved-address, total and screenshot outcomes are actually verified.
