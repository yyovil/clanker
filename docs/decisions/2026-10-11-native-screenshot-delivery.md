# Deliver native screenshot paths and prefer visible viewport capture

## Finding

Canonical finding `native-screenshot-attachment-path` follows the [bounded Nike capture diagnostic](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791719112107249), run `r20261011-171512-adhoc-662ac3`, exact Hermes session `20261011_171519_ec79caa3`, Kernel browser `u5bys0qc9z9rvsdjooiih86m`, gateway PID 28838. This is an ordinary empty-bag diagnostic and is excluded from benchmark scoring.

At 17:17:23 IST Clanker reported it could inspect the screenshot images but could not attach them because it had no shareable paths. `browser_tool_vision._native_vision_result` appended the saved file path only to `meta` and `text_summary`. `VisionMessagePrepMixin._tool_result_content_for_active_model` correctly selects `content` for native vision providers, so the model received the pixels and question without the screenshot path. Two terminal searches did not recover the paths. This is a deterministic result-contract defect, separate from pixel capture behavior.

The same diagnostic compared viewport A, full-page B and viewport A again without account selection, authentication, cart mutation, DOM/CSS mutation or tab changes. Independent original-pixel inspection showed the two viewport images were pixel-identical and rendered the empty-bag heading, explanation and Shop Now button. The full-page image omitted those elements and the Nike logo. All images measured 1919 by 992 pixels; A/B difference bounds were (48,55,1160,491). Computed styles reported visible, fully opaque content and no visible overlay candidates. The view-transition inspection reported no animation; that alone does not prove a transition layer exists. The full-page operation did not persistently hide viewport contents. Its exact upstream compositor cause remains unknown.

Evidence is `.local/clanker-qa/batches/2026-10-11-reliability-round6/nike-capture-diagnostic/runs/r20261011-171512-adhoc-662ac3/evidence/capture-comparison.json`, with original PNG hashes and capture timestamps (17:16:34, 17:16:47 and 17:20:06 IST). The earlier Nike original scenario remains unsuccessful.

## Change

Keep the saved screenshot path and MEDIA attachment instruction in a text part next to the original image, as well as the fallback text summary and existing metadata. The actual native-model route now retains the exact path. No pixels are altered, no new capture is requested, and no secret values are introduced.

For native `browser_vision`, an omitted `full_page` now captures the current visible viewport. Explicit true retains full-document capture. This matches the tool's current-page visual inspection purpose and avoids making full-document rendering the only/default proof of visible content. It does not claim to repair the upstream full-page compositor. There are no site-specific rules, automatic screenshot retries, CSS changes, alternate sessions or privacy bypasses. Large-document callers can opt into full capture.

Internally, an omission sentinel distinguishes the native default from Camofox's existing backend behavior. Omitting the option on Camofox preserves its prior route; an explicit false still returns a clear unsupported refusal. The Lightpanda-to-Chrome capture route receives the resolved requested scope.

## Validation and limits

The isolated canonical red run had four expected failures and eleven passes: native attachment text omitted the path, fallback text lacked the share instruction, and native default/schema still selected full-page capture. The isolated focused green run passed all fifteen tests. The attachment regression invokes the real native-result builder and the actual native/text-only model-content selector, preserving the original saved bytes and image part. Capture-scope tests exercise registry dispatch, exact CLI flags, same task/output path, Camofox compatibility and the real Kernel document privacy guard.

The isolated related run had 103 passes and one Lightpanda requirement-test failure. The same copied requirement suite against unchanged deployed source reproduced that failure (37 passes, one failure), so it is an isolated test-context limitation rather than evidence of this patch regressing the requirement. The original suites must run in their normal repository test context after integration.

The source was first prepared under `.local/clanker-qa/findings/native-screenshot-attachment-path/isolated/` while live lanes ran. Runtime files were not edited or activated during that preparation. Final integration tests and live attachment verification must be recorded after coordinator application/restart. Successful empty-bag screenshots do not establish the original Nike saved-address checkout or full benchmark success.

## Integrated validation

After the live lanes were stopped and all human gates cancelled, the coordinator applied the reviewed seven-file candidate. The canonical runner passed **104 tests across seven files, zero failures and zero retries**, including the original Lightpanda suite in its normal repository context. Log: `.local/clanker-qa/findings/native-screenshot-attachment-path/integration-tests.log`. Both coordinator and independent peer reviewed the native-content path, viewport choice, Camofox omission compatibility and unchanged observation guards. Activation and live attachment verification remain pending.
