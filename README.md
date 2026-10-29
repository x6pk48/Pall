# Pall: a private browser-sidekick

**Track:** Personal AI  
**Status:** Local Chrome extension and local Nebius gateway; no hosted demo or public repository has been published yet.

Pall is a privacy-first assistant that lives in the browser. It helps people organize tasks, summarize the current page, remember useful facts, reuse skills, and spot suspicious sites or messages. It was built to make a personal assistant useful in everyday browsing without sending raw personal details to a model by default.

## What it does

- Keeps tasks, notes, memories, skills, and chat history in Chrome local storage.
- Redacts detected secrets and personal details before assistant requests; keeps reversible values in a local vault so Pall can restore them in the browser.
- Uses tool calling for tasks, notes, skills, page summaries, and page-safety findings.
- Requires the user's approval before changing protection settings or blocking a domain.
- Checks pages locally for suspicious wording, risky extension permissions, and selected site-security signals; blocks selected ads and tracking requests.
- Shows an animated, customizable cat or dog companion that changes expression and alert colour with the local risk level, with small safety recommendations.
- Uses an original, self-contained SVG companion; the cat's staggered thinking motion was inspired by the MIT-licensed [CSS Cat loader by Rplus](https://codepen.io/Rplus/pen/PWZYRM). No remote sprite or loader source is included.
- Lets users close a risky tab manually; optional automatic closure is off by default and only closes a danger-scored web tab when another tab remains open. Pall never closes a whole browser window.
- Logs model-call metadata and redacted payloads locally for inspection.

Local pattern checks are safeguards, not a guarantee of complete detection. Page content is treated as untrusted input, and Pall does not probe or attack sites.

## NVIDIA and Nebius

Pall sends OpenAI-compatible chat-completions requests to Nebius Token Factory through `gateway.js`. The defaults use NVIDIA Nemotron models:

- Reasoning: `nvidia/nemotron-3-super-120b-a12b`
- Fast memory extraction: `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`

Model availability and exact IDs depend on the Nebius account and current catalog; change the model fields in Pall Settings to an enabled NVIDIA open model if needed. The extension never receives the Nebius API key. The local gateway binds to `127.0.0.1`, requires a separate local bearer token, restricts browser origins, and repeats a sensitive-text check before upstream forwarding.

**How Token Factory is used:** it hosts inference for Pall's reasoning and fast memory-extraction calls. There are no Nebius Serverless Endpoints or Jobs in this version. No claim is made that inference or this application is publicly hosted.

## Run locally

Requirements: Node.js 20+ and Chrome 114+.

1. Create a Nebius Token Factory API key. Keep it private.
2. In PowerShell, from this project directory, set the key and start the gateway:

   ```powershell
   $env:NEBIUS_API_KEY = "your-nebius-token-factory-key"
   npm start
   ```

   The gateway prints a generated Pall-local token once on startup. Keep the terminal open. The key stays in the gateway process and is not saved by this project. To use a persistent local gateway token, set `$env:PALL_GATEWAY_TOKEN` before `npm start`.

3. In Chrome, visit `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select this project folder.
4. Open Pall's side panel, go to **Settings → Assistant gateway**, set the URL to `http://127.0.0.1:8787/v1`, paste the Pall-local token into **Gateway access token**, and save. This is not the Nebius API key.
5. Confirm the reasoning and fast model IDs are available to your Nebius account, then open the **Assistant** tab and try a task or page summary.
6. In **Settings → Look & feel**, customize the panel background and accent. Under **Your companion**, choose Pip the cat or dog, select its fur colour, and turn its animated pop-ups on or off. In **Protection**, automatic dangerous-tab closure is optional and disabled by default; manually closing a tab always requires a click and confirmation.

The gateway health check is `http://127.0.0.1:8787/health` while the gateway is running. It reports process readiness only; it does not verify Nebius credentials or model availability.

## Tests

```powershell
npm test
```

The gateway tests use a mocked upstream endpoint. They do not need a Nebius key and do not call Nebius. They cover forwarding, the local token, origin restrictions, health status, and basic egress checks.

## Demo recording guide

For the required short public video, record the running extension (not just screenshots). A useful under-three-minute sequence:

1. Show Pall in Chrome and identify the Personal AI use case.
2. Show the gateway terminal and the model configuration in Settings. Do not reveal the API key or gateway token.
3. Ask Pall to add a task, then show that it appears in the Tasks view.
4. Ask it to summarize the current page or explain the local page-safety findings.
5. Show Memory/Skills and the privacy log, then explain that personal data is stored in Chrome and the Nebius key remains in the local gateway.
6. Briefly show the custom theme and Pip mascot.

Upload the recording as a public YouTube video and add its URL to the submission. Do not record private browsing content, credentials, or personal data.

## Submission checklist

- [x] Track and project description documented.
- [x] Local setup and test instructions documented.
- [x] Open-source license included: MIT (see `LICENSE`).
- [ ] Publish this code to a public GitHub, GitLab, or Bitbucket repository and add its URL to the submission.
- [ ] Record and publish a public YouTube demo under three minutes; add its URL to the submission.
- [ ] Try the project with your Nebius account and provide genuine feedback on Token Factory and the NVIDIA model(s) used. Feedback is intentionally not fabricated in this README.
- [ ] If this project existed before the submission period, add a truthful explanation of what was significantly updated during that period. The project history and submission dates need the author's confirmation.
- [ ] Add a working public demo or test-build URL if one is deployed. The current build is local-only; do not present the health check as a public demo.

## License

MIT. See [LICENSE](LICENSE).
