# outbound-secret-guard

A `PreToolUse` hook for Claude Code that reads every tool call which sends text off the
machine and refuses the ones carrying a credential.

Catalog task: `AGENT-017`. Part of [thousand](../../README.md).

## What this is

An agent that can read your filesystem and also post to Discord, open a GitHub issue,
POST a webhook, or publish an Artifact is one careless paste away from putting a live API
key somewhere public. Telling the model to be careful does not fix this, because the model
cannot always tell which strings are secret. This hook inspects the payload instead.

It is one file, `outbound_secret_guard.py`, stdlib only, no dependencies. It reads a tool
call as JSON on stdin and writes a decision as JSON on stdout, exit code 0 always. Same
contract as `tools/disk_guard.py` in this repo.

### What it scans

Only calls that actually leave the machine, so the noise stays low:

| Tool | Scanned |
|---|---|
| `WebFetch`, `WebSearch` | url, prompt, every string field |
| `Artifact` | every field, plus the contents of the file being published |
| `mcp__*` | every string field, since MCP servers usually talk to a remote service |
| `Bash` | only when the command reaches the network: `curl`, `wget`, `gh`, `git push`, `ssh`, `scp`, `rsync`, `aws`, `gcloud`, `vercel`, `npm publish`, `ntfy`, `mail`, and friends |
| `Read`, `Write`, `Edit`, `Grep`, local MCP servers | nothing, these stay on the box |

`Bash` deserves a note. Scanning every shell command would flag `cat .env`, which is a
local read, and that kind of noise is how a guard ends up switched off. Set
`scan_all_tools: true` if you want the paranoid version anyway.

### How it detects

Three detectors run over each payload.

**1. Named credential shapes.** 25 gitleaks-style rules: AWS access key ids and secret
access keys, GitHub PATs including fine grained ones, OpenAI `sk-`, OpenRouter `sk-or-`,
Anthropic `sk-ant-`, Google `AIza`, GCP service account JSON, Slack tokens and webhooks,
Discord bot tokens and webhooks, Stripe live and test keys, npm, PyPI, Hugging Face,
GitLab, SendGrid, Twilio, PEM private key blocks, JWTs, credentials embedded in a URL,
and populated `Authorization` headers.

**2. Live environment values.** The hook reads the named environment variables from
`os.environ` at hook runtime and does a literal substring comparison against the payload.
This is the highest confidence signal available, since the string being sent is byte for
byte a credential this machine holds right now. `GEMINI_API_KEY` and `OPENROUTER_API_KEY`
are in the default list along with 18 others.

Nothing is persisted by this path. If you want detection to survive the variable not being
set, `learn-env` stores `sha256(random_salt || value)` plus a length, which is enough to
recognise the value again and not enough to recover it. The value itself is never written
to a file, a log line, a test fixture, or a denial message.

**3. Shannon entropy.** For credential shapes nobody wrote a regex for. Only values in an
assignment or header position are considered, at least 32 characters, at least 12 distinct
characters, above 4.2 bits per character. That threshold sits above a hex sha (4.0 is the
ceiling for hex) and a UUID (about 3.9), and below random base64 (4.7 and up). Values that
look like placeholders, lockfile integrity hashes, data URIs, ISO timestamps, or unix paths
are skipped, as are names like `publicKey`, `integrity`, and `max_tokens`.

### What a block looks like

```
BLOCKED: outbound-secret-guard found 1 credential in this
mcp__plugin_discord_discord__reply payload, which leaves this machine.

  [openrouter-key] OpenRouter API key
      value: sk-or-v1-[redacted 73 chars]   fingerprint: 82d747ac89b7
      found in: tool_input.message

The matched text is deliberately not reproduced here, because this message goes
into the transcript. Do not retry with the value pasted differently.

What to do:
  - If it is a real credential: send an environment variable reference instead,
    for example $OPENROUTER_API_KEY, and rotate the key if it already went out.
  - If it is a false positive: add the fingerprint above to allow_fingerprints in
    .outbound-secret-guard.json, or the rule id to disabled_rules.
```

The denial carries a rule id, a length, and a salted fingerprint. It never carries the
matched text, because the denial goes straight into the transcript, which is the thing you
were trying to keep the secret out of.

## Running it

```bash
./verify.sh                              # the full proof, exit 0 means it works
python3 -m unittest discover -s tests    # unit suite only

python3 outbound_secret_guard.py scan FILE...   # scan files, exit 1 on a finding
python3 outbound_secret_guard.py selftest       # built-in synthetic checks
python3 outbound_secret_guard.py learn-env GEMINI_API_KEY OPENROUTER_API_KEY
python3 outbound_secret_guard.py forget         # delete the hash store
echo -n 'value' | python3 outbound_secret_guard.py fingerprint   # for allowlisting
```

## Installing it

**This is deliberately not installed.** Adding a `deny` hook to a live agent is a decision
for Jesse, not for the agent that wrote it. To turn it on, add this to
`~/.claude/settings.json` (or a project `.claude/settings.json`) under `hooks`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /home/jesse/Projects/thousand/projects/outbound-secret-guard/outbound_secret_guard.py"
          }
        ]
      }
    ]
  }
}
```

The `"*"` matcher is correct here. The hook decides for itself which tools are outbound,
and a narrower matcher would silently miss MCP tools added later. Cost is about 40 ms per
tool call on an 80 KB payload, most of which is Python interpreter startup.

Optional, after installing:

```bash
python3 outbound_secret_guard.py learn-env    # remember this box's keys by salted hash
```

To turn it off, delete the block. There is no kill switch inside the hook on purpose.

## Configuration

Copy `config.example.json` to `.outbound-secret-guard.json` in your project root, or to
`~/.config/outbound-secret-guard/config.json`, or point `OUTBOUND_SECRET_GUARD_CONFIG` at
it. Every field is optional.

| Key | Default | Meaning |
|---|---|---|
| `entropy_threshold` | `4.2` | bits per character above which a value is suspicious |
| `entropy_min_length` | `32` | shorter values are never entropy-checked |
| `env_vars` | 20 common names | environment variables compared literally |
| `allow_literals` | `[]` | exact strings that are never a finding |
| `allow_patterns` | `[]` | regexes, must match the whole value |
| `allow_fingerprints` | `[]` | salted fingerprints, prefix match, for values you will not write down |
| `disabled_rules` | `[]` | rule ids to switch off, for example `twilio-account-sid` |
| `promote_to_block` | `[]` | rule ids whose warnings should block |
| `demote_to_warn` | `[]` | rule ids that should advise instead of block |
| `outbound_tool_patterns` | `[]` | extra tool name regexes to treat as outbound |
| `local_tool_patterns` | `[]` | extra tool name regexes to exempt |
| `scan_all_tools` | `false` | treat every tool call as outbound |
| `read_file_payloads` | `true` | read and scan files referenced by `file_path` |
| `on_error` | `"ask"` | `allow`, `ask`, or `deny` when the scan itself throws |
| `audit_log` | `null` | path for a jsonl record of rule ids and fingerprints, never content |

Three ways to allowlist exist because a false positive is sometimes a literal you can
paste, sometimes a family that needs a regex, and sometimes a value you are not willing to
put in a config file. For the third case:

```bash
echo -n 'the-value' | python3 outbound_secret_guard.py fingerprint   # -> twelve hex chars
```

then put a prefix of that in `allow_fingerprints`. The fingerprint is salted with a
machine-local salt, so publishing it tells an attacker nothing.

## False positives

A hook that cries wolf gets disabled, so this was measured rather than assumed. The
committed corpus at `tests/fixtures/benign_corpus.txt` holds 33 lines of ordinary agent
traffic: git shas, UUIDs, lockfile integrity hashes, `$OPENROUTER_API_KEY` references,
`process.env.X`, data URIs, public key fingerprints, and prose about what an API key looks
like. Zero blocking findings, asserted by the test suite.

Beyond the corpus, the scanner was run over 1331 real files from `~/Projects` (markdown,
json, ts, tsx, py, js, excluding `node_modules`) and produced zero findings at any
severity.

## Status

Verify command: `./verify.sh`, exit code **0**.

```
$ ./verify.sh
== 1. synthetic OPENROUTER_API_KEY pasted into a Discord reply ==
  PASS  permissionDecision == deny
  PASS  denial names the rule that fired
  PASS  denial does not echo the matched value
  ---- denial message as the agent sees it ----
  BLOCKED: outbound-secret-guard found 1 credential in this mcp__plugin_discord_discord__reply payload, which leaves this machine.

    [openrouter-key] OpenRouter API key
        value: sk-or-v1-[redacted 73 chars]   fingerprint: 82d747ac89b7
        found in: tool_input.message

  The matched text is deliberately not reproduced here, because this message goes
  into the transcript. Do not retry with the value pasted differently.

  What to do:
    - If it is a real credential: send an environment variable reference instead,
      for example $OPENROUTER_API_KEY, and rotate the key if it already went out.
    - If it is a false positive: add the fingerprint above to allow_fingerprints in
      .outbound-secret-guard.json, or the rule id to disabled_rules. Both are
      documented in the project README.

== 2. an ordinary Discord reply ==
  PASS  no decision emitted, the call proceeds

== 3. a live environment value, injected for this run only ==
  PASS  live env value denied on WebFetch
  PASS  denial names the variable
  PASS  denial does not echo the value

== 4. false positive corpus ==
  PASS  33 lines of ordinary agent traffic, zero blocking findings

== 5. unit suite ==
        ----------------------------------------------------------------------
        Ran 58 tests in 0.539s

        OK
  PASS  unit suite

VERIFY OK
```

The fingerprint changes on every run of `verify.sh`, because the script points the guard
at a throwaway hash store and each store generates a fresh salt. A verifier re-running
this will see a different twelve hex characters and the same PASS lines.

The 58 unit tests include one that reads the real `GEMINI_API_KEY` and `OPENROUTER_API_KEY`
from this machine's environment, pushes each through the hook as a Discord reply, and
asserts `deny` plus the absence of the value in the denial and in every file the guard
touched. That test skips cleanly where those variables are not set. No real key appears in
this repository, which a second test enforces by walking every file.

## Unfinished

- **Local writes are out of scope.** Writing a secret into a repo file with `Write` is not
  blocked, only sending one. `git secrets` and pre-commit hooks cover that. Turn on
  `scan_all_tools` if you want both, and expect more false positives.
- **The hash store matches whole tokens only.** A learned value split across a payload, or
  embedded inside a longer unbroken string, is caught by the live environment check and
  missed by the stored hash. Live detection is the primary path and the store is a fallback.
- **No base64 or URL decoding.** A key that is base64 encoded before being sent passes.
  Adding a decode pass would raise the false positive rate, so it needs its own measurement
  before being turned on.
- **Bash egress detection is pattern based.** A network call through an unusual binary, or
  through `python3 -c` with `urllib`, is not recognised as outbound. `scan_all_tools`
  closes that gap at the cost of noise.
- **Not installed.** No `settings.json` was modified. See "Installing it" above.
