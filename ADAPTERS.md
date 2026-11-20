# Adapter contract

Every tool, including Argus, Lynx and Taylon, plugs in the same way: a manifest in
`catalog/tools/<id>.yaml` and a script per mode in `adapters/<id>/`. The harness
never imports a tool. It runs the adapter and reads what it wrote.

## Manifest

```yaml
id: mytool
name: My Tool
role: under-test            # or baseline
version: 2.3.1              # the version the adapter requires
source: https://github.com/example/mytool
license: MIT
status: available           # or not-yet-available (no adapter yet)
env_passthrough: [MYTOOL_API_KEY]   # only these host variables reach the tool
image: ghcr.io/example/mytool:2.3.1@sha256:...   # for --container (sealed) runs
modes:
  sast:
    command: bash {adapter_dir}/sast.sh {source_dir} {out_dir}
    output: sarif           # sarif | trufflehog-jsonl | flags
    output_file: results.sarif
  dast:
    command: bash {adapter_dir}/dast.sh {target_url} {out_dir}
    output: sarif
```

The command is split into arguments first and the placeholders are filled in
afterwards, so a value never passes through a shell. An unknown placeholder fails
the run before anything starts.

| Placeholder | Meaning |
|---|---|
| `{target_url}` | Live target base URL (host mode: `http://127.0.0.1:<port>/` via the gateway; `tcp://127.0.0.1:<port>` for plain socket targets) |
| `{source_dir}` | The view: the target's source with answer files and markers removed. Empty for black-box modes. |
| `{out_dir}` | Where the tool writes its output |
| `{input_dir}` | Read-only inputs: `auth.json` from the target's setup, `task.md` for task targets |
| `{adapter_dir}` | This tool's `adapters/<id>/` folder |

There is deliberately no placeholder for the variant or the task id. A tool that
knew it was on the `patched` variant, or which CVE a task is, would have the
answer. The adapter runs inside `{out_dir}`.

The same values are also set as environment variables (`ITS_TARGET_URL`,
`ITS_OUT_DIR`, ...), along with the run's budget: `ITS_WALL_SECONDS`,
`ITS_BUDGET_USD` and `ITS_BUDGET_TOKENS`. Every other host variable is dropped,
except `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `USER` and the ones the
manifest lists in `env_passthrough`. In container mode (`--container`) these are
passed by name (`docker run -e NAME`), the adapter folder is at `/its/adapter`,
`common.sh` is at `/its/common.sh`, and a live target is reached through its
gateway on the edge network.

## Installing the tool

Add an `install` block so `itsuite tools install <id>` can install the exact
version into `.cache/tools`:

```yaml
install:
  kind: archive       # archive | binary | pip | docker
  url: https://github.com/example/mytool/releases/download/v2.3.1/mytool_linux_amd64.tar.gz
  sha256: <64 hex>    # the download is refused if it doesn't match
  binary: mytool      # the executable inside the archive
# pip:    packages: [mytool==2.3.1]  binaries: [mytool]
# docker: image: ghcr.io/example/mytool:2.3.1@sha256:...
```

Then check the adapter end to end before setting `verified: true`:

```bash
uv run itsuite check-adapter --tool mytool --mode sast --source /path/to/code
```

## Rules for the script

1. **Exit 0 when the tool finished, whatever it found.** Exit non-zero only when
   it didn't finish. Translate your tool's exit codes: many exit 1 when they find
   something. A non-zero exit, a timeout or a missing output file means the run is
   not scored. It never counts as "found nothing".
2. **Check the version.** Use `require_version` from `adapters/common.sh`. It
   refuses a different version (exit 3) and records the exact version string in
   `out/tool-version.txt`, which goes into the run record.
3. **Use what the target hands you.** If `{input_dir}/auth.json` exists, use it.
   It can contain `cookies`, a `login` (URL, username, password for the local test
   app), `exclude_paths` (pages that log you out or reset the app) and
   `openapi_url`. Every tool gets the same file.
4. **Don't add target knowledge.** An adapter may set options that apply to any
   target of that kind (a GET method for a crawlable web app, a rate limit). It
   must not name the endpoints, parameters or files where a target's
   vulnerabilities are. That is the answer key.
5. **Write SARIF 2.1.0 with CWEs.** Put CWE ids where the scorer looks for them: in
   `properties.tags` (`"CWE-89"` or `"external/cwe/cwe-089"`) on the rule or the
   result, or in `taxa`/`relationships` that point at a `CWE` tool component. A
   finding without a CWE only matches in `cwe_mode: any`.
6. **Report locations the scorer can match.** For source scans, use paths relative
   to `{source_dir}`, or absolute paths inside it, with `region.startLine`. For live
   scans, put the full URL in `artifactLocation.uri` or a logical location.
7. **Optional: report cost.** Write `out/cost.json` with any of `usd`,
   `input_tokens`, `output_tokens` and `total_tokens`. The harness doesn't enforce
   budgets. It passes them in and reports what the tool says it spent.
8. **Flag targets** (`output: flags`): print the flag, or write it anywhere in
   `{out_dir}`. The run counts as solved when the exact sealed flag appears.
9. **Agent targets** (`agent-attack`): `{target_url}` is where the agent answers.
   A target with several endpoints (Damn Vulnerable MCP Server runs one MCP server
   per challenge) lists every one in `{input_dir}/endpoints.json`, as
   `{"service:port": "url"}`. An LLM app with no API of its own (Damn Vulnerable LLM
   Agent) is served at an OpenAI-compatible `POST {target_url}/chat/completions`.
   It keeps no state between requests, so send the whole conversation in `messages`
   each time. Each reply also carries `its_steps`, the agent's tool calls and their
   outputs; scoring ignores them and looks only for the target's secrets. AI Goat's
   bots are plain TCP chat sockets (`tcp://host:port`, as with netcat): the bot sends
   a greeting and a ` > ` prompt, you send one line, and it replies. If a reply
   doesn't come, reconnect: challenge 2's handler dies on a model reply it can't
   parse and leaves the connection open but silent (upstream behaviour).

## Benchmarks with their own runner (`bridge`)

AgentDojo, CVE-Bench, Cybench and the other `bridge` targets grade runs
themselves. Run the tool inside that benchmark's own harness, then import the
results:

```bash
itsuite import-upstream path/to/agentdojo/runs --format agentdojo --tool mytool --target agentdojo
itsuite import-upstream results.jsonl --format jsonl --tool mytool --target cybench
```

The JSONL format has one task per line: `{"task_id": "...", "success": true,
"variant": "unguided", "duration_s": 12.5, "cost_usd": 0.4, "error": ""}`. A line
with `error` set is reported as an errored task and left out of the success rate.
