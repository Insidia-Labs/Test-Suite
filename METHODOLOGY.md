# Methodology

This suite measures security tools against public, pinned targets with answer
keys written by the targets' own authors. It is built so that no tool, ours
included, gets an advantage from the way it is tested.

Frozen on **2026-11-19**. Changing any rule below after a tool has been run
against the suite invalidates the comparison, so changes get a new suite version.

## 1. Rules

### 1.1 No tool code in the suite

The harness never imports Argus, Lynx, Taylon or any baseline tool. Every tool
connects the same way: an adapter script runs the tool's own CLI and writes
SARIF (or one of the few other formats in [`ADAPTERS.md`](ADAPTERS.md)). The
scorer only reads that output.

### 1.2 Answer keys come from upstream

| Answer key | Where it comes from |
|---|---|
| OWASP Benchmark (Java, Python) | `expectedresults-*.csv` in the benchmark repo |
| Juice Shop (source) | `vuln-code-snippet vuln-line` markers in Juice Shop's source |
| Juice Shop (live) | The app's own `/api/Challenges` solved flags |
| CASTLE | Each file's header (`vulnerable`, `cwe`) and `{!LINE}` markers |
| CWE-Bench-Java | `data/project_info.csv` and `data/fix_info.csv` |
| OpenSSF CVE Benchmark | `CVEs/*.json` (`prePatch.weaknesses`) |
| CredData | `meta/*.csv` (`GroundTruth` column) |
| XBOW | A random flag the harness injects at build time (see 1.5) |
| AgentDojo | AgentDojo's own `security()` check per injection task |
| Upstream-scored benchmarks | That benchmark's own grader, imported unchanged |

Where the suite has to derive a label, the rule is written down in the target's
manifest and the derived file is frozen before any tool runs:

- **DVWA**: low, medium and high are vulnerable and impossible is the clean
  control, as DVWA documents. Each module's CWE set comes from the module's
  title (for example "SQL Injection" → CWE-89). The table is in
  `src/itsuite/keys/dvwa.py`.
- **VAmPI**: items come from VAmPI's README list, and each one is tied to the
  `if vuln:` branch in VAmPI's source that implements it. Items without such a
  branch stay vulnerable when `vulnerable=0`, so they are never used as clean
  controls.
- **CWE families**: a finding with a different CWE counts only when one CWE is an
  ancestor of the other through ChildOf links in MITRE's CWE-1000 view (for
  example CWE-564 is a child of CWE-89). Siblings, which only share a parent,
  don't count. The 33 edges are in `src/itsuite/cwe.py`; they were checked
  against CWE 5.0, and `scripts/check_cwe_families.py` re-checks them against any
  release. Run with `cwe_mode: strict` for the exact-CWE result.

### 1.3 Tools never see the answers

Before a tool runs, the harness builds a **view** of the target's source. The
view leaves out answer files (expected-results CSVs, other tools' results,
solution guides, code-fix catalogs, test suites that contain exploits) and
removes in-source answer markers. Removed markers are replaced with blank text,
so line numbers don't change. CASTLE files are also renamed to opaque names,
because their paths contain the CWE. Every view also drops instruction files
written for AI coding agents (`AGENTS.md`, `CLAUDE.md`, `.cursor/`, `.claude/`,
`.ai/` and the like; the list is in `src/itsuite/view.py`). They steer LLM-based
tools and have no effect on deterministic ones, so keeping them would favour one
kind of tool.

Answer keys are built from the untouched source into `.cache/keys/`, stored
under their SHA-256 digest, and loaded at scoring time by the exact digest the run
recorded. A key whose content changes under the same name is refused. Flag keys get
a new random flag every run and never overwrite each other.

The tool never learns which variant or task it is on. The variant (`patched`,
`clean`, `impossible`) and the task id (a CVE id for CWE-Bench-Java) are not passed
to adapters and are not in the run folder's name. They live in `run.json`, which
is written after the tool finishes. Where a target itself shows its variant, every
tool sees it equally: DVWA prints its security level on every page and keeps it in
a cookie.

**Host mode** runs the tool as a normal process, working in its own `out/`
folder. Harness-only files (the path map, and the isolated compose file holding
the flag) are kept in `.cache/private/`, not in the run folder. Even so, a host
process can read `.cache/` and can ask the Docker daemon about the target's
images, where a built-in flag is visible. Host-mode results are therefore
labelled "unsealed". **Container mode** mounts only the view (read-only), the
input folder (read-only), an output folder and the adapter, with no Docker
socket, so those results are labelled "sealed". The container runs the suite
tools image (`itsuite tools image`): a pinned base image plus exactly the pinned
tool versions, tagged by a hash of its contents, so a different tool version
gives a different tag. Against a live target, the tool container joins only the
edge network, where it can reach the gateway (and the internet, for its own model
API) but not the target's other services. Published numbers should come from
container mode. Tools that run Docker themselves (ZAP) can't run sealed.

### 1.4 Everything is pinned

Each target is pinned to a full git commit (or an archive SHA-256). The fetcher
refuses to continue if the checked-out commit is different, and resets a cached
checkout that a build or container wrote into. Tool versions are pinned in
`catalog/tools/`, and `itsuite tools install` installs exactly those versions:
release downloads are kept only if their SHA-256 matches the manifest, Python
tools get exact `==` pins, and images are pulled by digest. Each adapter refuses
any other version. Helper images (the port gateway and the egress probe)
are pinned by tag and digest in `src/itsuite/isolation.py`.

Pins were taken on 2026-11-19. The rule was the HEAD of the default branch, with
one exception: crAPI's default branch is `develop`, so it is pinned to the
`v1.1.6` release.

### 1.5 Targets have no internet access

Live targets run on Docker networks marked `internal: true`. Published ports are
removed. A small gateway container is the only path in: it listens on
`127.0.0.1` and forwards to the target, and it can't route the target's own
traffic out. After start-up the harness runs a probe on the target network that
tries to reach the internet. If the probe succeeds, the run stops.

Compose files that ask for `network_mode: host`, `privileged`, the Docker socket
or host PID/IPC are refused.

For flag-based targets, the harness generates a fresh random flag for each run
and passes it in as the build argument. XBOW's default flag is the SHA-256 of the
benchmark's name, so anyone could compute it without solving anything.

### 1.6 Same budget for every tool

A profile sets the wall-clock limit per run, and every tool gets the same one.
Token and dollar limits are passed to the adapter as `ITS_BUDGET_TOKENS` and
`ITS_BUDGET_USD`. The tool has to enforce them. It can report what it spent in
`cost.json`, and the report shows that number.

LLM-based tools are run N times per task (`--repeat`). Reports give the mean and
a Wilson 95% interval, never a single best run.

### 1.7 Crashes are not clean results

An adapter that exits non-zero, times out or writes no output gets status
`error`, `timeout` or `no-output`, and that run is not scored. A crashed scan is
never counted as "found nothing". On timeout the adapter's whole process group is
stopped (and its container, in container mode). Output that can't be parsed, a
missing answer key, or a live target that fails during the run also leave the run
unscored, with the reason. Every run folder appears in the report, scored or not.
If the tool's own SARIF says its run didn't finish (`executionSuccessful: false`),
the score carries `tool_reported_incomplete: true`.

For benchmarks that grade themselves, an errored task is reported two ways: left
out of the success rate, and counted as a failure (`success_rate_errors_as_failures`,
the lower bound).

### 1.8 Every vulnerable set has a clean control

| Vulnerable set | Clean control |
|---|---|
| OWASP Benchmark true cases | Its false-positive cases (about half) |
| DVWA low/medium/high | DVWA impossible |
| VAmPI `vulnerable=1` | VAmPI `vulnerable=0` (toggled items only) |
| CWE-Bench-Java buggy commit | The fix commit |
| OpenSSF CVE Benchmark `prePatch` | `postPatch` |
| CASTLE `vulnerable: true` | CASTLE `vulnerable: false` |
| CredData `T` rows | CredData `F` rows |
| AgentDojo with no defense | AgentDojo with each built-in defense |

Real-world repositories may contain issues nobody has labelled. Findings that
match no case are written to `adjudication.jsonl` for a person to review. They
are not counted as true or false positives until someone decides. For the same
reason, a key with no negative cases (real CVEs, Juice Shop) reports recall only.
Its precision is shown as empty, not as a perfect 1.0.

A person decides with `itsuite adjudicate mark <run> <index> --verdict real|not-real
--by <name>`. The decision is written to `adjudications/<target>.yaml` in the repo,
so it is reviewed and versioned like the rest of the suite. It is about a location
and CWE in the target, not about the tool that reported it, so it applies to every
tool's findings there. Scores show adjudicated findings in their own block (real,
not real, pending) and never change the upstream key's numbers. Decisions proposed
by an assistant say so in `by` and need a person's review.

### 1.10 How findings are matched

- SARIF results of kind `pass`, `notApplicable` or `informational`, and suppressed
  results, are not findings.
- A source finding matches a case in the same file whose lines it overlaps, ± the
  manifest's `line_tolerance`. A finding spanning more than 25 lines counts at its
  first line only, so one file-wide result can't land on every case in the file.
  Each finding goes to its nearest case or cases. Cases on the same line all
  count, since one bug can solve several Juice Shop challenges.
- A shorter finding path only matches when it still contains a folder, so a bare
  file name can't match a same-named file elsewhere. Absolute paths outside the
  view are counted as `unresolved_paths`.
- A live finding matches the most specific case token in its URL or logical
  location (`/users/v1/login` beats `/users/v1/{username}`).

### 1.9 Contamination is labelled

Each target has a `contamination` rating:

- **high**: solutions are widely published and certainly in LLM training data
  (Juice Shop, DVWA, WebGoat, OWASP Benchmark Java, Juliet).
- **medium**: public, with some write-ups.
- **low**: recent, or keeps its answers out of the public repo (for example
  CVE-Bench's zero-day mode).

Reports keep high-contamination targets in their own section. An LLM tool that
scores well only there may be remembering answers rather than finding bugs.

### 1.11 LLM-backed targets run on one pinned model

Some targets are an LLM application, so how easy they are depends on the model
behind them. Every tool meets the same model: a pinned build
(`catalog/models/`, a Hugging Face repo at a full revision) served by a pinned
vLLM on the host with a fixed seed and fixed server settings. Each target keeps its
own sampling settings (DVLA uses temperature 0, AI Goat 0.9, so AI Goat's replies
vary between runs and should be run with `--repeat`).
The model runs offline (no Hub access, no usage reporting) and listens only on
Docker's bridge address. Targets reach it through one gateway container,
`its-model`, on their internal network; it is their only way out, and the egress
probe still runs. Targets that call a hosted model upstream (DVLA picks one from
its `llm-config.yaml`: OpenAI or Hugging Face) get the suite model's address
instead; nothing else in the target changes. Where a target
only has a web UI, the suite adds a small API front end (for DVLA,
`targets/damn-vulnerable-llm-agent/its_api.py`) that builds the same agent with
the same prompts and tools, so tools that speak HTTP can attack it. The front
end returns the agent's tool calls with each reply; scoring only looks for the
target's secrets, which are rotated per run like other flags. Targets that load a
model inside their own process (AI Goat runs a 13B Vicuna file through
llama-cpp-python) get a stand-in module with the same interface instead
(`targets/ai-goat/llama_cpp.py`). It sends the target's own prompt, unchanged, to
the suite model as a plain completion.

## 2. Metrics

| Metric | Used for |
|---|---|
| Precision, recall, F1 (+ Wilson 95% CI) | Every key with positive and negative cases |
| True and false positive rates, Youden index (TPR − FPR) | OWASP Benchmark, per category and averaged (the benchmark's own score) |
| Recall + count of unmatched findings | Keys with positives only (real CVEs, Juice Shop) |
| Success rate (+ Wilson CI), pass@k | Flags, AgentDojo attack success, upstream-scored benchmarks |
| Wall time, cost, cost per true positive | Every run |

## 3. Levels

| Level | Meaning | Examples |
|---|---|---|
| L0 | Smoke: well-known practice apps | DVWA, Juice Shop, VAmPI, DVGA |
| L1 | Training apps and goats | WebGoat, crAPI, NodeGoat, PyGoat, WrongSecrets, the Goat IaC/CI projects, Damn Vulnerable MCP Server |
| L2 | Scored scanner benchmarks | OWASP Benchmark, Juliet, CASTLE, WAVSEP, Firing Range, CredData |
| L3 | Real-world CVEs and agent security | CWE-Bench-Java, OpenSSF CVE Benchmark, XBOW, CVE-Bench, AgentDojo, Vul4J |
| L4 | Expert and autonomous | Cybench, NYU CTF Bench, BountyBench, CyberGym, AIRTBench |

## 4. Known limits

- OWASP Benchmark URLs and Java packages contain the test category (for example
  `/benchmark/pathtraver-00/`). The category is not the answer, since about half
  of each category is false-positive cases, but it is a hint every tool gets.
- Juliet's function and file names contain the CWE and `bad`/`good`. It stays
  `planned` until the suite has an identifier-renaming pass. Until then, scores
  from LLM tools on Juliet would be meaningless.
- Host mode is unsealed (see 1.3).
- CWE-Bench-Java's `fix_info.csv` gives method line ranges. The suite matches a
  finding inside the range, ± the tolerance set in the manifest.
- Juice Shop's source contains its own challenge checks
  (`challengeUtils.solveIf(challenges.xChallenge, ...)`), often next to the
  vulnerable code. Removing them would break the code, so they stay, and they
  hint at where challenges live. This is one more reason Juice Shop is rated
  high contamination.
- Benchmarks marked `bridge` run on their own graders. The suite imports and
  aggregates their results. It does not re-grade them.
- XBOW, Damn Vulnerable MCP Server and Damn Vulnerable LLM Agent build from
  digest-pinned base images and a dated Debian snapshot (or archive.debian.org
  for retired releases), so they keep building as mirrors change. VAmPI, DVWA and
  Juice Shop don't pin their builds yet; when one stops building, the run is
  recorded as `target-error` and not scored.
- LLM-backed targets (Damn Vulnerable LLM Agent, AI Goat) run on one pinned local model
  (see 1.11). Their results hold for that model and settings only: a different
  model makes the same target easier or harder. The pinned model is small (Qwen3.5
  0.8B, chosen for speed on an 8 GB card). On DVLA it calls the tools correctly but
  often doesn't give a final answer: it repeats the last tool call until the agent's
  6-step limit. Secrets then appear only in the agent's tool steps (`its_steps`, what
  DVLA's own UI shows in its status boxes), so a tool that reads only the final reply
  can miss a goal it reached.
- Some baselines pull rules or vulnerability data at run time (Semgrep's
  `p/default`, Trivy's database). Their results depend on the date, which every
  run records.
