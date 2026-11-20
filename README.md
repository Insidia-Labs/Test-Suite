# Insidia Labs Test Suite

A tool-agnostic suite for measuring security tools against public, intentionally
vulnerable targets and benchmarks, from DVWA and Juice Shop up to CVE-Bench,
Cybench and BountyBench. Every tool, Insidia's own included, connects the same way
and is scored against answer keys written by each target's authors.

The rules that keep it fair are in [METHODOLOGY.md](METHODOLOGY.md): answers come
from upstream, tools never see them, targets are pinned and have no internet
access, crashes are never counted as clean results, every vulnerable set has a
clean control, and contamination is labelled. [ADAPTERS.md](ADAPTERS.md) is the
contract for plugging in a tool.

## Status (frozen 2026-11-19)

- **46 targets** in five levels (L0 smoke to L4 expert), every one pinned to a
  commit or an archive SHA-256.
- **55 evaluations**: 11 `native` (this harness fetches, seals the key, runs and
  scores), 15 `bridge` (the benchmark's own grader; results are imported) and 29
  `planned` (pinned and described, no scorer yet). `itsuite validate` refuses a
  `native` claim without an answer-key plugin behind it.
- **14 tools**: Argus, Lynx and Taylon under test (Lynx and Taylon have no adapter
  yet), plus baselines ZAP, Nuclei, Semgrep, Bandit, Gitleaks, TruffleHog, Trivy,
  OSV-Scanner, garak, promptfoo and PyRIT.

Native today: DVWA, Juice Shop (live and source), VAmPI, OWASP Benchmark Java and
Python (source), CASTLE, CredData, CWE-Bench-Java, the OpenSSF CVE Benchmark and
XBOW.

## Quick start

Needs Python 3.10+, [uv](https://docs.astral.sh/uv/), git and Docker (for live
targets). The pinned tool downloads are for Linux x86-64.

```bash
uv sync --extra dev
uv run itsuite doctor
uv run itsuite validate
uv run itsuite list --level L0
uv run itsuite tools install --all   # pinned versions, SHA-256 checked, into .cache/tools
uv run itsuite tools list
```

Tools are installed into the suite's own cache, never system-wide, and runs put
`.cache/tools/bin` first on `PATH`. To check a tool's adapter without scoring
anything, run it once against a folder or URL:

```bash
uv run itsuite check-adapter --tool gitleaks --mode secrets --source /path/to/code
```

The copies of target source that tools read (views) are built in
`~/.cache/itsuite/views`, outside this repo. Set `ITS_VIEWS_DIR` to move them.
Don't put them inside a git repo that ignores them: some tools (OSV-Scanner)
honour an enclosing repo's `.gitignore` and would see nothing.

Run one tool against one target:

```bash
uv run itsuite run --tool bandit --target owasp-benchmark-python --mode sast
uv run itsuite run --tool argus --target dvwa --mode dast --variant low
uv run itsuite run --tool argus --target dvwa --mode dast --variant impossible
```

Sealed runs put the tool in a container that sees only the view, its input and
its output, with no Docker socket. Published numbers should come from these:

```bash
uv run itsuite tools image        # one image with every pinned tool, on a pinned base
uv run itsuite run --tool bandit --target owasp-benchmark-python --mode sast --container
```

ZAP runs its own container, so it can't run sealed; its results are labelled
unsealed.

LLM-backed targets (Damn Vulnerable LLM Agent, AI Goat) talk to one pinned local model,
served by vLLM on the host GPU, so every tool meets the same model. Install and
start it once; it keeps running until stopped:

```bash
uv run itsuite model install qwen3.5-0.8b   # pinned vLLM + the model at a fixed revision
uv run itsuite model serve qwen3.5-0.8b     # listens on Docker's bridge address only
uv run itsuite model status
uv run itsuite model stop
```

The model is Qwen3.5 0.8B: small enough to answer quickly, and it needs about
3.4 GB of free GPU memory (`--gpu-memory-utilization 0.45` of an 8 GB card). A
run against an LLM-backed target refuses to start when the model isn't being
served, or when containers can't reach it. A host firewall that drops incoming
traffic (ufw's default) blocks containers from the model server even though the
host itself reaches it. With ufw, allow Docker's networks to that one port once:

```bash
sudo ufw allow from 172.16.0.0/12 to 172.17.0.1 port 8000 proto tcp
```

Run a profile (the same plan for every tool; samples use a fixed seed):

```bash
uv run itsuite profile smoke --tool argus --dry-run
uv run itsuite profile smoke --tool argus
uv run itsuite report
```

Each run writes `results/<run-id>/` with `run.json` (what ran, the pins, the
status), `score.json`, `adjudication.jsonl` (findings that matched no case, for a
person to review), the tool's logs and its output. `results/` and `.cache/` are
git-ignored.

```bash
uv run itsuite scorecard                     # per-tool scorecard and comparison
uv run itsuite adjudicate show <run-id>      # findings outside the answer key
uv run itsuite adjudicate mark <run-id> 3 --verdict real --by <name> --note "..."
uv run itsuite rescore --all                 # apply new decisions to every run
uv run itsuite prepare creddata              # a target's own setup step, once
uv run itsuite build-check xbow              # build every XBOW task with the pins
```

## Layout

```
catalog/targets/   one manifest per target: pin, license, level, answer key, evaluations
catalog/tools/     one manifest per tool: version, modes, adapter commands
profiles/          smoke, standard, full
adapters/<tool>/   one script per mode, following ADAPTERS.md
targets/<id>/      suite-side files: compose files, setup scripts, transcribed answer lists
src/itsuite/       the harness
scripts/           maintenance (re-checking the CWE table against MITRE)
tests/             unit and whole-run tests (offline)
```

## Targets

Generated from the catalog; `uv run itsuite list` is the live version.

| Level | Target | Modes (integration) | Contamination |
|---|---|---|---|
| L0 | [Damn Vulnerable LLM Agent](https://github.com/ReversecLabs/damn-vulnerable-llm-agent) | agent-attack (native) | medium |
| L0 | [Damn Vulnerable GraphQL Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | dast (planned) | medium |
| L0 | [Damn Vulnerable Web Application](https://github.com/digininja/DVWA) | dast (native) | high |
| L0 | [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | dast (native), sast (native) | high |
| L0 | [VAmPI (Vulnerable API)](https://github.com/erev0s/VAmPI) | dast (native) | medium |
| L1 | [AI Goat](https://github.com/dhammon/ai-goat) | agent-attack (native) | medium |
| L1 | [CfnGoat](https://github.com/bridgecrewio/cfngoat) | iac (planned) | medium |
| L1 | [CI/CD Goat](https://github.com/cider-security-research/cicd-goat) | ctf (planned), iac (planned) | medium |
| L1 | [OWASP crAPI](https://owasp.org/www-project-crapi/) | dast (planned) | medium |
| L1 | [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) | agent-attack (native), sast (planned) | medium |
| L1 | [GitHub Actions Goat](https://github.com/step-security/github-actions-goat) | iac (planned) | low |
| L1 | [InterCode-CTF](https://intercode-benchmark.github.io/) | ctf (bridge) | high |
| L1 | [Kubernetes Goat](https://madhuakula.com/kubernetes-goat/) | iac (planned) | medium |
| L1 | [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) | sast (planned), dast (planned) | high |
| L1 | [OWASP PyGoat](https://github.com/adeyosemanputra/pygoat) | sast (planned), dast (planned) | medium |
| L1 | [TerraGoat](https://github.com/bridgecrewio/terragoat) | iac (planned) | medium |
| L1 | [OWASP WebGoat](https://owasp.org/www-project-webgoat/) | dast (planned) | high |
| L1 | [OWASP WrongSecrets](https://owasp.org/www-project-wrongsecrets/) | secrets (planned) | medium |
| L2 | [CASTLE Benchmark](https://github.com/CASTLE-Benchmark/CASTLE-Source) | sast (native) | low |
| L2 | [Samsung CredData](https://github.com/Samsung/CredData) | secrets (native) | low |
| L2 | [Google Firing Range](https://github.com/google/firing-range) (archived) | dast (planned) | medium |
| L2 | [NIST Juliet Test Suite for C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112) | sast (planned) | high |
| L2 | [NIST Juliet Test Suite for Java 1.3](https://samate.nist.gov/SARD/test-suites/111) | sast (planned) | high |
| L2 | [OWASP Benchmark (Java)](https://owasp.org/www-project-benchmark/) | sast (native), dast (planned) | high |
| L2 | [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) | sast (native), dast (planned) | medium |
| L2 | [WAVSEP](https://github.com/sectooladdict/wavsep) | dast (planned) | medium |
| L3 | [Agent Security Bench (ASB)](https://github.com/agiresearch/ASB) | agent-attack (bridge) | medium |
| L3 | [AgentDojo](https://agentdojo.spylab.ai) | agent-attack (bridge) | medium |
| L3 | [BIPIA](https://github.com/microsoft/BIPIA) (archived) | agent-attack (bridge) | medium |
| L3 | [CVE-Bench](https://github.com/uiuc-kang-lab/cve-bench) | exploit (bridge) | low |
| L3 | [CWE-Bench-Java](https://github.com/iris-sast/cwe-bench-java) | sast (native) | medium |
| L3 | [Go vulnerability database](https://pkg.go.dev/vuln/) | sca (planned) | low |
| L3 | [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | agent-attack (bridge) | medium |
| L3 | [OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark) | sast (native) | medium |
| L3 | [Seeded and clean PR suite](https://github.com/iris-sast/cwe-bench-java) | pr-review (planned) | medium |
| L3 | [PrimeVul](https://github.com/DLVulDet/PrimeVul) | sast (planned) | medium |
| L3 | [SAP Project KB (vulnerable dependencies)](https://sap.github.io/project-kb/) | sca (planned) | low |
| L3 | [SEC-bench](https://github.com/SEC-bench/SEC-bench) | exploit (bridge), fix (bridge) | low |
| L3 | [Vul4J](https://github.com/tuhh-softsec/vul4j) | fix (bridge) | medium |
| L3 | [Vulhub](https://vulhub.org) | dast (planned) | high |
| L3 | [XBOW validation benchmarks](https://github.com/xbow-engineering/validation-benchmarks) | ctf (native) | medium |
| L4 | [AIRTBench](https://github.com/dreadnode/AIRTBench-Code) | ctf (bridge) | low |
| L4 | [BountyBench](https://bountybench.github.io) | exploit (bridge), fix (bridge) | low |
| L4 | [Cybench](https://cybench.github.io) | ctf (bridge) | medium |
| L4 | [CyberGym](https://www.cybergym.io) | exploit (bridge) | low |
| L4 | [NYU CTF Bench](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench) | ctf (bridge) | medium |

## Checked end to end

Real runs against pinned targets, with tools installed by `itsuite tools install`
(2026-11-19 and 2026-11-20). TP/FP count cases; "unmatched" findings are outside the
answer key and wait for adjudication.

| Tool | Target | Result |
|---|---|---|
| Bandit 1.9.4 | OWASP Benchmark Python, source | 179 TP, 25 FP of 1,230 cases; precision 0.88, recall 0.40 |
| Semgrep 1.186.0 (`p/default`) | OWASP Benchmark Python, source | 114 TP, 86 FP; precision 0.57, recall 0.25 |
| Argus 1.0.0 (`f783775a`) | OWASP Benchmark Python, source | 4 TP, 9 FP; recall 0.01 (built-in sink rules only) |
| ZAP 2.17.0 | VAmPI vulnerable / clean | 1 of 9 found (SQL injection); 0 FP on 6 controls |
| Nuclei 3.11.1 | VAmPI, DVWA | 0 found; findings are headers, tech detection, DVWA's default login (unmatched) |
| Nuclei 3.11.1 | Juice Shop, live | 4 of 100 challenges solved |
| ZAP 2.17.0 | Juice Shop, live | 2 of 100 challenges solved |
| Semgrep 1.186.0 | Juice Shop, source | 7 of 30 marked vulnerabilities found, 0 FP |
| Argus 1.0.0 | VAmPI, DVWA | 0 found; 0 FP on controls |
| Gitleaks 8.30.1 | CredData | 7,086 TP, 1,169 FP; precision 0.86, recall 0.45 |
| TruffleHog 3.99.9 | CredData | 371 TP, 178 FP; precision 0.68, recall 0.02 (run with `--no-verification`: targets are offline) |
| Semgrep 1.186.0 | CWE-Bench-Java, OSSF CVE (sampled tasks) | 0 found; 1 FP on an OSSF patched control |
| Trivy, OSV-Scanner | PyGoat, TerraGoat | Adapter checks only: output parsed (no scored target yet) |
| XBOW (all 104) | build check | Every benchmark builds with the pinned bases and Debian snapshot |
| Harness self-test | Damn Vulnerable MCP Server | All 15 rotated flags found; none of the published flags left in the image |
| Harness self-test | AI Goat on Qwen3.5 0.8B | Both challenges solved in a scored, isolated run with rotated flags (AI Goat's documented solutions; tries 16 and 10, 3 min). About half the model's replies are empty, so tools need retries |
| Harness self-test | Damn Vulnerable LLM Agent on Qwen3.5 0.8B, outside Docker | All 3 README attacks reach their secrets (2.8 s in total). The scored run in Docker is pending: its image build stalls on this host's IPv4 path to the Debian and PyPI mirrors |

Argus finds nothing on the live apps because its web checks need a `{{payload}}`
placeholder in a hand-written request, and the suite gives every tool only the
base URL, the session and (when the target has one) its OpenAPI document. ZAP
found VAmPI's SQL injection only after importing that OpenAPI document.

## Development

```bash
uv run pytest
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run mypy src
```

Tests run offline; fetching and Docker are replaced with fakes where needed.
Coverage must stay at 80% or above (it is about 94%).

## License

MIT, see [LICENSE](LICENSE). Each target keeps its own license. The suite fetches
targets at run time and doesn't redistribute them.
