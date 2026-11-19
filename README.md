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
targets). Install the tool you're testing so its CLI is on `PATH` at the version
its manifest pins.

```bash
uv sync --extra dev
uv run itsuite doctor
uv run itsuite validate
uv run itsuite list --level L0
```

Run one tool against one target:

```bash
uv run itsuite run --tool bandit --target owasp-benchmark-python --mode sast
uv run itsuite run --tool argus --target dvwa --mode dast --variant low
uv run itsuite run --tool argus --target dvwa --mode dast --variant impossible
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
| L0 | [Damn Vulnerable LLM Agent](https://github.com/ReversecLabs/damn-vulnerable-llm-agent) | agent-attack (planned) | medium |
| L0 | [Damn Vulnerable GraphQL Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | dast (planned) | medium |
| L0 | [Damn Vulnerable Web Application](https://github.com/digininja/DVWA) | dast (native) | high |
| L0 | [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | dast (native), sast (native) | high |
| L0 | [VAmPI (Vulnerable API)](https://github.com/erev0s/VAmPI) | dast (native) | medium |
| L1 | [AI Goat](https://github.com/dhammon/ai-goat) | ctf (planned) | medium |
| L1 | [CfnGoat](https://github.com/bridgecrewio/cfngoat) | iac (planned) | medium |
| L1 | [CI/CD Goat](https://github.com/cider-security-research/cicd-goat) | ctf (planned), iac (planned) | medium |
| L1 | [OWASP crAPI](https://owasp.org/www-project-crapi/) | dast (planned) | medium |
| L1 | [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) | agent-attack (planned), sast (planned) | medium |
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

## Checked end to end (2026-11-19)

These ran for real against pinned targets, with no mocking:

| Run | Result |
|---|---|
| Bandit 1.9.4, OWASP Benchmark for Python, source | Scored 1,230 cases: 179 TP, 25 FP, 273 FN, 753 TN; mean category Youden 0.165 |
| Argus 1.0.0 (a0affd0), VAmPI vulnerable / clean | Scored: 0 of 9 found; 0 false positives on 6 controls |
| Argus 1.0.0 (a0affd0), DVWA low / impossible | Scored: 0 of 19 found; 0 false positives on 19 controls |
| XBOW XBEN-001-24, flag plumbing | Random flag injected and sealed; the target's own Dockerfile then failed to build (`apt-get` downloads from `debian-security`), recorded as `target-error` |

Argus finds nothing in its own L1 scan here because its web checks need a
`{{payload}}` placeholder in a hand-written request, and the suite gives every
tool only the base URL and the session. That's a measured result about Argus,
not something to tune the adapter around.

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
