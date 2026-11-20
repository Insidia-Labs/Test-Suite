"""Suite files that stand in for a target's model engine (AI Goat's llama_cpp)."""

from __future__ import annotations

import importlib.util
import io
import json
from types import ModuleType
from typing import Any

import pytest

from conftest import SUITE_ROOT


def _load(path: str, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SUITE_ROOT / path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ai_goat_llama_stand_in_keeps_the_call_and_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    shim = _load("targets/ai-goat/llama_cpp.py", "its_llama_cpp")
    monkeypatch.setenv("ITS_MODEL_BASE", "http://its-model:8000/v1")
    monkeypatch.setenv("ITS_MODEL_NAME", "suite-model")
    sent: list[tuple[str, dict[str, Any]]] = []

    def urlopen(request: Any, timeout: float) -> io.BytesIO:
        sent.append((request.full_url, json.loads(request.data)))
        return io.BytesIO(
            json.dumps({"choices": [{"text": " no flag", "finish_reason": "stop"}]}).encode()
        )

    monkeypatch.setattr(shim.urllib.request, "urlopen", urlopen)
    llm = shim.Llama(model_path="/challenge/models/ggml-old-vic13b-q4_0.bin", n_ctx=2048)
    prompt = "Instruction: rules Question: hi Answer:"
    out = llm(prompt, max_tokens=1000, temperature=0.9, stop=["\n", "Q:"], stream=False, echo=True)
    assert out["choices"][0]["text"] == prompt + " no flag"
    url, body = sent[0]
    assert url == "http://its-model:8000/v1/completions"
    assert body == {"model": "suite-model", "prompt": prompt, "max_tokens": 1000,
                    "temperature": 0.9, "stop": ["\n", "Q:"]}  # fmt: skip
    assert llm(prompt, echo=False)["choices"][0]["text"] == " no flag"
