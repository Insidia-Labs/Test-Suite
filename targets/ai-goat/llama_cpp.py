"""Stand-in for llama_cpp, added by the Insidia test suite.

AI Goat's challenges load a 13B Vicuna GGML file with llama-cpp-python and call it with
a raw "Instruction: ... Question: ... Answer:" prompt. This module is mounted next to
core.py, so ``from llama_cpp import Llama`` finds it first. It sends the same prompt,
with the same max_tokens, temperature and stop strings, to the suite's pinned model
(ITS_MODEL_BASE) as a plain completion, with no chat template. With echo=True it puts
the prompt back in front of the text, as llama-cpp-python does, because the challenges
split the reply on " Answer: ". Only the standard library: the challenge image has no
other HTTP client. Streaming isn't supported; the challenges don't use it.
"""

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

TIMEOUT = 300


class Llama:
    def __init__(self, model_path: str = "", n_ctx: int = 2048, **_: Any) -> None:
        self.base = os.environ["ITS_MODEL_BASE"].rstrip("/")
        self.model = os.environ["ITS_MODEL_NAME"]

    def __call__(
        self,
        prompt: str,
        max_tokens: int = 128,
        temperature: float = 0.8,
        stop: Optional[List[str]] = None,
        stream: bool = False,
        echo: bool = False,
        **_: Any,
    ) -> Dict[str, Any]:
        body = {"model": self.model, "prompt": prompt, "max_tokens": max_tokens,
                "temperature": temperature, "stop": list(stop or [])}
        request = urllib.request.Request(self.base + "/completions",
                                         data=json.dumps(body).encode("utf-8"),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            choice = json.load(response)["choices"][0]
        text = (prompt if echo else "") + choice["text"]
        return {"choices": [{"text": text, "index": 0,
                             "finish_reason": choice.get("finish_reason")}]}
