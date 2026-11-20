# AI Goat's challenge image (rootcauz/ai-base:0.0.1, by digest) plus the packages
# challenge 2 pip-installs when it starts, which an offline target can't do. They are
# pinned to the versions current at AI Goat's pinned commit (2024-08-21), with --no-deps
# so nothing else comes in. The model file and llama-cpp-python inside it go unused: the
# suite's llama_cpp.py is mounted in their place.
FROM rootcauz/ai-base:0.0.1@sha256:a5359f717843195d62b6fa03f42e376239bd4c561402b4bfeac1f5b48ce6ccec
RUN pip3 install --no-cache-dir --no-deps certifi==2024.7.4 charset-normalizer==3.3.2 \
    idna==3.7 requests==2.32.3 urllib3==2.2.2 validators==0.33.0
