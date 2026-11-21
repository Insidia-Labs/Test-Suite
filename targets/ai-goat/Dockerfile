# AI Goat's challenge image (rootcauz/ai-base:0.0.1, by digest) plus the packages
# challenge 2 pip-installs when it starts, which an offline target can't do. They are
# pinned as PyPI stood when challenge 2 and its solution were written (2023-07-18):
# validators 0.21.0 (August 2023) and later reject http://localhost URLs, which breaks
# the challenge's documented solution. --no-deps keeps anything else out. The model file
# and llama-cpp-python inside the image go unused: the suite's llama_cpp.py is mounted
# in their place.
FROM rootcauz/ai-base:0.0.1@sha256:a5359f717843195d62b6fa03f42e376239bd4c561402b4bfeac1f5b48ce6ccec
RUN pip3 install --no-cache-dir --no-deps certifi==2023.5.7 charset-normalizer==3.2.0 \
    decorator==5.1.1 idna==3.4 requests==2.31.0 urllib3==2.0.3 validators==0.20.0
