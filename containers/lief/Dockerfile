# ReverseAI LIEF worker (reverseai.worker/1). Built by tools/build_lief_image.py with --network none:
# the base is pinned by its linux/arm64 manifest digest and LIEF comes from a hash-checked local wheel.
FROM python:3.12-slim@sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e
COPY requirements.txt /opt/reverseai/requirements.txt
COPY wheels/ /tmp/wheels/
RUN python3 -m pip install --no-index --find-links /tmp/wheels --only-binary=:all: --require-hashes --no-deps \
        --no-cache-dir --disable-pip-version-check -r /opt/reverseai/requirements.txt \
    && rm -rf /tmp/wheels
COPY worker.py /opt/reverseai/worker.py
USER 65534:65534
# The worker's fixed parser options must be exactly this LIEF's: an unknown or new option fails the build.
RUN ["python3", "-I", "-B", "-c", "import importlib.util as u; s = u.spec_from_file_location('worker', '/opt/reverseai/worker.py'); w = u.module_from_spec(s); s.loader.exec_module(w); w.parser_configs()"]
ENTRYPOINT ["python3", "-I", "-B", "/opt/reverseai/worker.py"]
