# ReverseAI YARA-X worker (reverseai.worker/1). Built by tools/build_yarax_image.py with --network none:
# the base is pinned by its linux/arm64 manifest digest and YARA-X comes from a hash-checked local wheel.
FROM python:3.12-slim@sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e
COPY requirements.txt /opt/reverseai/requirements.txt
COPY wheels/ /tmp/wheels/
RUN python3 -m pip install --no-index --find-links /tmp/wheels --only-binary=:all: --require-hashes --no-deps \
        --no-cache-dir --disable-pip-version-check -r /opt/reverseai/requirements.txt \
    && rm -rf /tmp/wheels
COPY m2_fixture_v1.json /opt/reverseai/m2_fixture_v1.json
COPY worker.py /opt/reverseai/worker.py
USER 65534:65534
# The reviewed ruleset must compile cleanly from its generated source: a bad rule fails the build.
RUN ["python3", "-I", "-B", "-c", "import importlib.util as u; s = u.spec_from_file_location('worker', '/opt/reverseai/worker.py'); w = u.module_from_spec(s); s.loader.exec_module(w); w.compiled('m2_fixture_v1')"]
ENTRYPOINT ["python3", "-I", "-B", "/opt/reverseai/worker.py"]
