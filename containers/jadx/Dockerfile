# ReverseAI JADX worker (reverseai.worker/1). Built by tools/build_jadx_image.py: the base is pinned by its linux/arm64
# manifest digest; JADX 1.5.6 (jadx-1.5.6.zip, the one download of decision owner-next-m4b) and the Temurin JDK
# already approved for Ghidra come from the build context, checked by SHA-256. No step uses the network: the build
# stage takes the jar and its licence from the zip, unpacks the JDK and compiles the fixed driver against the jar; the
# image copies /opt/jdk, /opt/jadx and the driver classes from it and nothing else.
FROM python:3.12-slim@sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e AS build
COPY unpack.py driver/ReverseAIJadx.java downloads/jadx-1.5.6.zip downloads/OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz /tmp/
RUN --network=none python3 -I -B /tmp/unpack.py jadx /tmp/jadx-1.5.6.zip \
        545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974 \
        fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b /opt/jadx \
    && python3 -I -B /tmp/unpack.py check /tmp/OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz \
        23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223 \
    && mkdir /opt/jdk \
    && tar -xzf /tmp/OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz -C /opt/jdk --strip-components=1 --no-same-owner \
    && mkdir -p /opt/reverseai/driver \
    && /opt/jdk/bin/javac --release 21 -encoding UTF-8 -nowarn -cp /opt/jadx/jadx-1.5.6-all.jar \
        -d /opt/reverseai/driver /tmp/ReverseAIJadx.java \
    && rm -rf /tmp/*

FROM python:3.12-slim@sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e
COPY --from=build /opt/jdk /opt/jdk
COPY --from=build /opt/jadx /opt/jadx
COPY --from=build /opt/reverseai/driver /opt/reverseai/driver
COPY worker.py /opt/reverseai/worker.py
USER 65534:65534
# The worker, the JDK, the jar, its licence and the compiled driver must be in place: a missing piece fails the build.
RUN --network=none ["python3", "-I", "-B", "-c", "import os, importlib.util as u; s = u.spec_from_file_location('worker', '/opt/reverseai/worker.py'); w = u.module_from_spec(s); s.loader.exec_module(w); assert os.access(w.JAVA, os.X_OK) and os.path.isfile(w.JAR) and os.path.isfile('/opt/jadx/LICENSE'); assert sorted(os.listdir(w.DRIVER)) == ['ReverseAIJadx$1.class', 'ReverseAIJadx.class']"]
ENTRYPOINT ["python3", "-I", "-B", "/opt/reverseai/worker.py"]
