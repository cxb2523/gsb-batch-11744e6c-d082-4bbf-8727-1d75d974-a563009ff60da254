# ReverseAI Ghidra worker (reverseai.worker/1). Built by tools/build_ghidra_image.py: the base is pinned by its
# linux/arm64 manifest digest; Ghidra 12.1.4 and the Temurin JDK come from the build context, checked by SHA-256
# (owner-m3-downloads). Only the natives stage uses the network, once, for Debian's g++ and make at their exact
# trixie versions (owner-m3-apt-trixie) to build the arm64 decompiler and GNU demangler from the release's sources,
# following Ghidra's own build instructions; the image copies /opt/jdk and /opt/ghidra from it and nothing else.
FROM python:3.12-slim@sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e AS natives
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++=4:14.2.0-1 make=4.4.1-2 \
    && rm -rf /var/lib/apt/lists/*
COPY unpack.py downloads/ghidra_12.1.4_PUBLIC_20260921.zip downloads/OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz /tmp/
RUN --network=none python3 -I -B /tmp/unpack.py ghidra /tmp/ghidra_12.1.4_PUBLIC_20260921.zip \
        ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db /opt \
    && mv /opt/ghidra_12.1.4_PUBLIC /opt/ghidra \
    && rm -rf /opt/ghidra/docs /tmp/ghidra_12.1.4_PUBLIC_20260921.zip \
    && python3 -I -B /tmp/unpack.py check /tmp/OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz \
        23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223 \
    && mkdir /opt/jdk \
    && tar -xzf /tmp/OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz -C /opt/jdk --strip-components=1 --no-same-owner \
    && rm /tmp/OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz /tmp/unpack.py
# The release ships x86_64 natives only: build the arm64 decompiler and GNU demangler from its own sources.
RUN --network=none cp -r /opt/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp /tmp/decompile \
    && cd /tmp/decompile && touch *.cc *.hh \
    && make -j"$(nproc)" ghidra_opt ARCH_TYPE= OSDIR=linux_arm_64 \
    && install -D -m 0755 ghidra_opt /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile \
    && demangler=/opt/ghidra/GPL/DemanglerGnu/src/demangler_gnu_v2_41 \
    && gcc -O2 -std=gnu17 -DHAVE_STDLIB_H -DHAVE_STRING_H -I"$demangler/headers" "$demangler"/c/*.c -o /tmp/demangler_gnu_v2_41 \
    && install -D -m 0755 /tmp/demangler_gnu_v2_41 /opt/ghidra/GPL/DemanglerGnu/os/linux_arm_64/demangler_gnu_v2_41 \
    && rm -rf /tmp/decompile /tmp/demangler_gnu_v2_41

FROM python:3.12-slim@sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e
COPY --from=natives /opt/jdk /opt/jdk
COPY --from=natives /opt/ghidra /opt/ghidra
COPY worker.py /opt/reverseai/worker.py
COPY project_cache.py /opt/reverseai/project_cache.py
COPY ghidra_scripts/ReverseAIOptions.java /opt/reverseai/ghidra_scripts/ReverseAIOptions.java
COPY ghidra_scripts/ReverseAIQuery.java /opt/reverseai/ghidra_scripts/ReverseAIQuery.java
COPY ghidra_scripts/ReverseAIPrepare.java /opt/reverseai/ghidra_scripts/ReverseAIPrepare.java
USER 65534:65534
# The worker, its fixed scripts, the JDK and both arm64 natives must be in place: a missing piece fails the build.
RUN --network=none ["python3", "-I", "-B", "-c", "import os, importlib.util as u; s = u.spec_from_file_location('worker', '/opt/reverseai/worker.py'); w = u.module_from_spec(s); s.loader.exec_module(w); assert all(os.access(p, os.X_OK) for p in ('/opt/jdk/bin/java', '/opt/ghidra/support/analyzeHeadless', '/opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile', '/opt/ghidra/GPL/DemanglerGnu/os/linux_arm_64/demangler_gnu_v2_41')); assert sorted(os.listdir(w.SCRIPTS)) == ['ReverseAIOptions.java', 'ReverseAIPrepare.java', 'ReverseAIQuery.java']; assert sorted(os.listdir('/opt/reverseai')) == ['ghidra_scripts', 'project_cache.py', 'worker.py']"]
ENTRYPOINT ["python3", "-I", "-B", "/opt/reverseai/worker.py"]
