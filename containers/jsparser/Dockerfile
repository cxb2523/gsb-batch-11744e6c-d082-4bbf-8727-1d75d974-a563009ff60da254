# ReverseAI jsparser worker (reverseai.worker/1). Built by tools/build_jsparser_image.py: the base is pinned by its
# linux/arm64 manifest digest; Node.js 24.22.1 and the @babel/parser 8.0.4 closure (the five downloads of decision
# owner-m5b-downloads) come from the build context and are checked by SHA-256 or sha512 integrity before use. No step
# uses the network and no npm client runs: the build stage takes bin/node and its licence from the Node.js tarball and
# writes the four packages' regular files under node_modules; the image copies /opt/node and node_modules from it.
FROM python:3.12-slim@sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e AS build
COPY unpack.py downloads/node-v24.22.1-linux-arm64.tar.xz downloads/parser-8.0.4.tgz downloads/types-8.0.4.tgz downloads/helper-string-parser-8.0.6.tgz downloads/helper-validator-identifier-8.0.6.tgz /tmp/
RUN --network=none python3 -I -B /tmp/unpack.py node /tmp/node-v24.22.1-linux-arm64.tar.xz \
        dbabf7a1cbf947e6059ffad2c27b80041db97dea1e553b62afdee7f13fca336e 30978868 /opt/node \
    && python3 -I -B /tmp/unpack.py npm /tmp/parser-8.0.4.tgz \
        sha512-srpptsAkEbbNIC/q8nT7o+m6CQe8CJUTV/t7MYc9NnWlgYVtHOb7JH6SorxMhN0kuRJjVqXbKClG6xSbPtzz+g== \
        /opt/reverseai/node_modules/@babel/parser \
    && python3 -I -B /tmp/unpack.py npm /tmp/types-8.0.4.tgz \
        sha512-eY+Yn3dCqTGmyiq2QRU66lA5FL8lqqqvecHt0fF3uHONIa7ToYsaCiWV8lOKqAs0Rb2SjixiKFROngnulPtt2g== \
        /opt/reverseai/node_modules/@babel/types \
    && python3 -I -B /tmp/unpack.py npm /tmp/helper-string-parser-8.0.6.tgz \
        sha512-+6HYEBnsDRZHJtUTAEfMQd0zMDqdFHS7C+5vAsEZqBUr3vEMWOWlHJ0Jz1gS8jJIlCvLsuA6ivmeoqzH936YcA== \
        /opt/reverseai/node_modules/@babel/helper-string-parser \
    && python3 -I -B /tmp/unpack.py npm /tmp/helper-validator-identifier-8.0.6.tgz \
        sha512-HYx0YmuchRxRSpnjvcNffnPS8DCauKNmnumIuHG3jnQAVewRA7kfJGwF13ayEpSZs7s4R/oBH4eppuXcAQd5JQ== \
        /opt/reverseai/node_modules/@babel/helper-validator-identifier \
    && rm -rf /tmp/*

FROM python:3.12-slim@sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e
COPY --from=build /opt/node /opt/node
COPY --from=build /opt/reverseai/node_modules /opt/reverseai/node_modules
COPY driver.mjs worker.py /opt/reverseai/
USER 65534:65534
# Node, its licence, the parser closure, the driver and the worker must be in place: a missing piece fails the build.
RUN --network=none ["python3", "-I", "-B", "-c", "import os, subprocess, importlib.util as u; s = u.spec_from_file_location('worker', '/opt/reverseai/worker.py'); w = u.module_from_spec(s); s.loader.exec_module(w); assert os.access(w.NODE, os.X_OK) and os.path.isfile('/opt/node/LICENSE') and os.path.isfile(w.DRIVER); assert subprocess.run([w.NODE, '--version'], capture_output=True, text=True, check=True).stdout.strip() == 'v24.22.1'; assert sorted(os.listdir('/opt/reverseai/node_modules/@babel')) == ['helper-string-parser', 'helper-validator-identifier', 'parser', 'types']"]
ENTRYPOINT ["python3", "-I", "-B", "/opt/reverseai/worker.py"]
