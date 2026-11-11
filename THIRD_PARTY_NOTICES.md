# Third-party notices

## Ghidra and the Temurin JDK (Ghidra worker image only)

The locally built image `reverseai-ghidra` (`tools/build_ghidra_image.py`, decision
`owner-m3-downloads`) contains Ghidra 12.1.4 from the National Security Agency
(`ghidra_12.1.4_PUBLIC_20260921.zip`, SHA-256
`ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`), licensed under the
Apache License 2.0, with the third-party components and licenses listed inside that
release (its `licenses/` and `GPL/` folders; the arm64 decompiler and GNU demangler are
built from its sources), and the Eclipse Temurin JDK 21.0.12.1+1 for aarch64
(SHA-256 `23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223`), licensed
under the GNU General Public License version 2 with the Classpath Exception. Debian's
`g++` 4:14.2.0-1 and `make` 4.4.1-2 are used only in the image's build stage (decision
`owner-m3-apt-trixie`) and are not part of the image. This repository does not
redistribute any of these files.

## JADX and the Temurin JDK (JADX worker image only)

The locally built image `reverseai-jadx` (`tools/build_jadx_image.py`, decision
`owner-next-m4b`) contains JADX 1.5.6 by skylot and contributors (`jadx-1.5.6.zip`,
SHA-256 `545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974`; its
`lib/jadx-1.5.6-all.jar`, SHA-256
`fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b`), licensed under the
Apache License 2.0, with the bundled dependencies and licenses that jar lists, and the
same Eclipse Temurin JDK 21.0.12.1+1 as the Ghidra image (SHA-256
`23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223`, GNU General Public
License version 2 with the Classpath Exception). The image keeps JADX's LICENSE next to
the jar. This repository does not redistribute any of these files.

## Node.js and @babel/parser (JavaScript parser worker image only)

The locally built image `reverseai-jsparser` (`tools/build_jsparser_image.py`, decision
`owner-m5b-downloads`) contains Node.js 24.22.1 by the Node.js contributors
(`node-v24.22.1-linux-arm64.tar.xz`, SHA-256
`dbabf7a1cbf947e6059ffad2c27b80041db97dea1e553b62afdee7f13fca336e`; only `bin/node` and
its `LICENSE`, which also lists the licenses of the dependencies bundled into the
binary), licensed under the MIT License, and four npm packages by Sebastian McKenzie and
the Babel contributors, each licensed under the MIT License with its `LICENSE` file kept
next to it in the image: `@babel/parser` 8.0.4 (integrity
`sha512-srpptsAkEbbNIC/q8nT7o+m6CQe8CJUTV/t7MYc9NnWlgYVtHOb7JH6SorxMhN0kuRJjVqXbKClG6xSbPtzz+g==`),
`@babel/types` 8.0.4
(`sha512-eY+Yn3dCqTGmyiq2QRU66lA5FL8lqqqvecHt0fF3uHONIa7ToYsaCiWV8lOKqAs0Rb2SjixiKFROngnulPtt2g==`),
`@babel/helper-string-parser` 8.0.6
(`sha512-+6HYEBnsDRZHJtUTAEfMQd0zMDqdFHS7C+5vAsEZqBUr3vEMWOWlHJ0Jz1gS8jJIlCvLsuA6ivmeoqzH936YcA==`) and
`@babel/helper-validator-identifier` 8.0.6
(`sha512-HYx0YmuchRxRSpnjvcNffnPS8DCauKNmnumIuHG3jnQAVewRA7kfJGwF13ayEpSZs7s4R/oBH4eppuXcAQd5JQ==`).
No npm client, npx or corepack is part of the image. This repository does not
redistribute any of these files.
