# Known-answer fixtures

`ovmf_AmdSev_suffix.bin` and `ovmf_OvmfX64_suffix.bin` are the last 4 KiB of two
OVMF builds from edk2 stable202405: the `OvmfPkg/AmdSev/AmdSevX64.dsc` build,
which supports measured direct boot, and the stock `OvmfPkg/OvmfPkgX64.dsc`
build, which does not. Everything a launch measurement needs from the firmware
lives in the GUIDed footer table at the end of the image, so the tail is enough
to reproduce a full-image measurement of a 4 MiB binary.

Both files are inputs for the regression vectors in `../known_answer.rs`. The
expected measurements there are what this implementation produces, pinned so a
refactor cannot move them unnoticed.

They are not independent confirmation. Nobody has checked them against a
measurement from a guest actually launched on SNP hardware, so they cannot show
that this tool computes what a PSP computes. Replacing them with a vector taken
from the Dallas node is what would.

Copies of the fixture files:

    ovmf_AmdSev_suffix.bin  sha256 8f765dfabc127fc0a938a0744a3103ec15864d7d794eb4c398aa976b6d6ab16c
    ovmf_OvmfX64_suffix.bin sha256 b4c021e085fb83ceffe6571a3d357b4a98773c83c474e47f76c876708fe316da

Neither file is a Prism guest image and neither belongs in
`crates/attestation/reference/snp-launch-measurements.json`. A reference entry
describes a firmware, kernel and command line an operator can actually launch.
