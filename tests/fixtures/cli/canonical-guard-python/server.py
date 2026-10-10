# In-function canonical-boundary guard: realpath on the member target,
# startswith(root + os.sep) reject, then the sink consumes the checked
# variable. The whole site must resolve recognized-complete (no
# deterministic class).
import os
import zipfile


def extract_zip(zf: zipfile.ZipFile, dest: str) -> None:
    for member in zf.namelist():
        target = os.path.realpath(os.path.join(dest, member))
        if not target.startswith(os.path.realpath(dest) + os.sep):
            continue
        with open(target, "wb") as f:
            f.write(zf.read(member))
