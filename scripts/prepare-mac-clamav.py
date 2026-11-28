"""Stage the verified official ClamAV package; never install it system-wide."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "build" / "clamav"
VERSION = "1.5.5"
ASSETS = {
    f"clamav-{VERSION}.macos.universal.pkg": "b69eecbfc4eba394d7ee44b07abe9d0215801c14819465876b6e5c739205fb51",
    f"clamav-{VERSION}.tar.gz": "90284644e5568732c15fc4f4312fd0f09ac14c14e5b29fba3909d4da4e281b1e",
}


def run(*args):
    subprocess.run(args, check=True)


def prepare():
    CACHE.mkdir(parents=True, exist_ok=True)
    for name, digest in ASSETS.items():
        target = CACHE / name
        if not target.exists():
            urllib.request.urlretrieve(f"https://github.com/Cisco-Talos/clamav/releases/download/clamav-{VERSION}/{name}", target)
        if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"Official release checksum mismatch: {name}")
    expanded = CACHE / "expanded"
    if not expanded.exists():
        run("pkgutil", "--expand-full", str(CACHE / f"clamav-{VERSION}.macos.universal.pkg"), str(expanded))
    runtime = CACHE / "runtime"
    binary_dir = runtime / "bin"
    library_dir = runtime / "lib"
    seed = runtime / "seed"
    notices = runtime / "licenses"
    for directory in (binary_dir, library_dir, seed, notices):
        directory.mkdir(parents=True, exist_ok=True)
    package_root = f"clamav-{VERSION}.macos.universal"
    programs = expanded / (package_root + "-programs.pkg") / "Payload/usr/local/clamav/bin"
    shutil.copytree(programs.parent / "etc" / "certs", runtime / "certs", dirs_exist_ok=True)
    libraries = expanded / (package_root + "-libraries.pkg") / "Payload/usr/local/clamav/lib"
    for name in ("clamscan", "freshclam"):
        target = binary_dir / name
        run("lipo", str(programs / name), "-thin", "arm64", "-output", str(target))
        run("install_name_tool", "-rpath", "/usr/local/clamav/lib", "@executable_path/../lib", str(target))
        target.chmod(0o755)
    for name in ("libclamav.12.dylib", "libfreshclam.4.dylib", "libclammspack.0.dylib", "libclamunrar.12.dylib", "libclamunrar_iface.12.dylib"):
        target = library_dir / name
        run("lipo", str((libraries / name).resolve()), "-thin", "arm64", "-output", str(target))
        run("install_name_tool", "-add_rpath", "@loader_path", str(target))
        target.chmod(0o755)
    for target in [*library_dir.iterdir(), *binary_dir.iterdir()]:
        run("codesign", "--force", "--sign", "-", str(target))
    # Seed definitions are build inputs only, never a requirement on a tester's Mac.
    database = CACHE / "updated" / "db"
    if not database.is_dir():
        database = Path("/opt/homebrew/var/lib/clamav")
    for name in ("main.cvd", "daily.cld", "daily.cvd", "bytecode.cvd"):
        source = database / name
        if source.is_file():
            shutil.copyfile(source, seed / name)
    for source in database.glob("*.sign"):
        shutil.copyfile(source, seed / source.name)
    for name in ("main", "daily", "bytecode"):
        if not any((seed / f"{name}.{suffix}").exists() for suffix in ("cvd", "cld")):
            raise RuntimeError(f"Build machine needs verified {name} definitions before packaging.")
    config = CACHE / "build-freshclam.conf"
    config.write_text(
        f'DatabaseDirectory "{seed}"\nCVDCertsDirectory "{runtime / "certs"}"\n'
        'DatabaseMirror database.clamav.net\nDNSDatabaseInfo current.cvd.clamav.net\n'
        'ConnectTimeout 15\nReceiveTimeout 60\nMaxAttempts 2\nTestDatabases yes\n'
    )
    run(str(binary_dir / "freshclam"), f"--config-file={config}", "--stdout")
    with tarfile.open(CACHE / f"clamav-{VERSION}.tar.gz") as archive:
        for item in archive:
            if item.isfile() and (item.name.endswith(("COPYING.txt", "COPYING", "LICENSE", "LICENSE.txt", "LICENSE.md"))):
                content = archive.extractfile(item)
                if content:
                    (notices / item.name.replace("/", "_")).write_bytes(content.read())
    (notices / "PROVENANCE.json").write_text(json.dumps({
        "version": VERSION, "upstream": "https://github.com/Cisco-Talos/clamav",
        "release_sha256": ASSETS,
        "changes": "Apple Silicon slice; library search paths relocated for private app bundle. Source archive accompanies the app.",
    }, indent=2))
    return runtime


if __name__ == "__main__":
    print(prepare())
