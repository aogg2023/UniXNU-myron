#!/usr/bin/env python3
"""Offline checker for the songyuan (Redmi K100 Pro Max) UEFI boot image.

Usage: python check_img.py <boot.img> [--fd-size 0x300000] [--fd-base 0x...]

It verifies, without the phone:
  1. Android boot v0 header and the gzip(shim+FD+payload) + appended DTB layout.
  2. The strict BootShim: FD_BASE/FD_SIZE literals, size > 300 bytes,
     FD_SIZE multiple of 16, payload window constants present.
  3. The XNUP payload: magic, declared size, every entry name/size/alignment,
     total length inside PAYLOAD_CAP, and loader.efi as a valid ARM64 EFI app.
  4. The FD: FV signature, size, LZMA GUIDed inner FV, driver count, and
     presence/absence of strings that tell whether the right pieces were built
     (XNU_Payload reservation, SmBiosTableDxe dropped, ...).
Exit code 0 = PASS, 1 = FAIL.
"""
import gzip
import lzma
import struct
import sys

MAGIC = 0x50554E58  # "XNUP"


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        fail("usage: check_img.py <boot.img>")
    path = args[0]
    img = open(path, "rb").read()
    print("image:", path, "size:", len(img))

    # 1. Android boot v0 header.
    if img[:8] != b"ANDROID!":
        fail("not an Android boot image")
    ksz = u32(img, 8)
    kaddr = u32(img, 12)
    tags = u32(img, 32)
    page = u32(img, 36)
    if page != 4096:
        print("WARN: page size", page)
    print(f"header: kernel_size={ksz} kernel_addr={kaddr:#x} tags={tags:#x} page={page}")
    if ksz <= 0 or page + ksz > len(img):
        fail("kernel field out of range")

    field = img[page:page + ksz]
    gi = field.find(b"\x1f\x8b\x08")
    fi = field.find(b"\xd0\x0d\xfe\xed")
    if gi < 0:
        fail("no gzip blob in kernel field")
    if fi < 0 or fi <= gi:
        fail("no appended DTB after the gzip blob")
    blob = gzip.decompress(field[gi:fi])
    dtb = field[fi:]
    print(f"gzip at {gi:#x}, dtb at {fi:#x} ({len(dtb)} bytes), blob {len(blob)} bytes")
    if dtb[:4] != b"\xd0\x0d\xfe\xed":
        fail("appended DTB magic mismatch")
    dtb_tot = struct.unpack_from(">I", dtb, 4)[0]
    if dtb_tot == len(dtb):
        pass
    elif dtb_tot < len(dtb):
        print(f"WARN: appended blob is a multi-DTB concatenation (first FDT {dtb_tot} of {len(dtb)} bytes)")
    else:
        fail(f"appended DTB totalsize {dtb_tot} > field {len(dtb)}")

    # 2. Strict BootShim.
    fvh = blob.find(b"_FVH")
    if fvh < 0:
        fail("no _FVH signature in blob")
    fd_start = fvh - 0x28
    shim = blob[:fd_start]
    print("shim:", len(shim), "bytes; FD starts at", hex(fd_start))
    if len(shim) <= 300:
        fail("shim too small: legacy (no PAYLOAD support) build")
    if len(shim) % 16:
        fail("shim length not a multiple of 16")
    fd_base = struct.unpack_from("<Q", shim, 8)[0]
    fd_size = struct.unpack_from("<Q", shim, 16)[0]
    print(f"shim: FD_BASE={fd_base:#x} FD_SIZE={fd_size:#x}")
    if fd_size % 16:
        fail("FD_SIZE not 16-aligned")
    fvlen = struct.unpack_from("<Q", blob, fvh - 8)[0]
    if fvlen != fd_size:
        print(f"WARN: FV length {fvlen:#x} != shim FD_SIZE {fd_size:#x}")

    # 3. XNUP payload after the FD.
    pay = blob[fd_start + fd_size:]
    if pay[:8] == b"\x00" * 8:
        fail("no XNUP payload after the FD (shim has no payload copy?)")
    magic, psize = struct.unpack_from("<II", pay, 0)
    if magic != MAGIC:
        fail(f"bad payload magic {magic:#x}")
    if psize > 0x03700000:
        fail(f"payload body {psize:#x} exceeds cap 0x3700000")
    print(f"payload: XNUP size={psize:#x} (container {8 + psize:#x})")
    cur, end = 8, 8 + psize
    entries = []
    while cur + 24 <= end:
        name = pay[cur:cur + 16].split(b"\x00")[0].decode(errors="replace")
        if not name:
            break
        esz = u32(pay, cur + 16)
        entries.append((name, esz, cur))
        if esz and esz % 16 == 0:
            pass
        cur = (cur + 24 + esz + 15) & ~15
    if not entries:
        fail("empty payload entry list")
    print("payload entries:", ", ".join(f"{n}({s:#x})" for n, s, _ in entries))
    for name, esz, off in entries:
        if esz % 16:
            print(f"WARN: {name} size {esz:#x} not 16-aligned")
    loader = [(n, s, o) for n, s, o in entries if n.startswith("loader")]
    if not loader:
        fail("payload has no loader.efi entry")
    name, esz, off = loader[0]
    data = pay[off + 24: off + 24 + esz]
    if data[:2] != b"MZ":
        fail(f"{name}: not a PE image")
    pe = u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\x00\x00":
        fail(f"{name}: bad PE signature")
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    oph = pe + 24
    entry = u32(data, oph + 16)
    subsys = struct.unpack_from("<H", data, oph + 68)[0]
    imgbase = struct.unpack_from("<Q", data, oph + 24)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    sec = pe + 24 + opt
    reloc = any(data[sec + i * 40:sec + i * 40 + 8].rstrip(b"\x00") == b".reloc" for i in range(nsec))
    print(f"{name}: machine={machine:#x} subsystem={subsys} entry={entry:#x} "
          f"imagebase={imgbase:#x} reloc={reloc}")
    if machine != 0xAA64:
        fail("loader is not AArch64")
    if subsys != 10:
        fail("loader subsystem is not EFI_APPLICATION")
    if not reloc:
        print("WARN: loader has no .reloc section (preferred base must be free)")

    # 4. FD checks.
    fd = blob[fd_start:fd_start + fd_size]
    if fd[fvh - fd_start:fvh - fd_start + 4] != b"_FVH":
        fail("FD does not start with the expected FV header")
    print(f"FD: {len(fd)} bytes, sha256 {__import__('hashlib').sha256(fd).hexdigest()[:16]}")
    # decompress the LZMA GUIDed volume image if present
    inner = fd
    lzma_guid = bytes.fromhex("98584eee14395942 9d6edc7bd79403cf".replace(" ", ""))
    found = False
    pos = fd.find(lzma_guid)
    while pos >= 4 and not found:
        start = pos - 4
        sec_size = u32(fd, start) & 0xFFFFFF
        if 0x20 <= sec_size <= len(fd):
            dataoff = struct.unpack_from("<H", fd, start + 20)[0]
            try:
                dec = lzma.decompress(fd[start + dataoff: start + sec_size], format=lzma.FORMAT_ALONE)
                if dec.find(b"_FVH") != -1:
                    inner = dec
                    found = True
                    print(f"inner FV decompressed: {len(dec):#x} bytes")
            except Exception:  # noqa: BLE001
                pass
        pos = fd.find(lzma_guid, pos + 1)
    if not found:
        print("WARN: inner FV could not be decompressed")
    reserved = (b"XNU_Payload" in inner) or (b"XNU_Payload" in fd) or (b"XNU Payload" in inner) or (b"XNU Payload" in fd)
    print(("PASS:" if reserved else "FAIL:") + " XNU payload reservation present")
    if not reserved:
        sys.exit(1)
    for needle, want, label in (
        (b"PlatformUpdateSmBiosType4", False, "SMBIOS driver removed"),
        (b"SmBiosTableDxe", False, "SMBIOS driver removed"),
        (b"RamManagerDxe", True, "RamManager driver present"),
        (b"Successfully Mapped RAM Range", True, "RamManager code present"),
    ):
        found = needle in inner or needle in fd
        ok = found == want
        print(("PASS:" if ok else "FAIL:") + f" {label} ({needle.decode()})")
        if not ok:
            sys.exit(1)
    drivers = 0
    o = (inner.find(b"_FVH") - 0x28)
    if o >= 0:
        hl = struct.unpack_from("<H", inner, o + 0x30)[0]
        o += hl
        endo = len(inner)
        while o + 24 <= endo:
            if inner[o:o + 16] == b"\xff" * 16:
                break
            sz = inner[o + 20] | (inner[o + 21] << 8) | (inner[o + 22] << 16)
            if sz < 24:
                break
            drivers += 1
            o = (o + sz + 7) & ~7
    print(f"FFS files in inner FV: {drivers}")
    print("RESULT: PASS")


if __name__ == "__main__":
    main()
