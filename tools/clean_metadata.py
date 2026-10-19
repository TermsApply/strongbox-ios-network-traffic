#!/usr/bin/env python3
"""clean_metadata.py - review and remove metadata from files to be published.

No external dependencies (standard library only; on macOS additionally the
`xattr` and `sips` commands, if available).

Usage:
  python3 tools/clean_metadata.py --check  publication/           # report only, changes nothing
  python3 tools/clean_metadata.py --clean  publication/sources/   # cleans PDF/PNG and extended attributes
  python3 tools/clean_metadata.py --clean --title file.pdf        # additionally blanks /Title in PDF
  python3 tools/clean_metadata.py --clean --no-xattr DIRECTORY    # without removing extended attributes
  python3 tools/clean_metadata.py --skip README.md --clean publication/

What it does:
  PNG  - rewrites the file keeping only the chunks IHDR, PLTE, tRNS, gAMA, cHRM,
         sRGB, iCCP, sBIT, pHYs, IDAT, IEND. Removes tEXt/iTXt/zTXt (including XMP), eXIf, tIME.
         After writing it checks that the IHDR dimensions and the joined IDAT data are identical.
  PDF  - in the Info dictionary (every /Info in the trailers, also in incremental
         sections) overwrites IN PLACE the values of /Author, /Creator, /Producer,
         /CreationDate, /ModDate, /Subject, /Keywords (and /Title with --title) with spaces
         of the same length. The file length and the xref table stay unchanged, so the file
         remains valid. Uncompressed XMP streams (/Type /Metadata): values of known tags
         (xmp:CreatorTool, xmp:CreateDate, xmp:ModifyDate, xmp:MetadataDate, pdf:Producer,
         dc:creator, xmpMM:DocumentID, xmpMM:InstanceID) are also overwritten with spaces.
         Compressed XMP is only reported - it needs another tool (rewriting the stream
         changes its length and the xref).
         After writing it checks that the file size and the page count are the same and that
         the old values no longer occur in the file (byte comparison); if `sips` is available,
         it tries to render page 1 to PNG in a temporary directory.
  xattr - on macOS removes all extended attributes (`xattr -c`) from every file,
         e.g. com.apple.metadata:kMDItemWhereFroms (download source), com.apple.quarantine,
         com.apple.lastuseddate#PS, com.apple.provenance, com.apple.FinderInfo.
  .DS_Store - reported (not removed).

What it does NOT do: it does not change visible content (Safari print headers and
footers, tab bars in screenshots), does not crop images, does not remove pages and does
not modify HAR/CSV/TXT/MD files (those are produced by scripts or are content).

The report prints only key names and value lengths - never the values themselves.
Exit code: 0 = OK, 1 = verification error after writing, 2 = bad argument.
"""
import os
import re
import struct
import subprocess
import sys
import tempfile
import zlib

VERSION = "1.1"

PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_KEEP = {b"IHDR", b"PLTE", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"pHYs", b"IDAT", b"IEND"}
PDF_KEYS = [b"Author", b"Creator", b"Producer", b"CreationDate", b"ModDate", b"Subject", b"Keywords"]
XMP_TAGS = [b"xmp:CreatorTool", b"xmp:CreateDate", b"xmp:ModifyDate", b"xmp:MetadataDate",
            b"pdf:Producer", b"xmpMM:DocumentID", b"xmpMM:InstanceID", b"xmpMM:OriginalDocumentID",
            b"dc:creator", b"photoshop:AuthorsPosition", b"xmp:CreatorTool"]


def has_command(name):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if os.access(os.path.join(d, name), os.X_OK):
            return True
    return False


# ---------------------------------------------------------------- PNG

def png_chunks(d):
    if not d.startswith(PNG_SIG):
        raise ValueError("not a PNG file")
    p = 8
    out = []
    while p + 8 <= len(d):
        L = struct.unpack(">I", d[p:p + 4])[0]
        chunk_type = d[p + 4:p + 8]
        body = d[p + 8:p + 8 + L]
        crc = d[p + 8 + L:p + 12 + L]
        out.append((chunk_type, body, crc))
        p += 12 + L
        if chunk_type == b"IEND":
            break
    return out


def png_describe_chunk(chunk_type, body):
    if chunk_type in (b"tEXt", b"zTXt", b"iTXt"):
        key = body.split(b"\0", 1)[0]
        return "%s(key=%s, length=%d)" % (chunk_type.decode(), key.decode("latin1"), len(body))
    return "%s(%d)" % (chunk_type.decode(), len(body))


def png_check(path):
    d = open(path, "rb").read()
    ch = png_chunks(d)
    remove = [png_describe_chunk(t, b) for t, b, _ in ch if t not in PNG_KEEP]
    w, h = struct.unpack(">II", ch[0][1][:8])
    return {"size": (w, h), "to_remove": remove, "chunks": [t.decode() for t, _, _ in ch]}


def png_clean(path):
    d = open(path, "rb").read()
    ch = png_chunks(d)
    before = png_check(path)
    new = bytearray(PNG_SIG)
    for chunk_type, body, crc in ch:
        if chunk_type in PNG_KEEP:
            new += struct.pack(">I", len(body)) + chunk_type + body + struct.pack(">I", zlib.crc32(chunk_type + body) & 0xFFFFFFFF)
    open(path, "wb").write(bytes(new))
    # verification
    d2 = open(path, "rb").read()
    ch2 = png_chunks(d2)
    idat1 = b"".join(b for t, b, _ in ch if t == b"IDAT")
    idat2 = b"".join(b for t, b, _ in ch2 if t == b"IDAT")
    ok = ch[0][1] == ch2[0][1] and idat1 == idat2 and all(t in PNG_KEEP for t, _, _ in ch2)
    return before, ok


# ---------------------------------------------------------------- PDF

def pdf_literal_end(d, i):
    """d[i] == '(' ; returns the index of the closing ')' taking \\ and nesting into account."""
    depth = 0
    j = i
    while j < len(d):
        c = d[j:j + 1]
        if c == b"\\":
            j += 2
            continue
        if c == b"(":
            depth += 1
        elif c == b")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    raise ValueError("unterminated literal string in PDF")


def pdf_find_value(d, start, key):
    """Looks for '/key' within d[start:dictionary_end]; returns (content_start, content_end, kind)."""
    m = re.compile(rb"/" + key + rb"\s*([(<])").search(d, start)
    if not m:
        return None
    i = m.end() - 1
    if d[i:i + 1] == b"(":
        k = pdf_literal_end(d, i)
        return (i + 1, k, "literal")
    if d[i:i + 2] == b"<<":
        return None
    k = d.find(b">", i)
    return (i + 1, k, "hex")


def pdf_info_objects(d):
    """Returns a list of (number, dictionary_start, dictionary_end) for every /Info in the trailers."""
    result = []
    for m in re.finditer(rb"/Info\s+(\d+)\s+(\d+)\s*R", d):
        n, g = m.group(1), m.group(2)
        for o in re.finditer(rb"(?<![0-9])" + n + rb"\s+" + g + rb"\s+obj\b", d):
            s = d.find(b"<<", o.end())
            e = d.find(b"endobj", o.end())
            if s != -1 and e != -1 and s < e:
                result.append((int(n), s, e))
    # unique
    return sorted(set(result))


def pdf_xmp_streams(d):
    out = []
    for m in re.finditer(rb"/Type\s*/Metadata", d):
        s = d.rfind(b" obj", 0, m.start())
        strm = d.find(b"stream", m.end())
        if strm == -1:
            continue
        sl = d.rfind(b"<<", 0, m.start())
        header = d[sl:strm]
        compressed = b"/Filter" in header
        p = strm + 6
        if d[p:p + 2] == b"\r\n":
            p += 2
        elif d[p:p + 1] == b"\n":
            p += 1
        e = d.find(b"endstream", p)
        out.append((p, e, compressed))
    return out


def pdf_page_count(d):
    return len(re.findall(rb"/Type\s*/Page(?![s/a-zA-Z])", d))


def pdf_check(path, title=False):
    d = open(path, "rb").read()
    rep = {"startxref": d.count(b"startxref"), "prev_in_trailer": len(re.findall(rb"trailer[^>]*?/Prev", d, re.S)),
           "pages": pdf_page_count(d), "info": [], "xmp": [], "attachments": d.count(b"/EmbeddedFiles"),
           "annotations_T": len(re.findall(rb"/T\s*\(", d)), "encryption": d.count(b"/Encrypt")}
    keys = PDF_KEYS + ([b"Title"] if title else [])
    for n, s, e in pdf_info_objects(d):
        fields = []
        for k in keys + ([] if title else [b"Title"]):
            w = pdf_find_value(d[:e], s, k)
            if w:
                content = d[w[0]:w[1]]
                empty = content.strip(b" ") == b"" or (w[2] == "hex" and set(content.replace(b" ", b"")) <= {ord("2"), ord("0")})
                fields.append((k.decode(), w[1] - w[0], "empty" if empty else "value", k in keys))
        rep["info"].append((n, fields))
    for p, e, comp in pdf_xmp_streams(d):
        if comp:
            rep["xmp"].append("compressed (%d B) - not cleaned" % (e - p))
        else:
            x = d[p:e]
            present = [z.decode() for z in XMP_TAGS if re.search(rb"<" + z + rb"[\s>]", x)]
            rep["xmp"].append("uncompressed, tags: %s" % ", ".join(sorted(set(present))))
    return rep


def pdf_clean(path, title=False):
    d = bytearray(open(path, "rb").read())
    length = len(d)
    pages = pdf_page_count(bytes(d))
    keys = PDF_KEYS + ([b"Title"] if title else [])
    old = []
    for n, s, e in pdf_info_objects(bytes(d)):
        for k in keys:
            w = pdf_find_value(bytes(d[:e]), s, k)
            if not w:
                continue
            a, b, kind = w
            content = bytes(d[a:b])
            if content.strip(b" ") == b"":
                continue
            old.append(content)
            if kind == "literal":
                d[a:b] = b" " * (b - a)
            else:
                n_hex = b - a
                d[a:b] = (b"20" * (n_hex // 2)) + (b"0" * (n_hex % 2))
    for p, e, comp in pdf_xmp_streams(bytes(d)):
        if comp:
            continue
        x = bytes(d[p:e])
        for z in XMP_TAGS:
            for m in re.finditer(rb"<" + z + rb"(\s[^>]*)?>(.*?)</" + z + rb">", x, re.S):
                content = m.group(2)
                # dc:creator contains <rdf:li>...</rdf:li>; overwrite only the text outside tags
                for t in re.finditer(rb">([^<]+)<", b">" + content + b"<"):
                    seg = t.group(1)
                    if seg.strip():
                        old.append(seg)
                        off = p + m.start(2) + t.start(1) - 1
                        d[off:off + len(seg)] = b" " * len(seg)
    open(path, "wb").write(bytes(d))
    d2 = open(path, "rb").read()
    ok = len(d2) == length and pdf_page_count(d2) == pages
    remaining = [s for s in old if len(s.strip()) >= 4 and s in d2]
    if remaining:
        ok = False
    render = None
    if has_command("sips"):
        with tempfile.TemporaryDirectory() as t:
            r = subprocess.run(["sips", "-s", "format", "png", path, "--out", os.path.join(t, "s.png")],
                               capture_output=True)
            render = r.returncode == 0 and os.path.getsize(os.path.join(t, "s.png")) > 0 if r.returncode == 0 else False
    return {"size_unchanged": len(d2) == length, "pages_unchanged": pdf_page_count(d2) == pages,
            "old_values_remaining": len(remaining), "render_sips": render, "overwritten": len(old)}, ok


# ---------------------------------------------------------------- xattr

def xattr_list(path):
    if not has_command("xattr"):
        return None
    r = subprocess.run(["xattr", path], capture_output=True, text=True)
    return [x for x in r.stdout.split("\n") if x]


def xattr_remove(path):
    # the system adds com.apple.provenance by itself on every write; it cannot be removed
    # permanently and carries no content (git does not transfer it) - not treated as an error.
    subprocess.run(["xattr", "-c", path], capture_output=True)
    return set(xattr_list(path) or []) <= {"com.apple.provenance"}


# ---------------------------------------------------------------- main

def collect_files(arguments, skip):
    files = []
    for a in arguments:
        if os.path.isdir(a):
            for directory, _, names in os.walk(a):
                for n in sorted(names):
                    p = os.path.join(directory, n)
                    if n in skip or os.path.relpath(p, a) in skip:
                        continue
                    files.append(p)
        elif os.path.isfile(a):
            files.append(a)
        else:
            print("No such file: %s" % a, file=sys.stderr)
            sys.exit(2)
    return files


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        print("Version %s" % VERSION)
        return 0
    mode = None
    title = False
    xattr_on = True
    skip = set()
    targets = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--check":
            mode = "check"
        elif a == "--clean":
            mode = "clean"
        elif a == "--title":
            title = True
        elif a == "--no-xattr":
            xattr_on = False
        elif a == "--skip":
            i += 1
            skip.add(argv[i])
        elif a == "--version":
            print("clean_metadata.py %s" % VERSION)
            return 0
        elif a.startswith("-"):
            print("Unknown option: %s" % a, file=sys.stderr)
            return 2
        else:
            targets.append(a)
        i += 1
    if mode is None or not targets:
        print("Give --check or --clean and a file/directory.", file=sys.stderr)
        return 2
    files = collect_files(targets, skip)
    errors = 0
    ds_store = [p for p in files if os.path.basename(p) == ".DS_Store"]
    for p in ds_store:
        print("WARNING .DS_Store: %s (remove by hand)" % p)
    for p in files:
        if os.path.basename(p) == ".DS_Store":
            continue
        ext = os.path.splitext(p)[1].lower()
        xa = xattr_list(p) if xattr_on else None
        line = [p]
        if ext == ".png":
            try:
                r = png_check(p)
            except ValueError as e:
                print("%s: %s" % (p, e))
                errors += 1
                continue
            line.append("PNG %dx%d; chunks to remove: %s" % (r["size"][0], r["size"][1], ", ".join(r["to_remove"]) or "none"))
            if mode == "clean" and r["to_remove"]:
                before, ok = png_clean(p)
                r2 = png_check(p)
                line.append("CLEANED (size after: %dx%d, IDAT check: %s)" % (r2["size"][0], r2["size"][1], "OK" if ok else "ERROR"))
                if not ok:
                    errors += 1
        elif ext == ".pdf":
            r = pdf_check(p, title)
            desc = []
            for n, fields in r["info"]:
                desc.append("Info obj %d: %s" % (n, ", ".join("%s[%d,%s%s]" % (k, ln, st, "" if cl else ",kept") for k, ln, st, cl in fields)))
            desc.append("XMP: %s" % ("; ".join(r["xmp"]) or "none"))
            desc.append("startxref=%d, /Prev in trailer=%d, pages=%d, attachments=%d, annotations /T=%d, encryption=%d" % (
                r["startxref"], r["prev_in_trailer"], r["pages"], r["attachments"], r["annotations_T"], r["encryption"]))
            line.append("PDF " + " | ".join(desc))
            to_clean = any(st == "value" and cl for _, fields in r["info"] for _, _, st, cl in fields) or any(x.startswith("uncompressed") and "tags: " in x and not x.endswith("tags: ") for x in r["xmp"])
            if mode == "clean" and to_clean:
                w, ok = pdf_clean(p, title)
                line.append("CLEANED %s" % w)
                if not ok:
                    errors += 1
        else:
            line.append("text/data file - content unchanged")
        if xa:
            line.append("xattr: %s" % ", ".join(xa))
            if mode == "clean":
                line.append("xattr removed: %s" % ("OK" if xattr_remove(p) else "ERROR"))
        print("  ".join(line))
    print("clean_metadata.py %s. Files: %d, verification errors: %d" % (VERSION, len(files), errors))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
