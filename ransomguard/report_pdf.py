"""Dependency-free PDF writer for incident reports (monospaced text, A4, automatic pagination).

Why hand-written: the project should run after `pip install watchdog psutil` only. The output is a plain PDF 1.4 file with
the built-in Courier fonts, so it opens in every viewer and needs no embedded font files."""
import textwrap
import time

PAGE_W, PAGE_H, MARGIN, FS, LEAD = 595, 842, 48, 8.5, 11.0
CHARS = 96                                   # Courier is 0.6 em wide: 96 * 8.5 * 0.6 = 490 pt, inside the margins
LINES_PER_PAGE = int((PAGE_H - 2 * MARGIN - 40) // LEAD)


def _esc(s):
    s = s.encode("cp1252", "replace").decode("cp1252")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(text):
    out = []
    for line in text.splitlines():
        if not line.strip():
            out.append("")
            continue
        indent = len(line) - len(line.lstrip())
        out += textwrap.wrap(line, CHARS, subsequent_indent=" " * (indent + 4), break_long_words=True, drop_whitespace=False) or [""]
    return out


def build_pdf(title, body, footer="RansomGuard - confidential incident report"):
    """Return the PDF file content (bytes) for a title and a block of monospaced text."""
    head = [title, f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')}", "-" * CHARS, ""]
    lines = head + _wrap(body)
    pages = [lines[i:i + LINES_PER_PAGE] for i in range(0, len(lines), LINES_PER_PAGE)] or [[""]]
    objs = []                                                    # 1-based object numbers = index + 1
    add = lambda data: (objs.append(data), len(objs))[1]
    add(b"<< /Type /Catalog /Pages 2 0 R >>")                    # 1
    add(b"")                                                     # 2 (Pages, filled in below)
    f_reg = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")
    f_bold = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>")
    kids = []
    for n, pg in enumerate(pages, 1):
        ops = ["BT", f"/F1 {FS} Tf", f"{LEAD} TL", f"{MARGIN} {PAGE_H - MARGIN} Td"]
        for i, ln in enumerate(pg):
            if n == 1 and i == 0:
                ops.append(f"/F2 13 Tf 18 TL ({_esc(ln)}) Tj T* /F1 {FS} Tf {LEAD} TL")
            else:
                ops.append(f"({_esc(ln)}) Tj T*")
        ops += ["ET", "BT", f"/F1 7 Tf {MARGIN} {MARGIN - 18} Td ({_esc(footer)}   -   page {n} of {len(pages)}) Tj", "ET"]
        stream = "\n".join(ops).encode("cp1252", "replace")
        content = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        page = add(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] /Contents {content} 0 R "
                   f"/Resources << /Font << /F1 {f_reg} 0 R /F2 {f_bold} 0 R >> >> >>".encode())
        kids.append(page)
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>".encode()
    out, offs = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for o in offs:
        out += f"{o:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def write_pdf(path, title, body):
    data = build_pdf(title, body)
    with open(path, "wb") as f:
        f.write(data)
    return len(data)
