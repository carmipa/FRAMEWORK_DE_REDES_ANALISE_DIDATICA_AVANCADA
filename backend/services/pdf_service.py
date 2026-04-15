import io
import unicodedata


def gerar_pdf_simples(texto):
    """Gera PDF básico (1 página) sem dependências externas."""

    def _pdf_safe_text(s):
        normalized = unicodedata.normalize("NFKD", s)
        ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
        return ascii_only.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    lines = [_pdf_safe_text(ln)[:110] for ln in texto.splitlines()]
    stream_lines = [
        "BT",
        "/F1 11 Tf",
        "14 TL",
        "72 800 Td",
    ]
    for ln in lines[:58]:
        stream_lines.append(f"({ln}) Tj")
        stream_lines.append("T*")
    stream_lines.append("ET")
    content = "\n".join(stream_lines).encode("latin-1", errors="replace")

    objs = []
    objs.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objs.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objs.append(
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n"
    )
    objs.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
    objs.append(f"5 0 obj << /Length {len(content)} >> stream\n".encode("ascii") + content + b"\nendstream endobj\n")

    output = io.BytesIO()
    output.write(b"%PDF-1.4\n")
    xref = [0]
    for obj in objs:
        xref.append(output.tell())
        output.write(obj)
    xref_pos = output.tell()
    output.write(f"xref\n0 {len(xref)}\n".encode("ascii"))
    output.write(b"0000000000 65535 f \n")
    for pos in xref[1:]:
        output.write(f"{pos:010d} 00000 n \n".encode("ascii"))
    output.write(f"trailer << /Size {len(xref)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode("ascii"))
    output.seek(0)
    return output

