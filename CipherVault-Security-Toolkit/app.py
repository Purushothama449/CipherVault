"""
Cyber Encryption Center
A Flask-powered encryption & decryption toolkit.
"""

import io
import base64
from datetime import datetime

from flask import Flask, render_template, request, send_file, jsonify
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload cap


# ----------------------------------------------------------------------
# Cipher helpers (used for file-level byte operations on the server)
# ----------------------------------------------------------------------
def _xor_bytes(data: bytes, key: str) -> bytes:
    key = key or "key"
    key_bytes = key.encode("utf-8")
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


def _shift_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b + shift) % 256 for b in data)


# ----------------------------------------------------------------------
# Page routes
# ----------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ----------------------------------------------------------------------
# File encryption / decryption
# ----------------------------------------------------------------------
@app.route("/api/encrypt-file", methods=["POST"])
def encrypt_file():
    file = request.files.get("file")
    algorithm = request.form.get("algorithm", "caesar")
    key = request.form.get("key", "3")

    if not file or file.filename == "":
        return jsonify({"error": "No file provided"}), 400

    data = file.read()

    try:
        if algorithm == "xor":
            out = _xor_bytes(data, key)
        elif algorithm == "base64":
            out = base64.b64encode(data)
        else:  # caesar / rot13 -> byte shift
            shift = 13 if algorithm == "rot13" else int(key or 3)
            out = _shift_bytes(data, shift)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Encryption failed: {exc}"}), 400

    buf = io.BytesIO(out)
    buf.seek(0)
    return send_file(
        buf,
        as_attachment=True,
        download_name=f"encrypted_{file.filename}",
        mimetype="application/octet-stream",
    )


@app.route("/api/decrypt-file", methods=["POST"])
def decrypt_file():
    file = request.files.get("file")
    algorithm = request.form.get("algorithm", "caesar")
    key = request.form.get("key", "3")

    if not file or file.filename == "":
        return jsonify({"error": "No file provided"}), 400

    data = file.read()

    try:
        if algorithm == "xor":
            out = _xor_bytes(data, key)
        elif algorithm == "base64":
            out = base64.b64decode(data)
        else:
            shift = 13 if algorithm == "rot13" else int(key or 3)
            out = _shift_bytes(data, -shift)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Decryption failed: {exc}"}), 400

    name = file.filename
    if name.startswith("encrypted_"):
        name = name[len("encrypted_"):]

    buf = io.BytesIO(out)
    buf.seek(0)
    return send_file(
        buf,
        as_attachment=True,
        download_name=f"decrypted_{name}",
        mimetype="application/octet-stream",
    )


# ----------------------------------------------------------------------
# Security report (PDF) -- built with reportlab
# ----------------------------------------------------------------------
@app.route("/api/security-report", methods=["POST"])
def security_report():
    payload = request.get_json(force=True, silent=True) or {}
    stats = payload.get("stats", {})
    activity = payload.get("activity", [])

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter, topMargin=0.7 * inch, bottomMargin=0.7 * inch
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleCustom",
        parent=styles["Title"],
        textColor=colors.HexColor("#0e1726"),
        fontSize=22,
        spaceAfter=2,
    )
    subtitle_style = ParagraphStyle(
        "SubtitleCustom",
        parent=styles["Normal"],
        textColor=colors.HexColor("#0891b2"),
        fontSize=12,
        spaceAfter=10,
    )
    heading_style = ParagraphStyle(
        "HeadingCustom",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#0e7490"),
        spaceBefore=14,
        spaceAfter=8,
    )
    footer_style = ParagraphStyle(
        "FooterCustom",
        parent=styles["Italic"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#64748b"),
    )

    elements = []
    elements.append(Paragraph("Cyber Encryption Center", title_style))
    elements.append(Paragraph("Security Report &mdash; DecodeLabs", subtitle_style))
    elements.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
            styles["Normal"],
        )
    )

    elements.append(Paragraph("System Overview", heading_style))
    overview_data = [
        ["Metric", "Value"],
        ["Total Encryptions", str(stats.get("encryptions", 0))],
        ["Files Processed", str(stats.get("files", 0))],
        ["Threat Level", stats.get("threatLevel", "LOW")],
        ["Connection Status", stats.get("connection", "Active")],
        ["Overall Strength", f"{stats.get('strength', 87)}%"],
    ]
    t = Table(overview_data, colWidths=[3 * inch, 3 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e7490")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(t)

    elements.append(Paragraph("Recent Activity", heading_style))
    if activity:
        act_data = [["Action", "Detail", "Time"]]
        for a in activity[:25]:
            detail = str(a.get("detail", ""))[:46]
            act_data.append([a.get("action", ""), detail, a.get("time", "")])
        t2 = Table(act_data, colWidths=[1.8 * inch, 3.0 * inch, 1.2 * inch])
        t2.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e7490")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        elements.append(t2)
    else:
        elements.append(Paragraph("No recent activity recorded.", styles["Normal"]))

    elements.append(Spacer(1, 0.4 * inch))
    elements.append(Paragraph("Protected by DecodeLabs", footer_style))

    doc.build(elements)
    buf.seek(0)
    return send_file(
        buf,
        as_attachment=True,
        download_name="security_report.pdf",
        mimetype="application/pdf",
    )


if __name__ == "__main__":
    app.run(debug=True)
