"""
AgentAudit DPDP Compliance Report Generator
============================================
Reads the HMAC-signed audit_trail.jsonl, verifies every entry's signature,
and produces a 1-2 page PDF compliance summary suitable for a DPO to
attach to a regulatory filing or board report.
 
DPDP Act 2025 alignment:
  - Rule 6 (Forensic Integrity): every entry's HMAC signature is verified
    and the report states the integrity status explicitly.
  - Rule 7 (Reasonable Security Safeguards): violation breakdown shows
    which safeguard categories fired during the period.
 
Usage:
  python compliance_report.py
  python compliance_report.py --log ./logs/audit_trail.jsonl --out report.pdf
  python compliance_report.py --org "Acme Bank Pvt Ltd" --period "Q1 2026"
 
Requires:
  pip install reportlab
"""
 
import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
 
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
        KeepTogether,
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
except ImportError:
    print("ERROR: reportlab is not installed.", file=sys.stderr)
    print("Install with: pip install reportlab", file=sys.stderr)
    sys.exit(2)
 
# Reuse the engine's verifier — single source of truth.
try:
    from audit import verify_log_entry
except ImportError:
    print("ERROR: cannot import verify_log_entry from audit.py.", file=sys.stderr)
    print("Run this script from the AgentAudit repository root.", file=sys.stderr)
    sys.exit(2)
 
 
# ---------- Color palette (DPDP-compliance professional) ----------
 
COLOR_PRIMARY = colors.HexColor("#0B3D91")     # deep navy
COLOR_ACCENT = colors.HexColor("#D9531E")      # warning amber
COLOR_GREEN = colors.HexColor("#1B7E3A")       # pass
COLOR_RED = colors.HexColor("#B3261E")         # block / fail
COLOR_GREY_BG = colors.HexColor("#F2F2F2")
COLOR_GREY_LINE = colors.HexColor("#CCCCCC")
COLOR_TEXT = colors.HexColor("#212121")
COLOR_DIM = colors.HexColor("#666666")
 
 
# ---------- Violation category mapping ----------
 
VIOLATION_CATEGORIES = {
    "CONFIRMED_DATA_EXFILTRATION_PATTERN": "Credential / Secret Leak",
    "PII_DETECTED": "Indian PII (DPDP Rule 7)",
    "UNAUTHORIZED_HIGH_ENTROPY_DRIFT": "Cryptographic Obfuscation",
    "TOTAL_PILOT_DEVIATION": "Prompt Injection / Intent Drift",
}
 
 
def categorize(violation: str) -> str:
    """Map a raw violation code to a human-readable category."""
    if violation.startswith("PII_DETECTED"):
        return VIOLATION_CATEGORIES["PII_DETECTED"]
    return VIOLATION_CATEGORIES.get(violation, "Other")
 
 
# ---------- Audit log loader + verifier ----------
 
def load_and_verify(log_path: str) -> dict:
    """
    Read the JSONL audit log, verify every signature, return aggregate stats.
    """
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Audit log not found: {log_path}")
 
    entries = []
    verified = 0
    tampered = 0
    parse_errors = 0
 
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if verify_log_entry(line):
                verified += 1
            else:
                # Try to parse it for the report even if signature failed
                tampered += 1
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                parse_errors += 1
 
    if not entries:
        return {
            "entries": [],
            "total": 0,
            "blocked_count": 0,
            "safe_count": 0,
            "verified": 0,
            "tampered": 0,
            "parse_errors": parse_errors,
            "category_counter": Counter(),
            "raw_violation_counter": Counter(),
            "first_ts": None,
            "last_ts": None,
            "unique_sessions": 0,
            "unique_tools": 0,
            "log_sha256": _file_sha256(log_path),
            "log_path": log_path,
        }
 
    # Aggregate stats
    total = len(entries)
    blocked = [e for e in entries if e.get("verdict") == "BLOCKED"]
    safe = [e for e in entries if e.get("verdict") == "SAFE"]
 
    # Violation category counts
    category_counter = Counter()
    raw_violation_counter = Counter()
    for entry in blocked:
        for v in entry.get("violations", []) or []:
            category_counter[categorize(v)] += 1
            # For top-violations table, normalize PII_DETECTED:* to just PII_DETECTED
            normalized = v.split(":")[0] if v.startswith("PII_DETECTED") else v
            raw_violation_counter[normalized] += 1
 
    # Time range
    timestamps = sorted(e.get("timestamp", "") for e in entries if e.get("timestamp"))
    first_ts = timestamps[0] if timestamps else None
    last_ts = timestamps[-1] if timestamps else None
 
    # Unique sessions and tools
    unique_sessions = len({e.get("session_id") for e in entries if e.get("session_id")})
    unique_tools = len({e.get("tool_name") for e in entries if e.get("tool_name")})
 
    return {
        "entries": entries,
        "total": total,
        "blocked_count": len(blocked),
        "safe_count": len(safe),
        "verified": verified,
        "tampered": tampered,
        "parse_errors": parse_errors,
        "category_counter": category_counter,
        "raw_violation_counter": raw_violation_counter,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "unique_sessions": unique_sessions,
        "unique_tools": unique_tools,
        "log_sha256": _file_sha256(log_path),
        "log_path": log_path,
    }
 
 
def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
 
 
# ---------- PDF builder ----------
 
def build_pdf(stats: dict, out_path: str, org: str, period: str, version: str):
    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="AgentAudit DPDP Compliance Report",
        author="AgentAudit Sentinel OS",
    )
 
    styles = getSampleStyleSheet()
    s_title = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        textColor=COLOR_PRIMARY,
        spaceAfter=4,
        alignment=TA_LEFT,
    )
    s_subtitle = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=11,
        textColor=COLOR_DIM,
        spaceAfter=14,
    )
    s_h2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=COLOR_PRIMARY,
        spaceBefore=10,
        spaceAfter=6,
    )
    s_body = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=9.5,
        textColor=COLOR_TEXT,
        leading=13,
    )
    s_footer = ParagraphStyle(
        "Footer",
        parent=styles["Normal"],
        fontSize=7.5,
        textColor=COLOR_DIM,
        alignment=TA_CENTER,
    )
 
    story = []
 
    # ---- Header ----
    story.append(Paragraph("DPDP Compliance Report", s_title))
    story.append(Paragraph(
        f"Generated by AgentAudit Sentinel OS v{version} &nbsp;·&nbsp; "
        f"DPDP Act 2025, Rules 6 &amp; 7",
        s_subtitle,
    ))
 
    # ---- Report metadata table ----
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
 
    meta_data = [
        ["Organization", org],
        ["Reporting Period", period],
        ["Report Generated", generated_at],
        ["Source Log", stats["log_path"]],
        ["Source Log SHA-256", _truncate_hash(stats["log_sha256"])],
    ]
    meta_table = Table(meta_data, colWidths=[45 * mm, 125 * mm])
    meta_table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
        ("TEXTCOLOR", (0, 0), (0, -1), COLOR_PRIMARY),
        ("TEXTCOLOR", (1, 0), (1, -1), COLOR_TEXT),
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_GREY_BG),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, COLOR_GREY_BG]),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, COLOR_GREY_LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8))
 
    # ---- Empty log handling ----
    if stats["total"] == 0:
        story.append(Paragraph("Audit Trail Status", s_h2))
        story.append(Paragraph(
            "<b>The audit log is empty.</b> No interception decisions were recorded "
            "during the reporting period. Verify that the AgentAudit Sentinel was "
            "active and that traffic was being routed through the proxy.",
            s_body,
        ))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f"<i>Source log file present at {stats['log_path']} but contains zero entries.</i>",
            s_body,
        ))
        _build_footer_and_save(doc, story, s_footer, version)
        return
 
    # ---- Forensic Integrity status ----
    story.append(Paragraph("Forensic Integrity (DPDP Rule 6)", s_h2))
 
    integrity_clean = stats["tampered"] == 0 and stats["parse_errors"] == 0
    if integrity_clean:
        integrity_text = (
            f"<font color='#1B7E3A'><b>VERIFIED.</b></font> "
            f"All {stats['verified']} log entries passed HMAC-SHA256 signature "
            f"verification. The audit trail is cryptographically intact and has not "
            f"been tampered with since each entry was written."
        )
    else:
        integrity_text = (
            f"<font color='#B3261E'><b>INTEGRITY FAILURE.</b></font> "
            f"{stats['verified']} of {stats['verified'] + stats['tampered']} entries "
            f"passed HMAC verification. {stats['tampered']} entries failed signature "
            f"verification and may have been tampered with. "
            f"{stats['parse_errors']} entries were unparseable. "
            f"Investigate immediately and preserve the source log for forensic review."
        )
    story.append(Paragraph(integrity_text, s_body))
    story.append(Spacer(1, 8))
 
    # ---- Activity Summary ----
    story.append(Paragraph("Activity Summary", s_h2))
 
    block_rate = (stats["blocked_count"] / stats["total"]) * 100 if stats["total"] else 0.0
 
    summary_data = [
        ["Metric", "Value"],
        ["Total Interception Decisions", f"{stats['total']:,}"],
        ["Allowed (SAFE)", f"{stats['safe_count']:,}"],
        ["Blocked (Policy Violation)", f"{stats['blocked_count']:,}"],
        ["Block Rate", f"{block_rate:.2f}%"],
        ["Unique Agent Sessions", f"{stats['unique_sessions']:,}"],
        ["Distinct Tools Invoked", f"{stats['unique_tools']:,}"],
        ["First Event", _fmt_ts(stats["first_ts"])],
        ["Last Event", _fmt_ts(stats["last_ts"])],
    ]
    summary_table = Table(summary_data, colWidths=[85 * mm, 85 * mm])
    summary_table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_GREY_BG]),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, COLOR_GREY_LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8))
 
    # ---- Violation Breakdown by Safeguard Category ----
    if stats["blocked_count"] > 0:
        story.append(Paragraph(
            "Violation Breakdown by Safeguard Category (DPDP Rule 7)", s_h2,
        ))
 
        cat_data = [["Safeguard Category", "Block Events", "% of Blocks"]]
        for category, count in stats["category_counter"].most_common():
            pct = (count / stats["blocked_count"]) * 100
            cat_data.append([category, f"{count:,}", f"{pct:.1f}%"])
 
        cat_table = Table(cat_data, colWidths=[100 * mm, 35 * mm, 35 * mm])
        cat_table.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
            ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_GREY_BG]),
            ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, COLOR_GREY_LINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(cat_table)
        story.append(Spacer(1, 8))
 
        # ---- Top 10 specific violations ----
        top_block = []
        top_block.append(Paragraph("Top Violation Codes", s_h2))
        top_data = [["Violation Code", "Count"]]
        for code, count in stats["raw_violation_counter"].most_common(10):
            top_data.append([code, f"{count:,}"])
 
        top_table = Table(top_data, colWidths=[135 * mm, 35 * mm])
        top_table.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
            ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_GREY_BG]),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, COLOR_GREY_LINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        top_block.append(top_table)
        story.append(KeepTogether(top_block))
    else:
        story.append(Paragraph("Violation Breakdown", s_h2))
        story.append(Paragraph(
            "<b>No policy violations recorded during this reporting period.</b> "
            "All agentic tool-calls passed the four-layer Sentinel inspection pipeline.",
            s_body,
        ))
 
    _build_footer_and_save(doc, story, s_footer, version)
 
 
def _build_footer_and_save(doc, story, footer_style, version):
    """Add footer and render the document."""
    def _on_page(canvas, doc_obj):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(COLOR_DIM)
        page_width = A4[0]
        footer_text = (
            f"AgentAudit Sentinel OS v{version}  ·  "
            f"DPDP Act 2025 Compliance Report  ·  "
            f"Page {doc_obj.page}"
        )
        canvas.drawCentredString(page_width / 2, 10 * mm, footer_text)
        canvas.restoreState()
 
    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
 
 
def _truncate_hash(h: str) -> str:
    """Display a long hex hash as 'first8...last8' for readability."""
    if not h or len(h) < 20:
        return h or "(unavailable)"
    return f"{h[:16]}...{h[-16:]}"
 
 
def _fmt_ts(ts: str) -> str:
    """Convert ISO timestamp to a more readable display form."""
    if not ts:
        return "(none)"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return ts
 
 
# ---------- CLI ----------
 
def main():
    parser = argparse.ArgumentParser(
        description="Generate a DPDP compliance report PDF from the AgentAudit audit trail.",
    )
    parser.add_argument(
        "--log",
        default="./logs/audit_trail.jsonl",
        help="Path to the audit trail JSONL file (default: ./logs/audit_trail.jsonl)",
    )
    parser.add_argument(
        "--out",
        default="dpdp_compliance_report.pdf",
        help="Output PDF path (default: dpdp_compliance_report.pdf)",
    )
    parser.add_argument(
        "--org",
        default="[Customer Organization]",
        help="Organization name printed on the report",
    )
    parser.add_argument(
        "--period",
        default=None,
        help="Reporting period label (default: derived from log timestamps)",
    )
    parser.add_argument(
        "--version",
        default="10.9",
        help="AgentAudit version string for the footer (default: 10.9)",
    )
    args = parser.parse_args()
 
    print(f"Reading audit log: {args.log}")
    try:
        stats = load_and_verify(args.log)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
 
    period = args.period or (
        f"{_fmt_ts(stats.get('first_ts'))} – {_fmt_ts(stats.get('last_ts'))}"
        if stats.get("first_ts") else "(empty log)"
    )
 
    print(f"Total entries:    {stats.get('total', 0)}")
    print(f"  Verified HMAC:  {stats.get('verified', 0)}")
    print(f"  Tampered:       {stats.get('tampered', 0)}")
    print(f"  Blocked:        {stats.get('blocked_count', 0)}")
    print(f"  Safe:           {stats.get('safe_count', 0)}")
 
    print(f"Generating PDF: {args.out}")
    build_pdf(stats, args.out, args.org, period, args.version)
    print(f"Report written: {os.path.abspath(args.out)}")
    return 0
 
 
if __name__ == "__main__":
    sys.exit(main())