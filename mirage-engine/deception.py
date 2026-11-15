from fpdf import FPDF
from docx import Document
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
import base64
import hashlib
import os
import html
import json
import random
import urllib.parse
from datetime import datetime
import honeytoken

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GEN_DIR = os.path.join(BASE_DIR, "generated_decoys")
os.makedirs(GEN_DIR, exist_ok=True)

_BULAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"]
_FAUNA = ["GARUDA", "ELANG", "RAJAWALI", "MACAN", "BANTENG", "KOMODO", "WALET", "ENGGANG"]
_SIFAT = ["WASKITA", "SAMUDRA", "PARAMARTA", "BRAJA", "CAKRA", "TIRTA", "BAYU", "ARUNA"]
_KOTA = ["Jakarta Pusat", "Bogor", "Bandung", "Semarang", "Surabaya", "Makassar", "Balikpapan", "Banjarmasin"]
_KEGIATAN = [
    "Pengamanan kunjungan kerja", "Pengawalan rombongan", "Peninjauan fasilitas",
    "Rapat koordinasi pengamanan", "Pendaratan dan transit",
]


def _seed(session_id: str) -> random.Random:
    """Nilai deterministik per sesi: dokumen yang bocor bisa dikaitkan ke satu sesi (watermark),
    dan dua sesi tidak pernah memiliki isi yang sama."""
    return random.Random(int(hashlib.sha256(session_id.encode()).hexdigest()[:16], 16))


def session_facts(session_id: str) -> dict:
    r = _seed(session_id)
    now = datetime.now()
    lat = -6.0 - r.random() * 2.2
    lon = 106.4 + r.random() * 4.5
    return {
        "sandi": f"{r.choice(_FAUNA)}-{r.choice(_SIFAT)}-{r.randint(10, 99)}",
        "nomor": f"ST/{r.randint(100, 999)}/{_BULAN[now.month - 1]}/{now.year}/Sops",
        "koordinat": f"{lat:.6f}, {lon:.6f}",
        "frek": f"{r.randint(225, 399)}.{r.randint(0, 9)}{r.randint(0, 9)}{r.randint(0, 9)} MHz",
        "kota": r.choice(_KOTA),
        "kegiatan": r.choice(_KEGIATAN),
        "jam": [f"{h:02d}.{r.choice(['00', '15', '30', '45'])}" for h in sorted(r.sample(range(5, 20), 4))],
        "kode_ref": "".join(r.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(10)),
        "tanggal": now.strftime("%d-%m-%Y"),
    }


def beacon_url(base: str, session_id: str, channel: str) -> str:
    """Path dibuat menyerupai aset biasa, bukan 'telemetry'."""
    return f"{base}/assets/{urllib.parse.quote(session_id)}?channel={channel}"


def create_poisoned_pdf(session_id: str, callback_base_url: str) -> str:
    f = session_facts(session_id)
    pdf = FPDF()
    pdf.set_title(f"Telegram Operasi {f['nomor']}")
    pdf.set_author("Staf Operasi")
    pdf.set_creator("Microsoft Word")
    pdf.set_producer("Microsoft: Print To PDF")

    pdf.add_page()
    pdf.set_font("Courier", "B", 13)
    pdf.cell(0, 8, "SURAT TELEGRAM", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Courier", "", 10)
    pdf.cell(0, 6, f"NOMOR {f['nomor']}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 6, "KLASIFIKASI: RAHASIA", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(6)
    pdf.set_font("Courier", "", 11)
    pdf.multi_cell(0, 6, (
        f"Dari      : Asops\n"
        f"Kepada    : Kasdam, Danrem, Dandim (lihat distribusi)\n"
        f"Perihal   : {f['kegiatan']} - {f['kota']}\n"
        f"Sandi     : {f['sandi']}\n"
        f"Tanggal   : {f['tanggal']}\n"
    ))
    pdf.ln(3)
    pdf.set_font("Courier", "B", 11)
    pdf.cell(0, 7, "1. DASAR", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 11)
    pdf.multi_cell(0, 6, (
        "a. Rencana kegiatan pimpinan sesuai agenda terbaru.\n"
        "b. Hasil koordinasi dengan satuan pengamanan setempat.\n"
        "c. Ketentuan pengamanan dan komunikasi yang berlaku."
    ))
    pdf.ln(3)
    pdf.set_font("Courier", "B", 11)
    pdf.cell(0, 7, "2. PELAKSANAAN", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 11)
    pdf.multi_cell(0, 6, (
        f"a. Titik kumpul    : {f['koordinat']}\n"
        f"b. Jalur komunikasi: {f['frek']} (cadangan)\n"
        f"c. Rujukan berkas  : {f['kode_ref']}"
    ))

    pdf.add_page()
    pdf.set_font("Courier", "B", 11)
    pdf.cell(0, 7, "3. RENCANA WAKTU", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 11)
    etapa = ["Tiba / pendaratan", "Pergerakan ke lokasi", "Kegiatan utama", "Kembali / transit"]
    for jam, e in zip(f["jam"], etapa):
        pdf.cell(0, 6, f"   {jam} WIB   {e}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Courier", "B", 11)
    pdf.cell(0, 7, "4. LAMPIRAN", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 11)
    pdf.multi_cell(0, 6, "Lampiran A (peta rute dan jadwal rinci) tersedia pada tautan berikut.")
    pdf.ln(2)
    url = beacon_url(callback_base_url, session_id, "pdf_link")
    pdf.set_text_color(0, 0, 255)
    pdf.cell(0, 7, "Buka Lampiran A", new_x="LMARGIN", new_y="NEXT", link=url)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)
    cred = honeytoken.mint(session_id)
    pdf.set_font("Courier", "B", 11)
    pdf.cell(0, 7, "5. AKSES PORTAL KOORDINASI", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 11)
    pdf.multi_cell(0, 6, (
        f"Portal   : {callback_base_url}/portal\n"
        f"Pengguna : {cred['username']}\n"
        f"Kata sandi: {cred['password']}\n"
        "Ganti sandi setelah login pertama."
    ))
    pdf.ln(4)
    pdf.set_font("Courier", "", 9)
    pdf.cell(0, 5, f"Hal. 2 dari 2   |   Ref {f['kode_ref']}", new_x="LMARGIN", new_y="NEXT", align="R")

    filepath = os.path.join(GEN_DIR, f"DOKUMEN_VVIP_{session_id}.pdf")
    pdf.output(filepath)
    return filepath


def create_poisoned_html_decoy(session_id: str, callback_base_url: str) -> str:
    f = session_facts(session_id)
    url = beacon_url(callback_base_url, session_id, "img_pixel")
    escaped_url = html.escape(url)
    # URL beacon JS tidak ditulis polos di source (hanya obfuscation ringan, bukan keamanan).
    b64 = base64.b64encode(beacon_url(callback_base_url, session_id, "js_telemetry").encode()).decode()
    rel = base64.b64encode(f"/assets/{urllib.parse.quote(session_id)}?channel=js_telemetry".encode()).decode()

    cred = honeytoken.mint(session_id)
    rows = "".join(
        f"<tr><td>{j} WIB</td><td>{e}</td></tr>"
        for j, e in zip(f["jam"], ["Tiba / pendaratan", "Pergerakan ke lokasi", "Kegiatan utama", "Kembali / transit"])
    )
    html_content = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>Telegram Operasi {html.escape(f['nomor'])}</title>
<meta name="robots" content="noindex">
<style>
body{{font-family:Georgia,serif;max-width:760px;margin:32px auto;padding:0 20px;color:#111;background:#fff}}
h1{{font-size:18px;text-align:center;margin-bottom:2px}} .c{{text-align:center;font-size:13px}}
table{{border-collapse:collapse;margin:12px 0}} td{{border:1px solid #999;padding:4px 10px;font-size:14px}}
.m td{{border:none;padding:2px 12px 2px 0}}
</style>
</head>
<body>
<img src="{escaped_url}" width="1" height="1" alt="" style="position:absolute;left:-9999px">
<h1>SURAT TELEGRAM</h1>
<p class="c">NOMOR {html.escape(f['nomor'])}<br>KLASIFIKASI: RAHASIA</p>
<table class="m">
<tr><td>Perihal</td><td>: {f['kegiatan']} - {f['kota']}</td></tr>
<tr><td>Sandi</td><td>: {f['sandi']}</td></tr>
<tr><td>Titik kumpul</td><td>: {f['koordinat']}</td></tr>
<tr><td>Jalur cadangan</td><td>: {f['frek']}</td></tr>
<tr><td>Rujukan</td><td>: {f['kode_ref']}</td></tr>
</table>
<p><b>Akses portal koordinasi</b></p>
<table class="m">
<tr><td>Portal</td><td>: {html.escape(callback_base_url)}/portal</td></tr>
<tr><td>Pengguna</td><td>: {cred['username']}</td></tr>
<tr><td>Kata sandi</td><td>: {cred['password']}</td></tr>
</table>
<p><b>Rencana waktu</b></p>
<table>{rows}</table>
<script>
(function(){{
  try {{
    var tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown";
    var res = screen.width + "x" + screen.height;
    var qs = "&tz=" + encodeURIComponent(tz) + "&res=" + encodeURIComponent(res);
    var u = atob({json.dumps(b64)}) + qs;
    var r = atob({json.dumps(rel)}) + qs;
    fetch(u, {{mode:"cors"}}).catch(function(){{ return fetch(r); }}).catch(function(){{}});
  }} catch(e) {{}}
}})();
</script>
</body>
</html>"""
    filepath = os.path.join(GEN_DIR, f"BRIEFING_VVIP_{session_id}.html")
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html_content)
    return filepath


def _add_hyperlink(paragraph, url: str, text: str):
    """Tautan DOCX sungguhan: relasi eksternal + elemen <w:hyperlink> yang mereferensikannya.
    (Relasi saja tanpa elemen ini tidak pernah dipicu.) Butuh klik pengguna."""
    r_id = paragraph.part.relate_to(url, RT.HYPERLINK, is_external=True)
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), r_id)
    run = OxmlElement("w:r")
    rpr = OxmlElement("w:rPr")
    color = OxmlElement("w:color")
    color.set(qn("w:val"), "0000FF")
    underline = OxmlElement("w:u")
    underline.set(qn("w:val"), "single")
    rpr.append(color)
    rpr.append(underline)
    run.append(rpr)
    t = OxmlElement("w:t")
    t.text = text
    run.append(t)
    hyperlink.append(run)
    paragraph._p.append(hyperlink)


def create_poisoned_docx(session_id: str, callback_base_url: str) -> str:
    f = session_facts(session_id)
    doc = Document()
    cp = doc.core_properties
    now = datetime.now()
    cp.author = "Staf Operasi"
    cp.last_modified_by = "Staf Operasi"
    cp.title = f"Telegram Operasi {f['nomor']}"
    cp.created = now
    cp.modified = now
    cp.comments = ""
    cp.revision = 3

    doc.add_heading("SURAT TELEGRAM", level=1)
    doc.add_paragraph(f"NOMOR {f['nomor']}  |  KLASIFIKASI: RAHASIA")
    doc.add_paragraph(f"Perihal        : {f['kegiatan']} - {f['kota']}")
    doc.add_paragraph(f"Sandi          : {f['sandi']}")
    doc.add_paragraph(f"Titik kumpul   : {f['koordinat']}")
    doc.add_paragraph(f"Jalur cadangan : {f['frek']}")
    doc.add_paragraph(f"Rujukan        : {f['kode_ref']}")
    doc.add_heading("Rencana waktu", level=2)
    for jam, e in zip(f["jam"], ["Tiba / pendaratan", "Pergerakan ke lokasi", "Kegiatan utama", "Kembali / transit"]):
        doc.add_paragraph(f"{jam} WIB  {e}", style="List Bullet")

    cred = honeytoken.mint(session_id)
    doc.add_heading("Akses portal koordinasi", level=2)
    doc.add_paragraph(f"Portal   : {callback_base_url}/portal")
    doc.add_paragraph(f"Pengguna : {cred['username']}")
    doc.add_paragraph(f"Kata sandi: {cred['password']}")
    para = doc.add_paragraph("Lampiran A (peta rute dan jadwal rinci): ")
    _add_hyperlink(para, beacon_url(callback_base_url, session_id, "docx_link"), "Buka Lampiran A")

    filepath = os.path.join(GEN_DIR, f"BRIEFING_VVIP_{session_id}.docx")
    doc.save(filepath)
    return filepath
