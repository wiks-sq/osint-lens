"""Regenerates the binary test fixtures (run from the repo root: python3 tests/fixtures/make_fixtures.py).

Requires Pillow. The generated files are committed, so you only need this when
changing them.
"""
import io
import os
import zipfile
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))


def rational_dms(value):
    from fractions import Fraction
    from PIL.TiffImagePlugin import IFDRational
    d = int(value)
    m = int((value - d) * 60)
    s = Fraction(round(((value - d) * 60 - m) * 60 * 100), 100)
    return (IFDRational(d, 1), IFDRational(m, 1), IFDRational(s.numerator, s.denominator))


def make_jpeg():
    img = Image.new("RGB", (32, 24), (40, 120, 200))
    exif = Image.Exif()
    exif[0x010F] = "Canon"
    exif[0x0110] = "Canon EOS R6"
    exif[0x0131] = "Adobe Photoshop 25.0 (Windows)"
    exif[0x013B] = "Jane Example"
    exif[0x8298] = "(c) Example Oy"
    ifd = exif.get_ifd(0x8769)
    ifd[0x9003] = "2024:06:21 14:03:59"
    ifd[0xA431] = "032021001234"
    ifd[0xA434] = "RF24-105mm F4 L IS USM"
    gps = exif.get_ifd(0x8825)
    gps[1] = "N"
    gps[2] = rational_dms(60.169857)
    gps[3] = "E"
    gps[4] = rational_dms(24.938379)
    img.save(os.path.join(HERE, "photo_gps.jpg"), exif=exif.tobytes(), quality=80)


def make_png():
    from PIL import PngImagePlugin
    img = Image.new("RGB", (8, 8), (255, 0, 0))
    info = PngImagePlugin.PngInfo()
    info.add_text("Author", "PNG Author")
    info.add_text("Software", "GIMP 2.10")
    img.save(os.path.join(HERE, "meta.png"), pnginfo=info)


def make_docx():
    path = os.path.join(HERE, "report.docx")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("docProps/core.xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
            '<dc:title>Q3 salaries</dc:title><dc:creator>Matti Meikäläinen</dc:creator>'
            '<cp:lastModifiedBy>mmeikalainen</cp:lastModifiedBy><cp:revision>7</cp:revision>'
            '<dcterms:created>2024-09-01T08:00:00Z</dcterms:created><dcterms:modified>2024-09-03T12:30:00Z</dcterms:modified>'
            '</cp:coreProperties>'))
        z.writestr("docProps/app.xml", (
            '<?xml version="1.0"?><Properties><Template>C:\\Users\\mmeikalainen\\AppData\\Roaming\\Microsoft\\Templates\\Normal.dotm</Template>'
            '<Application>Microsoft Office Word</Application><AppVersion>16.0000</AppVersion><Company>Example Oy</Company><TotalTime>42</TotalTime></Properties>'))
        z.writestr("word/document.xml", '<w:document xmlns:w="w"><w:body><w:ins w:author="Liisa Virtanen"/></w:body></w:document>')
        z.writestr("word/comments.xml", '<w:comments xmlns:w="w"><w:comment w:author="Pekka Korhonen"/></w:comments>')


def make_pdf():
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >> endobj\n"
        b"4 0 obj << /Title (Internal pricing) /Author (John Q. Public) /Creator (Microsoft\\256 Word 2019) "
        b"/Producer <FEFF004D006900630072006F0073006F0066007400AE00200057006F0072006400200032003000310039> "
        b"/CreationDate (D:20230115093000+02'00') >> endobj\n"
        b"trailer << /Root 1 0 R /Info 4 0 R >>\n%%EOF\n"
    )
    with open(os.path.join(HERE, "doc.pdf"), "wb") as f:
        f.write(body)


def make_favicon():
    img = Image.new("RGBA", (16, 16), (10, 200, 90, 255))
    img.save(os.path.join(HERE, "favicon.ico"), sizes=[(16, 16)])


if __name__ == "__main__":
    make_jpeg()
    make_png()
    make_docx()
    make_pdf()
    make_favicon()
    print("fixtures written to", HERE)
