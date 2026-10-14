#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Metadata Tool — Universal File Metadata Extractor
v4.0 FINAL — AI File Detected: Yes/No, GPS = Lat/Lon only (robust parsing,
no fake 0.000000), no path row on browser upload, value-aware explanations
(English), terminal menu: [1] Extract / [0] Back
"""

import io, os, re, sys, csv, json, time, uuid, zlib, struct, shutil, sqlite3, tarfile, threading, traceback, zipfile, webbrowser, subprocess
import html as html_mod
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from datetime import datetime
from fractions import Fraction
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlparse, parse_qs
from urllib.request import pathname2url

APP_NAME = "Metadata Tool"
APP_SUBTITLE = "Universal File Metadata Extractor"
VERSION = "4.0"
HOST, PORT = "127.0.0.1", 5000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
HTML_FILE = os.path.join(BASE_DIR, "metadata.html")
MAX_UPLOAD_MB = 300
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
MAX_SCAN = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 400
NESTED_ARCHIVE_BYTES = 24 * 1024 * 1024
SLOW_EXTRACTION_SECONDS = 60

# ------------------------------------------------------------ optional deps
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False
try:
    from mutagen import File as MutagenFile
    HAVE_MUTAGEN = True
except Exception:
    HAVE_MUTAGEN = False
try:
    from pypdf import PdfReader, PdfWriter
    HAVE_PYPDF = True
except Exception:
    try:
        from PyPDF2 import PdfReader, PdfWriter
        HAVE_PYPDF = True
    except Exception:
        HAVE_PYPDF = False
try:
    import pefile
    HAVE_PEFILE = True
except Exception:
    HAVE_PEFILE = False
try:
    import olefile
    HAVE_OLEFILE = True
except Exception:
    HAVE_OLEFILE = False
try:
    import py7zr
    HAVE_PY7ZR = True
except Exception:
    HAVE_PY7ZR = False
try:
    import rarfile
    HAVE_RARFILE = True
except Exception:
    HAVE_RARFILE = False
try:
    import reportlab
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    HAVE_REPORTLAB = True
except Exception:
    HAVE_REPORTLAB = False
FFPROBE = shutil.which("ffprobe")
EXIFTOOL = shutil.which("exiftool")

if os.name == "nt":
    os.system("")
try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

class C:
    RESET = "\033[0m"; BOLD = "\033[1m"
    CYAN = "\033[96m"; RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    WHITE = "\033[97m"; GRAY = "\033[90m"

_GLYPHS = {
 'M':["███╗   ███╗","████╗ ████║","██╔████╔██║","██║╚██╔╝██║","██║ ╚═╝ ██║","╚═╝     ╚═╝"],
 'e':["███████╗","██╔════╝","█████╗  ","██╔══╝  ","███████╗","╚══════╝"],
 't':["████████╗","╚══██╔══╝","   ██║   ","   ██║   ","   ██║   ","   ╚═╝   "],
 'a':[" █████╗ ","██╔══██╗","███████║","██╔══██║","██║  ██║","╚═╝  ╚═╝"],
 'd':[" ██████╗ ","██╔════╝ ","██║  ███╗","██║   ██║","╚██████╔╝"," ╚═════╝ "],
 'T':["████████╗","╚══██╔══╝","   ██║   ","   ██║   ","   ██║   ","   ╚═╝   "],
 'o':[" ██████╗ ","██╔═══██╗","██║   ██║","██║   ██║","╚██████╔╝"," ╚═════╝ "],
 'l':["██╗     ","██║     ","██║     ","██║     ","███████╗","╚══════╝"],
 ' ':["   ","   ","   ","   ","   ","   "],
}

def print_banner():
    try:
        for row in range(6):
            print(C.WHITE + C.BOLD + "".join(_GLYPHS[ch][row] for ch in "Metadata ")
                  + C.RED + "".join(_GLYPHS[ch][row] for ch in "Tool") + C.RESET)
        print(C.WHITE + "U N I V E R S A L   F I L E   M E T A D A T A   E X T R A C T O R" + C.RESET)
        print(C.GRAY + "v" + VERSION + C.RESET + "\n")
    except Exception:
        print(APP_NAME + " v" + VERSION)

# ------------------------------------------------------------ helpers
def human_size(n):
    n = int(n)
    if n < 1024:
        return "%d bytes" % n
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024:
            return "%.2f %s" % (n, unit)
    return "%.2f PB" % n

def size_str(n):
    return "%s (%s bytes)" % (human_size(n), format(int(n), ","))

def ts(v):
    try:
        return datetime.fromtimestamp(float(v)).strftime("%d %b %Y %H:%M:%S")
    except Exception:
        return str(v)

def iso_ts(s):
    try:
        return datetime.strptime(str(s).strip().rstrip("Z"), "%Y-%m-%dT%H:%M:%S").strftime("%d %b %Y %H:%M:%S")
    except Exception:
        return str(s)

def safe_filename(name):
    name = os.path.basename(str(name).replace("\\", "/"))
    name = re.sub(r"[^\w.\-()\[\] ]+", "_", name).strip("._ ") or "file"
    return name[:120]

def clamp(s, n=6000):
    s = str(s)
    return s if len(s) <= n else s[:n] + " ... [truncated]"

EXT_FOR = {"image": ".jpg", "png": ".png", "gif": ".gif", "bmp": ".bmp", "tiff": ".tiff",
           "webp": ".webp", "ico": ".ico", "heic": ".heic", "pdf": ".pdf", "ooxml": ".docx",
           "odf": ".odt", "epub": ".epub", "zip": ".zip", "jar": ".jar", "apk": ".apk",
           "tar": ".tar", "gz": ".gz", "sevenz": ".7z", "rar": ".rar", "ole": ".doc",
           "exe": ".exe", "elf": ".elf", "media": ".mp4", "sqlite": ".sqlite",
           "csv": ".csv", "json": ".json", "xml": ".xml", "txt": ".txt", "rtf": ".rtf",
           "html": ".html", "unknown": ".bin"}

def fmt_bytes_value(b, maxlen=400):
    if not isinstance(b, (bytes, bytearray)):
        return str(b)
    try:
        s = bytes(b).decode("utf-8")
        printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
        if printable / max(len(s), 1) > 0.85:
            s2 = s.replace("\x00", "").strip()
            if s2:
                return clamp(s2, maxlen)
    except Exception:
        pass
    return "<binary data, %d bytes> [%s...]" % (len(b), bytes(b[:12]).hex(" "))

def to_str(v, maxlen=400):
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray)):
        return fmt_bytes_value(v, maxlen)
    if isinstance(v, (tuple, list)):
        return ", ".join(to_str(x, maxlen) for x in v)
    if hasattr(v, "numerator") and hasattr(v, "denominator"):
        try:
            d = int(v.denominator)
            if d == 0:
                return "%s/0" % v.numerator
            if d == 1:
                return str(int(v.numerator))
            f = float(v)
            return str(int(f)) if f == int(f) else "%s (%s)" % (str(v), "%.6g" % f)
        except Exception:
            return str(v)
    return str(v)

def _i(v):
    try:
        return int(float(v))
    except Exception:
        return None

def fmt_exposure(v):
    try:
        t = float(v)
        if t <= 0:
            return to_str(v)
        return ("1/%d s" % round(1 / t)) if t < 1 else ("%.4f s" % t)
    except Exception:
        return to_str(v)

ORIENTATION = {1: "Normal (0\u00b0)", 3: "Rotated 180\u00b0", 6: "Rotated 90\u00b0 CW", 8: "Rotated 90\u00b0 CCW",
               2: "Mirrored horizontal", 4: "Mirrored vertical", 5: "Mirrored + 90\u00b0 CW", 7: "Mirrored + 90\u00b0 CCW"}
FLASH = {0: "Off", 1: "Fired", 5: "Fired, auto", 7: "Fired, auto, red-eye", 9: "On", 13: "On, red-eye",
         16: "Off (compulsory)", 24: "Off, auto", 32: "Not present"}
METERING = {0: "Unknown", 1: "Average", 2: "Center-weighted", 3: "Spot", 4: "Multi-spot", 5: "Pattern", 6: "Partial", 255: "Other"}
EXPPROG = {1: "Manual", 2: "Program AE", 3: "Aperture priority", 4: "Shutter priority", 7: "Portrait", 8: "Landscape", 9: "Bulb"}
CSM = {1: "sRGB", 2: "Adobe RGB", 0xFFFF: "Uncalibrated"}
COMPT = {1: "Uncompressed", 5: "LZW", 6: "JPEG (old)", 7: "JPEG", 8: "Adobe Deflate", 32773: "PackBits"}

def apex_f(v):
    try:
        return "f/%.1f" % (2 ** (float(v) / 2))
    except Exception:
        return to_str(v)

def apex_shutter(v):
    try:
        x = 2.0 ** (-float(v))
        return ("1/%d s" % round(x)) if x < 1 else ("%.1f s" % x)
    except Exception:
        return to_str(v)

def _fn(v):
    try:
        return "f/%.1f" % float(v)
    except Exception:
        return to_str(v)

def _mm(v):
    try:
        return "%.1f mm" % float(v)
    except Exception:
        return to_str(v)

EXIF_FMT = {
    "ExposureTime": fmt_exposure, "ShutterSpeedValue": apex_shutter, "ApertureValue": apex_f,
    "MaxApertureValue": apex_f, "FNumber": _fn, "FocalLength": _mm, "FocalLengthIn35mmFilm": _mm,
    "Flash": lambda v: FLASH.get(_i(v), to_str(v)),
    "MeteringMode": lambda v: METERING.get(_i(v), to_str(v)),
    "ExposureProgram": lambda v: EXPPROG.get(_i(v), to_str(v)),
    "ColorSpace": lambda v: CSM.get(_i(v), to_str(v)),
    "Compression": lambda v: COMPT.get(_i(v), to_str(v)),
    "Orientation": lambda v: ORIENTATION.get(_i(v), to_str(v)),
    "ISOSpeedRatings": lambda v: "ISO %s" % to_str(v),
    "WhiteBalance": lambda v: {0: "Auto", 1: "Manual"}.get(_i(v), to_str(v)),
}

IPTC_NAMES = {(2, 0): "Record Version", (2, 5): "Object Name", (2, 25): "Keywords", (2, 40): "Special Instructions",
              (2, 55): "Date Created", (2, 80): "By-line", (2, 85): "By-line Title", (2, 90): "City",
              (2, 95): "Province/State", (2, 101): "Country", (2, 105): "Headline", (2, 110): "Credit",
              (2, 115): "Source", (2, 116): "Copyright Notice", (2, 120): "Caption/Abstract", (2, 122): "Writer/Editor"}

def dms_to_deg(rat, ref):
    """DMS -> decimal degrees. Robust: tuple, IFDRational, bytes (LE/BE), string.
    All-zero / unreadable coordinates -> None (no fake 0.000000 is ever shown)."""
    def _f(x):
        try:
            return float(x)
        except Exception:
            try:
                return float(x.numerator) / float(x.denominator)
            except Exception:
                return None
    try:
        if rat is None:
            return None
        vals = []
        if isinstance(rat, (bytes, bytearray)):
            b = bytes(rat)
            for endian in ("<", ">"):
                cand, ok = [], True
                for off in range(0, min(len(b), 24) - 7, 8):
                    num, den = struct.unpack_from(endian + "II", b, off)
                    if den == 0:
                        ok = False
                        break
                    cand.append(num / float(den))
                if ok and cand and any(abs(c) > 1e-6 for c in cand):
                    vals = cand
                    break
        elif isinstance(rat, str):
            try:
                parts = [p for p in re.split(r"[,\s\u00b0'\"]+", rat.strip()) if p]
                vals = [float(p) for p in parts[:3]]
            except Exception:
                return None
        else:
            try:
                it = list(rat)
            except TypeError:
                it = [rat]
            for x in it[:3]:
                fv = _f(x)
                if fv is None:
                    return None
                vals.append(fv)
        if not vals:
            return None
        while len(vals) < 3:
            vals.append(0.0)
        deg = abs(vals[0]) + vals[1] / 60.0 + vals[2] / 3600.0
        if vals[0] < 0:
            deg = -deg
        if abs(deg) < 1e-6:
            return None  # all-zero coordinates = no real fix
        if str(ref or "").strip().upper() in ("S", "W"):
            deg = -deg
        return round(deg, 6)
    except Exception:
        return None

# ------------------------------------------------------------ AI tool markers
AI_TOOL_NAMES = [
    "stable diffusion", "stablediffusion", "stable-diffusion", "automatic1111",
    "comfyui", "invokeai", "midjourney", "dall-e", "dalle", "novelai",
    "nai diffusion", "adobe firefly", "firefly ai", "generative fill",
    "runwayml", "fooocus", "kohya_ss", "diffusers", "sdxl", "playground ai",
    "leonardo.ai", "bing image creator", "copilot designer", "ideogram",
    "flux.1", "gen-2", "pika labs",
]

# ------------------------------------------------------------ category model
GROUP_META = {
    "basic":    ("Basic File Information", "filesystem"),
    "ai":       ("AI File Detection", "embedded"),
    "image":    ("Image & Color Properties", "embedded"),
    "exif":     ("EXIF Metadata", "embedded"),
    "iptc":     ("IPTC Metadata", "embedded"),
    "xmp":      ("XMP Metadata", "embedded"),
    "gps":      ("GPS & Location", "embedded"),
    "pdf":      ("PDF Metadata", "embedded"),
    "office":   ("Office & Package Metadata", "embedded"),
    "ole":      ("Legacy Office (OLE) Metadata", "embedded"),
    "archive":  ("Archive & Package Metadata", "embedded"),
    "apk":      ("APK Package Metadata", "embedded"),
    "exe":      ("Executable (PE) Metadata", "embedded"),
    "elf":      ("ELF Binary Metadata", "embedded"),
    "media":    ("Media Tags", "embedded"),
    "stream":   ("Video & Stream Metadata (FFprobe)", "embedded"),
    "custom":   ("Embedded & Custom Tags", "embedded"),
    "structure":("Content Structure", "embedded"),
    "sqlite":   ("SQLite Database Schema", "embedded"),
    "exiftool": ("ExifTool Deep Scan", "embedded"),
}

def _source_for(gid):
    if gid == "exiftool":
        return "ExifTool"
    if gid == "stream":
        return "ffprobe"
    if gid == "sqlite":
        return "sqlite3 (read-only)"
    if gid == "ai":
        return "signature & metadata scan"
    if gid in ("archive", "office", "apk"):
        return "zipfile/tarfile"
    if gid == "exe":
        return "PE parser" + (" + pefile" if HAVE_PEFILE else "")
    return {"exif": "Pillow", "iptc": "Pillow IPTC", "xmp": "XML parser", "gps": "EXIF GPS IFD",
            "image": "Pillow", "pdf": "pypdf", "ole": "olefile", "media": "mutagen",
            "custom": "container parser", "structure": "text analysis", "elf": "ELF parser",
            "basic": "filesystem"}.get(gid, "built-in parser")

# ------------------------------------------------------------ explanation engine
DYN = {
 "make": "The camera metadata identifies the equipment manufacturer as {value}. This indicates the picture was taken or processed by a {value} device, though such tags are editable text and cannot by themselves prove which photographer or exact unit produced the file.",
 "model": "The metadata records the capturing device model as {value}, meaning this picture was most likely taken with a {value}. The tag is written by the device itself but remains editable, so treat it as a strong indication rather than absolute proof.",
 "software": "The file reports that {value} was the last software to write it. This reveals the most recent tool in the file's editing chain \u2014 the original capture device may have been different \u2014 because editing programs overwrite this value on every re-save.",
 "artist": "The creator name stored in this file is {value}. It represents the authorship recorded by whoever saved the file, which supports attribution claims but is plain editable text and does not independently verify the photographer's identity.",
 "copyright": "The file carries the copyright notice \u201c{value}\u201d. It communicates the owner's legal claim over this image, but notice text is written freely by whoever saved the file and does not verify actual ownership or licensing status.",
 "lensmake": "The lens manufacturer recorded at capture is {value}. Combined with the lens model it helps identify the optical equipment used for this picture, though the value is self-reported by the camera and is absent on many devices.",
 "lensmodel": "The lens model recorded for this picture is {value}. It identifies the optics used at capture time and supports equipment analysis, but it remains editable EXIF text rather than verified hardware data.",
 "cameraownername": "The camera owner recorded in the metadata is {value}, typically entered manually in the camera's settings menu. It suggests intended ownership but is freely editable and does not prove who actually took the picture.",
 "author": "The document properties record {value} as the author. This is usually copied automatically from the creating application's user profile, so it suggests who made the file but can be changed easily and is not proof of authorship.",
 "title": "The document's stored title is \u201c{value}\u201d. Authoring software uses it for display and indexing; it is editable text entered during authoring and does not have to match what the document actually contains.",
 "creator (application)": "The source document was originally created with {value}. This traces the software chain behind the file, although the field is written by that same software itself and can be set to any value.",
 "producer": "This exact file was produced by {value}, such as a converter, printer driver or library. Comparing it with the creator field often reveals whether the document was converted or re-saved after it was first created.",
 "last modified by": "The account that last saved this document was {value}. It can indicate whose machine handled the file most recently, but the value comes from the application's settings and is easily changed or left blank.",
 "company": "The organization recorded in this document is {value}, typically taken from the Office profile of the creating machine. It can reveal the creator's employer, though it is editable metadata rather than verified information.",
 "package name": "The app declares its unique package identifier as {value}. This is the identity Android and app stores use for the application, but developers set it to any value at build time, so it does not verify the real publisher.",
 "version name": "The app displays version {value} to users. This human-readable string is chosen freely by the developer at build time, so it indicates the intended release but does not guarantee what the build actually contains.",
 "version code": "The app's internal update ordering value is {value}. Android uses it to decide which build replaces which, and the numbering scheme is entirely the developer's choice.",
 "gps latitude": "The file stores the north\u2013south coordinate {value}. Paired with the longitude it can indicate an approximate capture location on a map, but GPS tags can be stripped or spoofed and are not proof the photo was actually taken there.",
 "gps longitude": "The file stores the east\u2013west coordinate {value}. Together with the latitude it points to an approximate capture area; such data depends on the device's positioning receiver and can be edited freely without detection.",
 "datetimeoriginal": "The camera recorded the capture time as {value}. This is the primary timestamp for building a chronology, taken from the device clock \u2014 which may simply be wrong or deliberately altered \u2014 so verify before relying on it.",
 "datetime": "The file-change time inside EXIF is {value}, set from the device clock when the image was last written. It is useful for timelines but reflects whatever the clock said and can be modified without detection.",
 "datetimedigitized": "The image was digitized at {value} according to the device clock. For cameras this is usually the capture moment itself, but like all EXIF timestamps it is editable metadata rather than verified fact.",
 "embedded thumbnail": "A {value} preview image is embedded by the camera or editing software. Thumbnails sometimes preserve an earlier editing state that differs from the current picture, which can be forensically interesting.",
 "usercomment": "The EXIF comment stored in this file reads \u201c{value}\u201d. Its content is entirely whatever the camera or editor wrote, so it may contain useful notes, tool names or nothing meaningful at all.",
 "imagedescription": "The description stored with this image reads \u201c{value}\u201d. It is plain editable text commonly used for captions, so read it as a claim made by the author rather than an objective fact about the scene.",
 "container major brand": "The MP4/MOV container was created with the brand \u201c{value}\u201d, which indicates the intended specification family of the file. It is read from the header structure and is reliable technical information.",
}

EXPL = {
 "file name": "The name the file carries on your disk, including its extension. It helps identify and organize files, but names can be renamed freely at any time, so the name alone never proves what the file actually contains or where it originally came from.",
 "file type": "The real format detected by reading the file's internal signature bytes, not by trusting its filename. This exposes disguised or mislabeled files, because the internal structure always reveals what the file genuinely is regardless of what it was renamed to.",
 "mime type": "The standard media type for the detected format, used by operating systems and browsers to decide which application should open the file. It is derived from the file's internal signature rather than its name, so it reflects the true format.",
 "file size": "The total space the file occupies, shown in readable units and exact bytes. Larger files usually hold more or higher-fidelity data, but size changes every time a file is re-saved, converted or re-encoded, so it is not a quality measure.",
 "created date": "The creation timestamp recorded by your filesystem when the file landed on this storage device. It depends on the device clock and is updated by copy, download and restore operations, so it indicates local history rather than the file's true origin.",
 "modified date": "When the file's contents were last written on this system. A modified time later than the created time shows the file was edited or re-saved after arriving; sync tools and copy operations can also refresh this value without changing the content.",
 "accessed date": "The most recent time this file was read or opened on this computer. It reflects activity on the current machine only, not the file's origin, and many modern systems update it infrequently to reduce disk writes, so treat it as approximate.",
 "file extension": "The suffix after the final dot in the filename. Extensions are only labels that help the operating system pick a default program; the genuine format is determined from the internal signature, which is what the File Type row reports.",
 "file signature (magic bytes)": "The first bytes of the file shown in hexadecimal. Every format begins with a characteristic signature, so comparing these bytes against the extension instantly exposes files that were renamed to disguise their true type.",
 "file path": "The complete location of the file on this computer, including drive and folders. It shows exactly where the file was read from and can reveal local folder names, but it says nothing about the file's original source or history.",
 "file attributes": "Windows filesystem flags such as read-only, hidden, system or archive. These describe how the operating system stores and treats the file, not what is inside it, and they are managed by the OS rather than by the file's contents.",
 "image width": "The horizontal pixel count of the image. Together with the height it defines the resolution and aspect ratio. More pixels can preserve more visual detail, although they do not by themselves guarantee a sharp or high-quality result.",
 "image height": "The vertical pixel count of the image. Combined with the width it determines the overall resolution and shape of the picture; additional pixels add potential detail but do not ensure actual image sharpness or fidelity.",
 "megapixels": "The total number of pixels expressed in millions, calculated directly from width times height. It is a convenient way to compare potential detail between images, but real quality still depends on the sensor, lens and compression.",
 "aspect ratio": "Width divided by height, reduced to the simplest whole-number ratio. It describes the proportional shape of the image independently of its resolution, which matters for cropping, printing and display without distortion.",
 "color mode": "How pixel values are stored, such as RGB, grayscale or palette-indexed. It determines how many colors the file can represent and how decoders interpret the data, so it affects both fidelity and compatibility.",
 "resolution (dpi)": "The dots-per-inch value stored in the file, used mainly as a printing hint to compute physical size. It never changes the pixel data or on-screen sharpness; the same pixels can carry any DPI value.",
 "icc profile": "An embedded ICC color profile describing exactly how the file's colors should be converted for display. Profiles improve color accuracy across devices, but they are technical data and carry no information about the file's origin.",
 "transparency": "The file defines transparent pixels, allowing the image to blend over different backgrounds. This is a visual property of the pixel data and provides no clues about when or by whom the file was produced.",
 "frames": "The number of frames stored in this animation. More frames generally mean a longer or smoother animation and a larger file; the count is read from the container structure, not from editable text fields.",
 "loop behavior": "How the animation repeats during playback, such as looping forever or a fixed number of cycles. This is a playback setting written by the creating application and can be changed freely without affecting the frames.",
 "palette colors": "The number of colors defined in the palette table of an indexed-color image. Pixel values are indices into this table, which limits the maximum color count but can significantly reduce the file size.",
 "bit depth": "The number of bits stored per channel or pixel. Higher bit depth allows more distinct colors and smoother gradients, though the visible benefit depends on the image content and the display hardware.",
 "png color type": "The PNG-specific pixel layout recorded in the IHDR chunk, such as RGB, grayscale, palette or alpha variants. It tells decoders exactly how to interpret the raw pixel stream that follows.",
 "interlacing": "Whether the image uses Adam7 interlacing, which lets a rough version appear early while the file loads progressively. It changes storage order only, never the final decoded image or its quality.",
 "icc profile (iccp)": "A compressed ICC color profile embedded in the PNG container. It enables accurate color reproduction across different displays but is purely technical color data, unrelated to the file's provenance.",
 "apng animation (actl)": "The Animated PNG control chunk, which records how many animation frames the file contains. Its presence means this PNG is actually an APNG animation rather than a single still image.",
 "exposuretime": "The shutter duration used for this shot, such as 1/250 second. Faster settings freeze motion while longer ones admit more light; it records camera settings only and cannot verify authenticity.",
 "fnumber": "The lens aperture (f-stop) used at capture. Lower numbers mean a wider opening, shallower depth of field and more light. It describes photographic settings, not the file's history or origin.",
 "isospeedratings": "The sensor's light-sensitivity setting for this exposure. Higher ISO brightens dark scenes but adds noise. Like other capture settings it describes conditions, not whether the image is genuine.",
 "focallength": "The actual lens focal length in millimetres at capture. It defines the field of view and, with sensor data, can suggest the shot type; it cannot establish when or where the photo was taken.",
 "focallengthin35mmfilm": "The focal length expressed as the equivalent for a full-frame 35 mm camera. It is a calculated convenience value for comparing field of view across devices, not a separate measurement.",
 "flash": "Whether the flash fired and related flash details as reported by the camera. It reflects the camera's state at capture; mismatches with the visible image can hint at re-processing but are not proof.",
 "meteringmode": "The light-metering strategy the camera used, such as spot or center-weighted. It explains how exposure was computed and, like every EXIF field, can be edited or stripped without detection.",
 "exposureprogram": "The exposure mode the camera operated in, such as manual, program or aperture priority. It indicates how settings were chosen at capture and has no bearing on file authenticity.",
 "whitebalance": "The white-balance setting, automatic or a manual preset like daylight or tungsten. It influenced color rendering at capture, but later editing can change colors regardless of this recorded value.",
 "colorspace": "The color space flag recorded in EXIF, typically sRGB or uncalibrated. Viewers use it to interpret colors correctly; it is technical rendering information with no provenance meaning.",
 "orientation": "How the image should be rotated for correct display, recorded at capture. A mismatch with the visible content can indicate post-capture cropping or re-saving by editing software.",
 "makernote": "A proprietary vendor block of camera settings written by the manufacturer's firmware. Its format is private, so it is reported as present but not decoded; decoding requires vendor-specific documentation.",
 "xresolution": "The horizontal resolution value stored in EXIF, meaningful only together with its resolution unit. It is a printing hint and does not alter the actual pixel data or display quality.",
 "yresolution": "The vertical resolution value stored in EXIF, used with its unit as a print-sizing hint. It has no effect on-screen and can differ arbitrarily between files with identical pixels.",
 "resolutionunit": "The unit used for the EXIF resolution values, typically inches or centimetres. It simply tells software how to interpret the X and Y resolution numbers stored alongside it.",
 "exifversion": "The version of the EXIF specification the camera firmware supported when writing metadata. It indicates which standard features the device could record and nothing about the image content.",
 "brightnessvalue": "The brightness value estimated by the camera at capture, stored as an EXIF convenience figure. Treat it as an approximate indicator of scene luminance rather than a measured constant.",
 "shutterspeedvalue": "The shutter speed stored in APEX notation, an alternative encoding of exposure time. It records the same capture setting in a different mathematical form used by some cameras.",
 "aperturevalue": "The aperture stored in APEX notation, an alternative encoding of the f-number. It is the camera's own record of the opening used and carries no verification value.",
 "maxaperturevalue": "The widest aperture available on the lens, recorded as equipment metadata. It describes what the lens could do, not necessarily the setting chosen for this particular shot.",
 "subjectdistance": "The approximate distance from the camera to the subject, as estimated by the focusing system. Autofocus estimates can be inaccurate, so treat this as an indicative measurement only.",
 "digitalzoomratio": "The amount of digital zoom applied, if any. Digital zoom crops and enlarges pixels rather than using optics, which can reduce detail; the value is self-reported by the device.",
 "scenecapturetype": "The scene mode the camera applied, such as standard, landscape or night. It is a capture-mode label guiding in-camera processing and carries no verification significance.",
 "contrast": "The in-camera contrast processing preset applied at capture, such as normal, soft or hard. It describes the device's rendering choice, which later editing can override entirely.",
 "saturation": "The in-camera color-saturation preset applied at capture. It records how vividly the camera rendered colors; subsequent editing software can change the final appearance completely.",
 "sharpness": "The in-camera sharpening preset applied to the image. It reflects the device's rendering setting, not an objective measurement of how sharp the final picture actually is.",
 "subjectdistancerange": "The approximate subject-distance class the camera reported, such as macro or distant view. It is a coarse self-reported category rather than a precise measurement.",
 "sensingmethod": "The type of image sensor the camera declared, such as one-chip color area. It is fixed hardware information written by the firmware and rarely varies within a device model.",
 "customrendered": "Whether special in-camera processing was applied, as flagged by the device. It is a processing hint for decoders and has no bearing on the file's origin or integrity.",
 "gaincontrol": "The sensor gain adjustment the camera reported, such as low gain up. It relates to low-light amplification and is recorded as technical capture context only.",
 "exposuremode": "Whether exposure was set automatically, manually or with auto-bracketing. It explains how the camera chose settings at capture and proves nothing about the file's history.",
 "filesource": "The source type the camera declared, typically indicating a digital still camera. It is a fixed firmware-written flag and is identical across millions of files from the same device family.",
 "scenetype": "A flag indicating the image was from a direct still-camera capture, as declared by the firmware. It is self-reported and identical on countless files, so it verifies nothing.",
 "compression": "The compression scheme recorded for the image data, such as JPEG or uncompressed. It tells decoders how pixels were stored and is standard technical container information.",
 "ycbcrpositioning": "How chroma samples are positioned relative to luma in YCbCr data. It is a decoding detail that affects color interpolation and has no user-facing or forensic meaning.",
 "focalplanexresolution": "The horizontal resolution of the camera's sensor plane, recorded for calculating film-equivalent focal length. It is fixed hardware data written once by the firmware.",
 "focalplaneyresolution": "The vertical resolution of the sensor plane recorded in EXIF. Together with its unit it supports focal-length calculations and is otherwise purely technical.",
 "focalplaneresolutionunit": "The measurement unit for the sensor-plane resolution values, usually centimetres or inches. It contextualizes the two focal-plane resolution numbers.",
 "record version": "The version of the IPTC IIM specification this metadata block follows. It is structural bookkeeping written by the tagging software and has no descriptive meaning.",
 "object name": "A short title assigned to the image in editorial or stock workflows. It helps organize assets but is typed freely by people or tools and does not verify the image's subject.",
 "keywords": "Keywords assigned for search and categorization in editorial workflows. They reflect how someone tagged the file and are useful for organization, but they are not validated facts about the content.",
 "special instructions": "Usage or handling notes stored for editorial teams, such as embargo or credit requirements. They carry workflow guidance rather than technical facts and can be edited by anyone.",
 "date created": "The content-creation date entered in the IPTC record. It may come from the camera or be typed manually, so it should be cross-checked against EXIF timestamps before being trusted.",
 "by-line": "The photographer or creator name entered in editorial metadata. It records an attribution claim that must be verified independently, since anyone handling the file can change it.",
 "by-line title": "The job title associated with the by-line in editorial workflows. It adds claimed context about the creator's role but is unverified, editable text.",
 "city": "The city field describing where the image was reportedly made. It is typed manually during editorial processing and should not be treated as evidence of the actual location.",
 "province/state": "The province or state recorded for the image's reported origin. Like other IPTC location fields it is entered by hand and represents a claim, not a verified fact.",
 "country": "The country recorded for the image's reported origin. It is typed during editorial workflows and is not independent evidence of where the file was actually captured.",
 "headline": "A headline summarizing the intended story of the image for editorial use. It is free text that may or may not objectively describe what is visible in the frame.",
 "credit": "The credit line for the image provider or agency. It indicates the intended distributor rather than the file's true origin, and it can be changed freely.",
 "source": "The source of the image as recorded by the provider. It reflects the supply chain's labelling and does not by itself establish the original creator or capture location.",
 "copyright notice": "The copyright claim stored in the IPTC record. Like all such text it communicates a claim rather than proof, and actual rights status must be confirmed through proper channels.",
 "caption/abstract": "The caption describing the image, entered by an editor or photographer. Captions provide claimed context but are editable text and can be wrong or intentionally misleading.",
 "writer/editor": "The person who wrote or edited the caption text. It identifies who handled the editorial metadata, not who captured the image, and is freely editable.",
 "pdf version": "The PDF specification version declared in the file header. Newer versions support additional features such as improved compression, while older readers may reject files targeting newer versions.",
 "encrypted": "Whether the file carries an encryption flag restricting opening or editing. This is a security property of the document itself, not evidence that anything was hidden or tampered with.",
 "page count": "The number of pages counted directly from the document's internal page tree. Unlike free-text properties, this is measured from the actual structure and is reliable.",
 "subject": "A subject line entered in the document properties during authoring. It is descriptive free text intended for organization and is never validated against the actual content.",
 "form fields": "The number of interactive form fields detected in the document. Forms make documents fillable and can also carry user-entered data worth reviewing before the file is shared.",
 "embedded files": "Files attached inside the document container. Embedded attachments can carry additional documents or unexpected payloads, so their presence is worth reviewing carefully.",
 "revision": "The number of save sessions the document reports. Higher counts indicate more editing rounds, though the counter resets when a file is recreated or edited in different software.",
 "last printed": "The date the document reports it was last printed, recorded by the editing application. It may be absent or outdated if printing happened on another machine or was never recorded.",
 "content status": "The document's declared completion status, such as Draft or Final. It is a label entered by the author during document setup and carries no verification weight.",
 "language": "The language declared for the document content, used by spell-checkers and accessibility tools. It is a configuration setting rather than an analysis of the actual text.",
 "application": "The application that saved this document file, as recorded in its extended properties. It helps identify the software used, though many tools can produce the same format.",
 "total editing time": "The cumulative editing time in minutes maintained by the application across save sessions. It is an approximate counter and resets or drifts depending on how the file was handled.",
 "sheet names": "The worksheet names read from the workbook manifest, including any marked hidden. Hidden sheets can contain data the author did not intend to share, so review them carefully.",
 "hidden sheets": "How many worksheets the author marked as hidden. Hidden sheets frequently contain calculations, notes or data removed from view but still stored inside the file.",
 "worksheets": "The number of worksheet parts counted in the workbook package structure. This is measured directly from the file layout and is reliable.",
 "slides": "The number of slide parts counted in the presentation package. Like page counts it is measured from the actual structure rather than taken from editable metadata.",
 "files in book": "The number of internal files stored inside this EPUB container. E-books are ZIP packages, so this reflects the package layout rather than editable metadata.",
 "opf package file": "The OPF manifest file inside the EPUB that defines its structure and metadata. It is the authoritative package description written when the book was built.",
 "identifier": "A unique identifier for the publication, commonly an ISBN or UUID, as declared in the package metadata. It identifies the publication edition but is self-declared by the publisher.",
 "integrity check": "The archive's central directory was read successfully, confirming that the container structure is valid and every entry below was enumerated directly from it without extracting anything.",
 "total entries": "The number of items stored inside the archive, counted from its directory. Nothing was extracted or executed to produce this count; it comes purely from the container metadata.",
 "directory entries": "How many of the stored entries are folder placeholders rather than files. Folders are stored as entries themselves in archive formats and count toward the total.",
 "uncompressed size": "The total size the contents would occupy once extracted. Comparing it with the archive's actual size shows how much space compression saved on this particular content.",
 "compressed size (archive)": "The size the archive occupies on disk with its contents in stored form. It reflects the combined effect of the compression methods used across all entries.",
 "compression ratio": "How much smaller the stored archive is than its uncompressed contents. Text compresses dramatically, while already-compressed media such as photos barely shrinks at all.",
 "compression methods": "The compression algorithms used inside the archive. 'Store' means entries were saved without compression, while Deflate and Bzip2 are actual compression schemes.",
 "encrypted entries": "Entries flagged as password-protected inside the archive. Their contents cannot be inspected without the password, which is why they are reported rather than read.",
 "archive comment": "A comment stored in the archive by whoever created it. It is free text that can contain notes, tool names or anything else the creator chose to write.",
 "largest entry": "The single largest entry inside the archive. Large entries matter when planning extraction and are relevant to decompression-bomb awareness before opening unknown archives.",
 "full entry listing (safe, nothing extracted)": "A safe listing of every entry with its size, timestamp, compression method, CRC checksum and name. Nothing is extracted or executed; extremely long listings are truncated for display.",
 "compression layer": "The outer compression container detected from the file signature. Gzip, Bzip2 and XZ wrap the actual archive, so the tool reports the layer separately from the contents.",
 "gps coordinates": "The file carries GPS coordinate tags, but the stored values are zero or unreadable \u2014 the device had no usable satellite fix when this file was created. This commonly happens when location was enabled but no lock was acquired.",
 "androidmanifest.xml": "The mandatory manifest every valid APK must contain. It declares the app's identity, components and permissions; its absence means the file is not a genuine APK.",
 "dex files": "The Dalvik bytecode files holding the app's executable code. They are listed statically for identification only and are never executed, decompiled or run in any way.",
 "native abis": "The CPU architectures for which native libraries are bundled, such as arm64-v8a. They show which device processors the app's native code can run on.",
 "signing files": "Signature-related files found in the package. Their presence shows a signing step occurred, but verifying a signature's validity requires proper cryptographic tools.",
 "minimum sdk (api)": "The oldest Android API level the app supports. It shows how old a device can be and still install the application.",
 "target sdk (api)": "The Android API level the app was built and tested against. It affects which system behaviours and restrictions apply to the app at runtime.",
 "activities declared": "The number of activity components declared in the manifest. Activities represent user-facing screens, so the count hints at the app's interface complexity.",
 "services declared": "The number of service components declared. Services run background work without a user interface, so a high count can indicate significant background behaviour.",
 "receivers declared": "The number of broadcast receivers declared. Receivers respond to system events such as boot or connectivity changes, which is relevant to understanding app behaviour.",
 "providers declared": "The number of content providers declared. Providers share data between apps, so their presence is relevant when assessing what the app exposes.",
 "uses features": "The hardware or software features the app declares it uses, such as camera or GPS. Declared features indicate intent but do not prove how the app behaves.",
 "requested permissions": "The permissions the app asks Android to grant. They indicate what the app intends to access on a device; actual behaviour requires full code analysis.",
 "machine type": "The processor architecture the executable targets, read from its COFF header. It shows which CPUs can run the file natively and is reliable structural information.",
 "compile date (pe header)": "The build timestamp recorded in the PE header. It suggests when the file was compiled, but compilers can write arbitrary or zeroed timestamps to obscure builds, so treat it as a hint.",
 "coff characteristics": "Flags from the COFF header such as executable, DLL or 32-bit. They describe the binary's fundamental type and are read directly from the file structure.",
 "pe format": "Whether the binary uses the 32-bit PE32 or 64-bit PE32+ format. It determines how the operating system loads and maps the file into memory.",
 "linker version": "The version of the linker that produced the executable. It can indicate the build toolchain era but says nothing about the file's purpose or safety.",
 "entry point": "The memory address where execution begins, read from the optional header. It is a technical loader field that analysts use; it has no user-facing meaning.",
 "subsystem": "The execution environment the binary requires, such as GUI or console. It determines how Windows hosts the program when it is started.",
 "security flags": "Binary mitigations such as ASLR and DEP declared at build time. They describe exploit-hardening features the developer compiled in, not the file's trustworthiness.",
 "digital signature": "Whether an Authenticode signature table exists in the file. Presence alone does not prove validity \u2014 confirming a signature requires proper cryptographic verification tools.",
 "data directories (present)": "Which optional data directories exist in the binary, such as imports, resources or certificates. Their presence indicates what structures analysts and loaders will find inside.",
 "sections": "The executable's internal sections with their virtual and raw sizes. Names like .text and .data are standard; unusual names can indicate packing or custom tooling.",
 "overlay data": "Extra bytes appended after the last section. Overlays commonly carry installers or embedded payloads, so their presence is notable although normal for many programs.",
 "imported libraries": "The system libraries the binary imports functions from, with function counts. Import volume and choice of libraries hint at how heavily the program uses operating-system APIs.",
 "section entropy": "A randomness score per section. High entropy often indicates compression or packing, which is worth noting but is also normal for legitimate protected software.",
 "class": "Whether the ELF binary is 32-bit or 64-bit, read from its identification bytes. It determines the memory model the file was built for.",
 "byte order": "Whether the ELF file stores multi-byte values little-endian or big-endian. It must match the target CPU's byte order for the file to be loadable.",
 "type": "The ELF file's role, such as executable, shared library, relocatable object or core dump. It is read from the header and describes how the file is meant to be used.",
 "machine": "The CPU architecture the ELF file targets, such as x86-64 or ARM. It shows which platforms can load and run the binary natively.",
 "os/abi": "The operating system and ABI the ELF binary declares, such as Linux or System V. It guides loaders in applying the correct system conventions.",
 "program headers": "How many loadable segments the ELF file defines. Segments describe runtime memory layout and are counted directly from the header.",
 "section headers": "How many sections the ELF file defines for linking and analysis. A high count often indicates a fully linked binary with debug information.",
 "ole streams": "The internal storage streams of the legacy OLE compound file. Their names and count reveal the document family and structure without opening any content.",
 "last saved by": "The account name recorded when the document was last saved, from the editing machine's Office profile. It can reveal whose account handled the file but is easily changed.",
 "created (internal)": "The creation timestamp stored inside the document by the authoring application's clock. It supports timelines but is editable metadata, unlike filesystem dates.",
 "modified (internal)": "The last-saved timestamp stored inside the document itself. A difference from the internal creation date shows the file was edited after it was first produced.",
 "duration": "The playing time calculated from the media's stream parameters. It is measured from the file structure rather than taken from editable tags, so it is reliable.",
 "bitrate": "The average data rate of the media stream. Higher bitrates usually preserve more quality in lossy formats, though the encoder and source material matter just as much.",
 "sample rate": "The audio sampling frequency in hertz. Higher rates can capture higher frequencies, though the audible benefit depends on the content and playback equipment.",
 "channels": "The number of audio channels stored, such as mono or stereo. It describes the audio layout contained in the file without indicating quality by itself.",
 "bits per sample": "How many bits store each audio sample. More bits capture finer volume detail, which matters most for uncompressed or high-resolution audio.",
 "codec": "The codec used to encode the media stream. It tells you which decoders a player needs and is measured from the container's stream descriptions.",
 "encoder": "The software or library that encoded the file, when the encoder recorded itself. It helps trace the production chain but is a self-reported value.",
 "channel mode": "How stereo information was stored by the encoder, such as joint stereo or mono. It is a technical encoding detail from the audio frame headers.",
 "container format": "The container formats ffprobe identified for this file, such as mov or matroska. This is measured directly from the file structure by FFmpeg.",
 "duration (s)": "The total playing time in seconds as computed by ffprobe from the container and stream headers. It is reliable structural information.",
 "container size (s)": "The file size in bytes as reported by ffprobe. It matches the on-disk size and is included for completeness with the stream report.",
 "bitrate (container)": "The overall average bitrate of the entire file as computed by ffprobe. It combines all streams and reflects the encoder's data budget.",
 "jfif version": "The JFIF header version, the basic interchange format almost all JPEG files use. It is standard structural data written by the encoding software.",
 "photoshop resources (app13)": "An Adobe Photoshop resource block embedded in the JPEG. It often carries layers, paths or IPTC data written by Photoshop during editing.",
 "adobe segment (app14)": "An Adobe-specific marker that records color-transform settings for the JPEG. It is technical encoder information with no descriptive content.",
 "jpeg comment": "A free-text comment stored inside the JPEG container. Its content is entirely whatever the creating or editing software chose to write there.",
 "icc profile segments": "How many ICC color-profile segments the file carries. Profiles may be split across multiple segments; together they define accurate color conversion.",
 "jpeg encoding process": "Whether the JPEG uses baseline or progressive encoding. Progressive images load in increasingly detailed passes; the choice affects loading behaviour, not content.",
 "jpeg segment map": "The ordered list of every marker segment inside the JPEG. It gives a complete structural overview of what metadata blocks the file actually contains.",
 "last modification (time)": "The modification timestamp stored in the PNG tIME chunk by the saving software. It is internal to the file and independent of filesystem dates.",
 "gamma (gama)": "The display gamma assumption stored in the PNG. Modern viewers mostly ignore it in favour of ICC profiles, so it rarely affects rendering today.",
 "srgb intent": "The rendering intent declared for an sRGB image, such as perceptual or saturation. It guides color conversion at display time and is standard technical data.",
 "exif chunk (exif)": "An EXIF block stored inside this container format. The tool parsed it and its tags appear in the EXIF category below.",
 "png chunk map (all chunks, in order)": "Every chunk in the PNG in storage order. This is a complete structural inventory; nothing inside the file was skipped or hidden from this view.",
 "gif version": "Which GIF specification version the file follows, 87a or 89a. The newer version supports comments and transparency extensions.",
 "logical screen": "The logical screen dimensions stored in the GIF header, which define the canvas the frames are composed onto.",
 "global color table": "Whether a shared color palette is defined for all frames, and how many colors it holds. Palette-based GIFs index colors from this table.",
 "gif comment": "A text comment embedded in the GIF by the creating software. It is free text and may contain tool names, notes or nothing useful.",
 "dimensions (header)": "The image dimensions as recorded directly in the file header, useful for cross-checking against the decoder's reported size for consistency.",
 "pixel density": "The physical pixel density stored in the header, converted to approximate DPI. It is a display and print hint that never changes the actual pixels.",
 "dib header": "The size and variant of the BMP's DIB header, which reveals which Windows era and feature set the file was written for.",
 "webp chunk map": "Every chunk inside the WebP RIFF container with sizes. It provides a complete structural inventory of what the file contains.",
 "ico container": "A multi-size icon container decoded by Pillow; the dimensions shown correspond to the largest frame stored inside the file.",
 "encoding": "The character encoding detected or assumed for this text file. It determines how bytes map to characters; wrong assumptions produce garbled text, so detection here is best-effort.",
 "byte-order mark": "A byte-order mark is present at the file start. BOMs identify UTF-8 or UTF-16 encoding explicitly but can confuse some older parsers.",
 "line count": "The number of lines counted directly from the decoded text. It is measured from the content itself and is exact for the portion scanned.",
 "word count (approx.)": "An approximate word count obtained by splitting the text on whitespace. It is a quick size estimate rather than a linguistic analysis.",
 "character count": "The number of characters after decoding. It differs from the raw byte size for multi-byte encodings such as UTF-8.",
 "root type": "Whether the JSON document's top level is an object, array or another type. It defines the overall shape of the data structure.",
 "top-level keys": "The field names at the JSON root, showing what categories of data the file organizes. Long lists are truncated for readability.",
 "total elements": "How many values the JSON structure contains in total, counted by walking the tree with depth and size guards against pathological files.",
 "max depth": "The deepest nesting level in the JSON structure. Deeply nested data is typically machine-generated and harder for tools to process.",
 "root element": "The name of the XML document's root element, which defines the document's primary type and namespace context.",
 "element count": "How many XML elements the document contains, counted by parsing the tree safely. It indicates the document's structural size.",
 "attribute count": "How many attributes exist across all XML elements. Attributes carry per-element data and add to the document's information density.",
 "delimiter": "The field separator detected in the CSV, shown in quotes. Correct delimiter detection is essential for parsing columns accurately.",
 "column names (header row)": "The column names from the CSV's first row. They show what data categories the file organizes without exposing row contents.",
 "column count": "How many columns the CSV header defines. Combined with the row count it describes the table's shape.",
 "data row count": "How many data rows follow the header. Counted from the parsed structure, it describes the dataset's size.",
 "markdown headings": "How many headings the Markdown document defines, counted from hash-prefixed lines. It indicates the document's organization.",
 "outline (first 10)": "The first ten headings, giving a quick outline of the document's structure without exposing its full text.",
 "markdown links": "How many hyperlinks the Markdown document contains, counted from link syntax patterns.",
}

EXPL_G = {
 ("media", "title"): "The track title stored in the file's tags. It helps organize media libraries but is typed by whoever tagged the file and can be edited freely.",
 ("media", "artist"): "The performing artist stored in the audio tags. It records attribution as entered by the tagger and is not verified against the recording itself.",
 ("media", "album"): "The album name stored in the audio tags, used to group tracks in library displays. Like all tags it is editable text.",
 ("media", "date"): "The year or date stored in the audio tags. It reflects what the tagger entered and may refer to release rather than the actual recording date.",
 ("media", "genre"): "The genre label stored in the audio tags. Genre names are free text from a conventional list and can be anything the tagger chose.",
 ("media", "track number"): "The track number stored in the tags, ordering the track within an album. Entered by the tagging software or person.",
 ("media", "composer"): "The composer stored in the audio tags. It records an authorship claim as entered and is not independently verified.",
 ("media", "publisher"): "The publisher or label stored in the tags. It reflects the tagger's entry and is not a verified rights record.",
 ("media", "comment"): "A free-text comment stored in the audio tags. Its content is entirely up to whoever wrote the tag.",
 ("media", "lyrics"): "Lyrics text embedded in the audio tags, typed or imported by tagging software. It may not match the actual performance.",
 ("media", "encoded by"): "The encoder application recorded in the tags. It shows which tool wrote the file, though the value is self-reported.",
 ("media", "copyright"): "A copyright notice stored in the audio tags. It communicates a claim; actual legal status must be verified through proper channels.",
 ("media", "attached picture"): "An embedded cover-art image stored inside the audio file, reported with its format and size. The artwork itself is not displayed or extracted.",
 ("sqlite", "text encoding"): "The text encoding the database stores strings in, read from the database header. It must be respected when reading any stored text.",
 ("sqlite", "sqlite library version"): "The version of the SQLite engine used to read this database's schema on this machine. It describes the reader, not the file.",
 ("sqlite", "page size"): "The fixed-size page unit the database uses to store data internally. It is a low-level storage parameter set when the database was created.",
 ("sqlite", "tables"): "All user table names found in the database schema, read in read-only mode. Only structure is reported \u2014 the contents of these tables are never accessed.",
 ("sqlite", "indexes"): "Index names defined in the database schema. Indexes speed up queries and are purely structural metadata.",
 ("structure", "title tag"): "The page title from the HTML title element. It is the primary human-readable label browsers display for the page.",
 ("structure", "content classification"): "The file was classified as source, config or log text using its filename convention after its content was verified to be plain text. Classification is by extension, not deep parsing.",
 ("structure", "generator"): "The software that wrote this file, as declared in its own generator field. Self-reported values identify the toolchain but can be set to anything.",
}

GROUP_FALLBACK = {
 "basic": "A filesystem property reported by the operating system for this file. It describes storage state such as naming, timing or flags rather than embedded content, and values can change when files are copied or restored.",
 "image": "An image property reported by the decoder while opening the file. It describes how the pixels are stored and displayed, which is measured from the file structure rather than claimed in editable text.",
 "exif": "The '{label}' tag was written into the file by the camera or editing software. It records a technical or descriptive detail from the capture or editing process, but such tags are plain metadata that can be modified or removed without detection.",
 "iptc": "The '{label}' field was entered in an editorial or tagging workflow. It represents a claim written by people or tools rather than a verified fact, and anyone handling the file can change it.",
 "xmp": "This XMP property was written by the application that created or edited the file. XMP is standard editable metadata, so it documents what the software recorded but is not protected against modification.",
 "gps": "A geographic coordinate recorded by the device's positioning system. It is a claim about where the file was made \u2014 useful context, but such data can be stripped or spoofed.",
 "pdf": "A PDF document property stored by the authoring software. It supports identification and timelines but is editable text or a self-reported counter, not a verified fact.",
 "office": "A self-reported document property written by the authoring application. It aids identification but is editable, so treat it as an indication rather than proof.",
 "ole": "A property or stream from the legacy OLE compound container, read without executing anything. It reflects what the creating application recorded at save time.",
 "archive": "A property read from the archive's directory without extracting any content. It describes the container's structure and stored entries only.",
 "apk": "A value declared statically in the Android package. It is developer-declared and read without ever executing the APK or any of its code.",
 "exe": "A static value read from the binary's headers or resources. It aids identification and analysis but does not prove what the program actually does when run.",
 "elf": "A field from the ELF binary headers, read statically without execution. It describes the target platform and file layout rather than the program's behaviour.",
 "media": "A tag or technical field stored in the media container. Tags are typed by whoever tagged the file; technical values are measured from the stream parameters.",
 "stream": "Reported by FFprobe directly from the container and codec headers. It describes how the media is encoded, not who created it or when.",
 "custom": "A value read directly from the file's container by the parser and preserved verbatim. It reflects what the creating software wrote and is shown exactly as found.",
 "structure": "A structural property measured directly from the decoded text or data content. It is computed from the file itself rather than claimed in editable metadata.",
 "sqlite": "Schema metadata read from the database in read-only mode. Only structure is reported \u2014 table contents are never exposed by this tool.",
 "exiftool": "The '{label}' tag was reported by ExifTool, which reads vendor-specific blocks built-in parsers cannot. It reflects exactly what is stored in the file; interpret unfamiliar tags with caution.",
 "unknown": "The parser could not identify this format deeply, so only filesystem-level information is available. Nothing about the internal content is claimed or invented here.",
}

def note_for(label, gid, value=""):
    L = str(label).lower()
    if gid == "ai":
        if "yes" in str(value).lower():
            return ("Markers produced by AI image generators (tool name, C2PA provenance manifest, or generation "
                    "parameters) were found inside this file, so it is plausibly AI-generated. This is a strong "
                    "indication, not proof \u2014 metadata can be added or removed by any software, so combine this "
                    "result with visual inspection before drawing a conclusion.")
        return ("No markers associated with AI image generators were found in this file. Keep in mind that many "
                "AI-generated images carry no markers at all, and ordinary screenshots have no camera data either, "
                "so 'No' cannot be treated as proof that this is a genuine photograph.")
    tpl = DYN.get(L)
    if tpl:
        try:
            return tpl.format(value=value)
        except Exception:
            return tpl.replace("{value}", value)
    v = EXPL_G.get((gid, L))
    if v:
        return v
    v = EXPL.get(L)
    if v:
        return v
    if L.startswith("tag 0x") or L.startswith("exif tag 0x") or L.startswith("gps tag 0x"):
        return ("An unrecognized tag number whose meaning is not in the standard tag tables. "
                "The parser preserved the raw value so nothing is lost, but interpret it with caution.")
    if L.startswith("iptc record"):
        return ("A non-standard IPTC dataset whose code is not in the common tables. The raw value is preserved "
                "verbatim; its meaning depends on the software that wrote it, so treat it as unverified.")
    if L.startswith("xmp: "):
        return ("This XMP property was written by the application that created or edited the file. XMP is standard "
                "editable metadata, so it documents what the software recorded but is not protected against modification.")
    if L.startswith("version info: "):
        return ("A version-resource string declared by the developer inside the executable. It aids identification but "
                "is self-reported and can be set to any value, so it does not verify the file's origin.")
    if L.startswith("custom property: ") or L.startswith("user-defined"):
        return ("A user-defined property stored inside the document by its author or software. Its meaning is specific "
                "to whoever created it; the value is shown exactly as stored.")
    if L.startswith("app property: "):
        return ("An extended application property recorded by the Office suite at save time. It is a self-reported "
                "counter or label that refreshes only when the document is saved.")
    if L.startswith("odf meta: "):
        return ("A metadata field from the OpenDocument meta.xml, written by the office suite that saved the file. "
                "It is standard editable document metadata rather than a verified fact.")
    if L.startswith("png text: "):
        return ("A text chunk stored inside the PNG container by the creating or editing software. Its content is "
                "whatever the software chose to write and can include tool names, captions or notes.")
    if L.startswith("nested archive: "):
        return ("An archive stored inside this archive, inspected read-only at depth one with a size cap. Nothing was "
                "extracted to disk; only its entry list was enumerated safely.")
    if L.startswith("container tag: "):
        return ("A tag stored in the media container by the muxer or encoder. Such tags record production details "
                "as self-reported text and are not independently verified.")
    if L.startswith("stream #"):
        return ("A stream summary produced by ffprobe from the container's own stream descriptions, combining codec, "
                "profile and the relevant dimensions or rates for this track.")
    if L.startswith("pdf property: "):
        return ("A non-standard key in the PDF information dictionary. Its meaning depends on the producing software; "
                "the value is preserved exactly as stored rather than interpreted.")
    if L.startswith("chunk ") and "unknown" in L:
        return ("An unknown or ancillary chunk that standard tables do not define. It is shown as hexadecimal so the "
                "data is preserved for inspection instead of being silently discarded.")
    if L.startswith("app") and "unrecognized" in L:
        return ("An application segment this parser does not specifically decode. It is shown as hexadecimal so the "
                "stored bytes remain visible rather than being hidden or discarded.")
    if L.startswith("table: "):
        return ("The table's row count and column names, read in read-only mode from the database schema. Row contents "
                "are never accessed or displayed by this tool.")
    if L.startswith("meta: "):
        return ("An HTML meta tag value declared by the page author. Meta content is self-declared text used by search "
                "engines and browsers, not a verified property of the page.")
    if L.startswith("open graph: "):
        return ("An Open Graph property used for social-media previews. It is declared by the page author and describes "
                "how the page prefers to be presented when shared.")
    if L.startswith("manifest: "):
        return ("An attribute declared in the APK's binary manifest, parsed statically. It records what the developer "
                "declared at build time and is read without executing anything.")
    if L.startswith("count of <"):
        return ("How many times this HTML element appears in the page, counted while parsing. Element frequencies give "
                "a quick structural overview without exposing page contents.")
    if L.startswith("rotation") or L.startswith("language"):
        return ("Per-stream metadata declared in the media container, such as playback rotation or language tagging. "
                "It guides players and is written by the muxer or authoring tool.")
    fb = GROUP_FALLBACK.get(gid)
    if fb:
        return fb.format(label=label)
    return "A metadata value read from the file by the parser and shown exactly as found. It is informational technical data that can be edited without detection."

# ------------------------------------------------------------ format detection
def detect_format(path):
    with open(path, "rb") as f:
        head = f.read(4096)
    d = {"family": "unknown", "short": "Unknown", "mime": "application/octet-stream", "ext": ".bin"}
    if head[:3] == b"\xff\xd8\xff":
        d.update(family="image", short="JPEG Image", mime="image/jpeg", ext=".jpg"); return d
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        d.update(family="image", short="PNG Image", mime="image/png", ext=".png"); return d
    if head[:4] == b"GIF8":
        d.update(family="image", short="GIF Image", mime="image/gif", ext=".gif"); return d
    if head[:4] == b"\x00\x00\x01\x00":
        d.update(family="image", short="Icon (ICO)", mime="image/x-icon", ext=".ico"); return d
    if head[:2] == b"BM":
        d.update(family="image", short="BMP Image", mime="image/bmp", ext=".bmp"); return d
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        d.update(family="image", short="TIFF Image", mime="image/tiff", ext=".tiff"); return d
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        d.update(family="image", short="WebP Image", mime="image/webp", ext=".webp"); return d
    if head[:4] == b"RIFF" and head[8:12] == b"AVI ":
        d.update(family="media", short="AVI Video", mime="video/x-msvideo", ext=".avi"); return d
    if head[:4] == b"FORM" and head[8:12] in (b"AIFF", b"AIFC"):
        d.update(family="media", short="AIFF Audio", mime="audio/aiff", ext=".aiff"); return d
    if head[:5] == b"%PDF-":
        d.update(family="pdf", short="PDF Document", mime="application/pdf", ext=".pdf"); return d
    if head[:16] == b"SQLite format 3\x00":
        d.update(family="sqlite", short="SQLite Database", mime="application/x-sqlite3", ext=".sqlite"); return d
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return _detect_zip_family(path, d)
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        d.update(family="ole", short="Legacy OLE Document (DOC/XLS/PPT/MSI)", mime="application/x-ole-storage", ext=".doc"); return d
    if head[:4] == b"\x7fELF":
        d.update(family="elf", short="ELF Binary (Linux/SO)", mime="application/x-elf", ext=".elf"); return d
    if head[:4] == b"\x1aE\xdf\xa3":
        if b"webm" in head:
            d.update(family="media", short="WebM Video", mime="video/webm", ext=".webm")
        else:
            d.update(family="media", short="Matroska Video (MKV)", mime="video/x-matroska", ext=".mkv")
        return d
    if head[4:8] == b"ftyp":
        brand = head[8:12].decode("latin-1", "replace").strip() or "isom"
        if brand.startswith("qt"):
            d.update(family="media", short="QuickTime Video (MOV)", mime="video/quicktime", ext=".mov")
        elif brand in ("M4A ", "M4B "):
            d.update(family="media", short="MPEG-4 Audio", mime="audio/mp4", ext=".m4a")
        elif brand in ("heic", "heix", "hevc", "mif1"):
            d.update(family="image", short="HEIC/HEIF Image", mime="image/heic", ext=".heic")
        elif brand == "avif":
            d.update(family="image", short="AVIF Image", mime="image/avif", ext=".avif")
        elif brand.startswith("3g"):
            d.update(family="media", short="3GP Video", mime="video/3gpp", ext=".3gp")
        else:
            d.update(family="media", short="MP4 Video", mime="video/mp4", ext=".mp4"); d["brand"] = brand
        return d
    if head[:3] == b"ID3":
        d.update(family="media", short="MP3 Audio", mime="audio/mpeg", ext=".mp3"); return d
    if head[:2] in (b"\xff\xf1", b"\xff\xf9"):
        d.update(family="media", short="AAC Audio (ADTS)", mime="audio/aac", ext=".aac"); return d
    if len(head) > 2 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0:
        d.update(family="media", short="MP3 Audio", mime="audio/mpeg", ext=".mp3"); return d
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        d.update(family="media", short="WAV Audio", mime="audio/x-wav", ext=".wav"); return d
    if head[:4] == b"\x30\x26\xb2\x75":
        d.update(family="media", short="Windows Media (ASF/WMV/WMA)", mime="video/x-ms-asf", ext=".asf"); return d
    if head[:4] == b"OggS":
        d.update(family="media", short="OGG Media (Vorbis/Opus)", mime="audio/ogg", ext=".ogg"); return d
    if head[:4] == b"fLaC":
        d.update(family="media", short="FLAC Audio", mime="audio/flac", ext=".flac"); return d
    if head[:4] == b"\x00\x00\x01\xba":
        d.update(family="media", short="MPEG Program Stream", mime="video/mpeg", ext=".mpg"); return d
    if head[:2] == b"MZ":
        d.update(family="exe", short="Windows Executable (PE/EXE)", mime="application/vnd.microsoft.portable-executable", ext=".exe"); return d
    if head[:5] == b"{\\rtf":
        d.update(family="rtf", short="Rich Text (RTF)", mime="application/rtf", ext=".rtf"); return d
    if head[:2] == b"\x1f\x8b":
        d.update(family="gz", short="Gzip Compressed (TAR.GZ/GZ)", mime="application/gzip", ext=".gz"); return d
    if head[:3] == b"BZh":
        d.update(family="gz", short="Bzip2 Compressed", mime="application/x-bzip2", ext=".bz2"); return d
    if head[:6] == b"\xfd7zXZ\x00":
        d.update(family="gz", short="XZ Compressed", mime="application/x-xz", ext=".xz"); return d
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        d.update(family="sevenz", short="7-Zip Archive", mime="application/x-7z-compressed", ext=".7z"); return d
    if head[:4] == b"Rar!":
        d.update(family="rar", short="RAR Archive", mime="application/x-rar-compressed", ext=".rar"); return d
    if len(head) > 262 and head[257:262] == b"ustar":
        d.update(family="tar", short="TAR Archive", mime="application/x-tar", ext=".tar"); return d
    s = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if s[:1] in (b"{", b"["):
        d.update(family="json", short="JSON Data", mime="application/json", ext=".json"); return d
    if s[:1] == b"<":
        low = head[:2048].lower()
        if b"<svg" in low:
            d.update(family="xml", short="SVG Vector Image", mime="image/svg+xml", ext=".svg"); return d
        if b"<html" in low:
            d.update(family="html", short="HTML Document", mime="text/html", ext=".html"); return d
        d.update(family="xml", short="XML Document", mime="application/xml", ext=".xml"); return d
    try:
        head.decode("utf-8")
        _text_family(d, path); return d
    except Exception:
        pass
    try:
        head.decode("latin-1")
        if all(32 <= b < 127 or b in (9, 10, 13) for b in head[:512] if b != 0):
            _text_family(d, path); return d
    except Exception:
        pass
    return d

def _text_family(d, path):
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if ext == "csv":
        d.update(family="csv", short="CSV Data", mime="text/csv", ext=".csv")
    elif ext in ("html", "htm"):
        d.update(family="html", short="HTML Document", mime="text/html", ext=".html")
    elif ext in ("md", "markdown"):
        d.update(family="txt", short="Markdown Text", mime="text/markdown", ext=".md")
    elif ext in ("log", "ini", "cfg", "conf", "yaml", "yml", "toml"):
        d.update(family="txt", short="Config/Log Text", mime="text/plain", ext="." + ext)
    elif ext in ("py", "js", "ts", "java", "c", "cpp", "h", "cs", "go", "rb", "php", "sh", "bat", "ps1", "sql"):
        d.update(family="txt", short="Source Code Text", mime="text/plain", ext="." + ext)
    else:
        d.update(family="txt", short="Plain Text", mime="text/plain", ext=".txt")

def _detect_zip_family(path, d):
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
    except Exception:
        d.update(family="unknown", short="Corrupt ZIP-based file", mime="application/zip", ext=".zip")
        return d
    if "AndroidManifest.xml" in names and any(n.startswith("classes") and n.endswith(".dex") for n in names):
        d.update(family="apk", short="Android Package (APK)", mime="application/vnd.android.package-archive", ext=".apk")
    elif "META-INF/container.xml" in names:
        d.update(family="epub", short="EPUB E-book", mime="application/epub+zip", ext=".epub")
    elif "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            d.update(family="ooxml", short="Word Document (DOCX)", mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document", ext=".docx")
        elif any(n.startswith("xl/") for n in names):
            d.update(family="ooxml", short="Excel Workbook (XLSX)", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ext=".xlsx")
        elif any(n.startswith("ppt/") for n in names):
            d.update(family="ooxml", short="PowerPoint Presentation (PPTX)", mime="application/vnd.openxmlformats-officedocument.presentationml.presentation", ext=".pptx")
        else:
            d.update(family="ooxml", short="Office Open XML Package", mime="application/zip", ext=".zip")
    elif "mimetype" in names:
        try:
            with zipfile.ZipFile(path) as z:
                mt = z.read("mimetype")[:60].decode("latin-1", "replace")
            if "opendocument" in mt:
                d.update(family="odf", short="OpenDocument (%s)" % mt.split(".")[-1], mime=mt.strip(), ext=".odt")
            else:
                d.update(family="zip", short="ZIP Archive", mime="application/zip", ext=".zip")
        except Exception:
            d.update(family="zip", short="ZIP Archive", mime="application/zip", ext=".zip")
    elif "META-INF/MANIFEST.MF" in names:
        d.update(family="jar", short="Java Archive (JAR)", mime="application/java-archive", ext=".jar")
    else:
        d.update(family="zip", short="ZIP Archive", mime="application/zip", ext=".zip")
    return d

# ------------------------------------------------------------ AXML parser
def _axml_string_pool(data, off):
    try:
        typ, _hs, _size = struct.unpack_from("<HHI", data, off)
        if typ != 0x0001:
            return None
        count, _sc, flags, strings_start, _st = struct.unpack_from("<IIIII", data, off + 8)
        utf8 = bool(flags & 0x100)
        offsets = struct.unpack_from("<%dI" % count, data, off + 28) if count else ()
        base = off + strings_start
        strings = []
        for o in offsets:
            p = base + o
            try:
                if utf8:
                    cl = data[p]; p += 1
                    if cl & 0x80:
                        cl = ((cl & 0x7F) << 8) | data[p]; p += 1
                    bl = data[p]; p += 1
                    if bl & 0x80:
                        bl = ((bl & 0x7F) << 8) | data[p]; p += 1
                    s = data[p:p + bl].decode("utf-8", "replace")
                else:
                    l16 = struct.unpack_from("<H", data, p)[0]; p += 2
                    if l16 & 0x8000:
                        l16 = ((l16 & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]; p += 2
                    s = data[p:p + l16 * 2].decode("utf-16-le", "replace")
            except Exception:
                s = ""
            strings.append(s)
        return strings
    except Exception:
        return None

def parse_axml(data):
    try:
        strings = _axml_string_pool(data, 8)
        if not strings:
            return None
        res = {"manifest": {}, "permissions": [], "features": [], "counts": {}, "uses_sdk": {}}
        COUNTED = ("activity", "activity-alias", "service", "receiver", "provider")
        off = 8
        while off + 8 <= len(data):
            typ, hs, size = struct.unpack_from("<HHI", data, off)
            if size < 8 or off + size > len(data):
                break
            if typ == 0x0102:
                name_i = struct.unpack_from("<I", data, off + 20)[0]
                attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, off + 24)
                elname = strings[name_i] if name_i < len(strings) else "?"
                if elname in COUNTED:
                    res["counts"][elname] = res["counts"].get(elname, 0) + 1
                abase = off + hs + attr_start
                for k in range(attr_count):
                    a = abase + k * (attr_size or 20)
                    if a + 20 > len(data):
                        break
                    aname_i, araw = struct.unpack_from("<II", data, a + 4)
                    dtype, ddata = data[a + 15], struct.unpack_from("<I", data, a + 16)[0]
                    an = strings[aname_i] if aname_i < len(strings) else "?"
                    if araw != 0xFFFFFFFF and araw < len(strings):
                        av = strings[araw]
                    elif dtype == 3 and ddata < len(strings):
                        av = strings[ddata]
                    elif dtype == 0x10:
                        av = str(ddata if ddata < 0x80000000 else ddata - 0x100000000)
                    elif dtype == 0x12:
                        av = "true" if ddata else "false"
                    elif dtype == 0x11:
                        av = "1" if ddata else "0"
                    elif dtype == 0x01:
                        av = "@" + hex(ddata)
                    else:
                        av = str(ddata)
                    if elname == "manifest":
                        res["manifest"][an] = av
                    elif elname in ("uses-permission", "uses-permission-sdk-23") and an == "name":
                        res["permissions"].append(av)
                    elif elname == "uses-feature" and an == "name":
                        res["features"].append(av)
                    elif elname == "uses-sdk":
                        res["uses_sdk"][an] = av
            off += size
        return res if res["manifest"] else None
    except Exception:
        return None

# ------------------------------------------------------------ PE / ELF
PE_DIR_NAMES = ["Export", "Import", "Resource", "Exception", "Certificate", "Relocation", "Debug",
                "Arch", "GlobalPtr", "TLS", "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLR", "Reserved"]

def parse_pe(data, path):
    res = {}
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    try:
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00" or len(data) < e_lfanew + 24:
            return None
        coff = e_lfanew + 4
        machine, nsec, tds, _ps, _ns, optsize, chars = struct.unpack_from("<HHIIIHH", data, coff)
        machines = {0x14C: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0xAA64: "ARM64", 0x1C0: "ARM"}
        res["Machine Type"] = machines.get(machine, hex(machine))
        res["Compile Date (PE header)"] = ts(tds) if tds else "(zeroed by compiler)"
        flags = []
        if chars & 0x0002: flags.append("Executable")
        if chars & 0x2000: flags.append("DLL")
        if chars & 0x0100: flags.append("32-bit")
        res["COFF Characteristics"] = ", ".join(flags) or "None"
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0] if len(data) >= opt + 2 else 0
        res["PE Format"] = "PE32+" if magic == 0x20B else "PE32"
        if len(data) >= opt + 4:
            res["Linker Version"] = "%d.%02d" % (data[opt + 2], data[opt + 3])
        if len(data) >= opt + 20:
            res["Entry Point"] = hex(struct.unpack_from("<I", data, opt + 16)[0])
        if len(data) >= opt + 70:
            subsystems = {1: "Native", 2: "GUI", 3: "Console", 9: "Windows CE", 10: "EFI", 16: "Boot"}
            res["Subsystem"] = subsystems.get(struct.unpack_from("<H", data, opt + 68)[0], "Unknown")
        if len(data) >= opt + 72:
            dllch = struct.unpack_from("<H", data, opt + 70)[0]
            dl = []
            if dllch & 0x0040: dl.append("ASLR")
            if dllch & 0x0100: dl.append("DEP")
            res["Security Flags"] = ", ".join(dl) or "None"
        dd = opt + (112 if magic == 0x20B else 96)
        if len(data) >= dd + 40:
            cert_size = struct.unpack_from("<I", data, dd + 36)[0]
            res["Digital Signature"] = "Yes (Authenticode table present)" if cert_size else "No signature table found"
            dirs = []
            for idx in range(16):
                if dd + idx * 8 + 8 > len(data):
                    break
                _rva, dsz = struct.unpack_from("<II", data, dd + idx * 8)
                if dsz:
                    dirs.append("%s (%s)" % (PE_DIR_NAMES[idx], human_size(dsz)))
            if dirs:
                res["Data Directories (present)"] = "\n".join(dirs)
        sec_base = opt + optsize
        rows, max_end = [], 0
        for s in range(min(nsec, 16)):
            so = sec_base + s * 40
            if so + 40 > len(data):
                break
            nm = data[so:so + 8].rstrip(b"\x00").decode("latin-1", "replace") or "(unnamed)"
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, so + 8)
            rows.append("%-8s  vsize=%-10s  raw=%-10s  va=%s" % (nm, human_size(vsize), human_size(rawsize), hex(vaddr)))
            max_end = max(max_end, rawptr + rawsize)
        if rows:
            res["Sections"] = "\n".join(rows)
        if max_end:
            res["Overlay Data"] = "Present (%s after last section)" % human_size(len(data) - max_end) if len(data) > max_end else "None"
    except Exception:
        return None
    if HAVE_PEFILE:
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            try:
                for fi in pe.FileInfo or []:
                    for st in fi:
                        if hasattr(st, "StringTable"):
                            for table in st.StringTable:
                                for k, v in table.entries.items():
                                    key = k.decode("latin-1", "replace")
                                    val = v.decode("latin-1", "replace").strip()
                                    if val:
                                        res["Version Info: " + key] = val
            except Exception:
                pass
            try:
                rows = ["%s (%d functions)" % (e.dll.decode("latin-1", "replace"), len(e.imports))
                        for e in pe.DIRECTORY_ENTRY_IMPORT]
                if rows:
                    res["Imported Libraries"] = "\n".join(rows[:40]) + ("\n... %d more" % (len(rows) - 40) if len(rows) > 40 else "")
            except Exception:
                pass
            try:
                res["Section Entropy"] = "\n".join(
                    "%-8s entropy=%.2f" % (s.Name.rstrip(b"\x00").decode("latin-1", "replace"), s.get_entropy())
                    for s in pe.sections)
            except Exception:
                pass
        except Exception:
            pass
    return res

def parse_elf(data):
    res = {}
    try:
        if data[:4] != b"\x7fELF" or len(data) < 52:
            return None
        ei_class, ei_data = data[4], data[5]
        res["Class"] = {1: "ELF32 (32-bit)", 2: "ELF64 (64-bit)"}.get(ei_class, str(ei_class))
        res["Byte Order"] = {1: "Little-endian", 2: "Big-endian"}.get(ei_data, str(ei_data))
        en = "<" if ei_data == 1 else ">"
        e_type, e_machine = struct.unpack_from(en + "HH", data, 16)
        res["Type"] = {1: "Relocatable", 2: "Executable", 3: "Shared object (SO)", 4: "Core dump"}.get(e_type, str(e_type))
        machines = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64 (ARM64)", 8: "MIPS", 20: "PowerPC", 243: "RISC-V"}
        res["Machine"] = machines.get(e_machine, str(e_machine))
        res["Entry Point"] = hex(struct.unpack_from(en + "Q", data, 24)[0])
        res["OS/ABI"] = {0: "System V / UNIX", 3: "Linux", 6: "Solaris", 9: "FreeBSD"}.get(data[7], str(data[7]))
        if ei_class == 2 and len(data) >= 64:
            e_phnum = struct.unpack_from(en + "H", data, 56)[0]
            e_shnum = struct.unpack_from(en + "H", data, 60)[0]
        else:
            e_phnum = struct.unpack_from(en + "H", data, 44)[0]
            e_shnum = struct.unpack_from(en + "H", data, 48)[0]
        res["Program Headers"] = str(e_phnum)
        res["Section Headers"] = str(e_shnum)
    except Exception:
        return None
    return res

# ------------------------------------------------------------ Extractor
class Extractor:
    def __init__(self, path, det, original_name=None, source="terminal"):
        self.path = path
        self.det = det
        self.name = original_name or os.path.basename(path)
        self.source = source
        self.groups = []
        self._group_index = {}
        self.gps = None
        self.preview = {"type": "none", "mime": det["mime"]}
        self.warnings = []
        st = os.stat(path)
        self.size = st.st_size
        self.st = st
        self._t0 = time.monotonic()

    def group(self, gid):
        name, kind = GROUP_META.get(gid, (gid.title(), "embedded"))
        if gid not in self._group_index:
            g = {"id": gid, "name": name, "kind": kind, "source": _source_for(gid), "fields": []}
            self._group_index[gid] = g
            self.groups.append(g)
        return self._group_index[gid]

    def add(self, gid, label, value):
        if value is None:
            return
        s = str(value).strip()
        if not s:
            return
        g = self.group(gid)
        g["fields"].append({"field": str(label), "value": clamp(s),
                            "explanation": note_for(str(label), gid, s)})

    def basic(self):
        st = self.st
        ext = os.path.splitext(self.name)[1].lstrip(".").lower()
        self.add("basic", "File Name", self.name)
        self.add("basic", "File Type", self.det["short"])
        self.add("basic", "MIME Type", self.det["mime"])
        self.add("basic", "File Size", size_str(self.size))
        self.add("basic", "Created Date", ts(st.st_ctime))
        self.add("basic", "Modified Date", ts(st.st_mtime))
        self.add("basic", "Accessed Date", ts(st.st_atime))
        self.add("basic", "File Extension", ext)
        try:
            with open(self.path, "rb") as f:
                sig = f.read(32)
            self.add("basic", "File Signature (Magic Bytes)", bytes(sig).hex(" "))
        except Exception:
            pass
        if self.source == "terminal":
            self.add("basic", "File Path", os.path.abspath(self.path))
            try:
                fa = st.st_file_attributes
                bits = {0x1: "Read-only", 0x2: "Hidden", 0x4: "System", 0x20: "Archive",
                        0x80: "Normal", 0x400: "Encrypted", 0x40000: "Reparse point"}
                self.add("basic", "File Attributes",
                         ", ".join(n for bit, n in bits.items() if fa & bit) or "None flagged")
            except AttributeError:
                pass
        # browser upload: no Path row at all (browsers never expose the original location)

    # ---------------- AI detection: simple Yes/No
    def _ai_detection(self):
        try:
            with open(self.path, "rb") as f:
                blob = f.read(8 * 1024 * 1024)
        except Exception:
            return
        low = blob.lower()
        marker = False
        for name in AI_TOOL_NAMES:
            if name.encode("utf-8", "ignore") in low:
                marker = True
                break
        if (b"c2pa" in low) or (b"content credentials" in low) or (b"contentcredentials" in low):
            marker = True
        if (b"negative prompt" in low) or (b"parameters:" in low):
            marker = True
        self.add("ai", "AI File Detected", "Yes" if marker else "No")

    # ---------------- EXIF / GPS
    def _exif_row(self, name, val):
        if val is None:
            return
        if isinstance(val, (bytes, bytearray)) and name == "UserComment":
            val = re.sub(rb"^(ASCII|UNICODE|JIS)\x00*", b"", bytes(val))
        fn = EXIF_FMT.get(name)
        try:
            s = fn(val) if fn else to_str(val)
        except Exception:
            s = to_str(val)
        self.add("exif", name, s)

    def _dump_gps(self, gps):
        if not gps:
            return
        lat = dms_to_deg(gps.get(2), gps.get(1, ""))
        lon = dms_to_deg(gps.get(4), gps.get(3, ""))
        if lat is None and lon is None:
            # GPS tags exist but coordinates are zero/unreadable — honest message
            raw = []
            for k in (2, 4):
                v = gps.get(k)
                if v is not None:
                    raw.append(to_str(v, 120))
            msg = "Present but zero/invalid \u2014 the device recorded no usable satellite fix"
            if raw:
                msg += " (raw: " + " | ".join(raw) + ")"
            self.add("gps", "GPS Coordinates", msg)
            return
        if lat is not None:
            self.add("gps", "GPS Latitude", "%.6f\u00b0 %s" % (abs(lat), "N" if lat >= 0 else "S"))
        if lon is not None:
            self.add("gps", "GPS Longitude", "%.6f\u00b0 %s" % (abs(lon), "E" if lon >= 0 else "W"))
        if lat is not None and lon is not None:
            self.gps = {"latitude": lat, "longitude": lon}

    def _dump_exif(self, ex):
        if not ex:
            return
        try:
            sub = ex.get_ifd(0x8769) or {}
        except Exception:
            sub = {}
        try:
            gps = ex.get_ifd(0x8825) or {}
        except Exception:
            gps = {}
        skip = {0x8769, 0x8825, 0xA005}
        for tag_id, val in sorted(ex.items()):
            if tag_id not in skip:
                self._exif_row(TAGS.get(tag_id, "Tag 0x%04X" % tag_id), val)
        for tag_id, val in sorted(sub.items()):
            self._exif_row(TAGS.get(tag_id, "Exif Tag 0x%04X" % tag_id), val)
        mn = sub.get(0x927C)
        if mn is not None:
            self.add("exif", "MakerNote", "Present, %d bytes (proprietary vendor format, not decoded)" % len(mn)
                     if isinstance(mn, (bytes, bytearray)) else to_str(mn))
        tln = ex.get(0x0202)
        if tln:
            self.add("exif", "Embedded Thumbnail", "%s bytes" % to_str(tln))
        self._dump_gps(gps)

    def _load_raw_exif(self, data):
        try:
            ex = Image.Exif()
            ex.load(data)
            self._dump_exif(ex)
            return True
        except Exception:
            return False

    def _parse_xmp_group(self, raw):
        if not raw:
            return
        props = {}
        try:
            root = ET.fromstring(raw)
        except Exception:
            return
        for el in root.iter():
            tag = el.tag.split("}")[-1]
            if tag in ("rdf", "RDF", "li"):
                continue
            text = (el.text or "").strip()
            if not text and len(el):
                lis = [(c.text or "").strip() for c in el.iter() if c.tag.split("}")[-1] == "li" and (c.text or "").strip()]
                if lis:
                    text = "; ".join(lis[:10]) + (" ..." if len(lis) > 10 else "")
            if text and tag not in props:
                props[tag] = text
            for an, av in el.attrib.items():
                an2 = an.split("}")[-1]
                if an2 in ("parseType", "about", "ID", "resource", "datatype", "ns"):
                    continue
                if av and len(av) < 300 and an2 not in props:
                    props[an2] = av
        for tag, text in sorted(props.items()):
            if tag.lower() == "about":
                continue
            self.add("xmp", "XMP: " + tag, clamp(text, 1000))

    def _exiftool_group(self):
        if not EXIFTOOL:
            return
        try:
            out = subprocess.run([EXIFTOOL, "-j", "-G", "-m", self.path], capture_output=True, timeout=60)
            data = json.loads(out.stdout.decode("utf-8", "replace"))[0]
            existing = {f["field"] for g in self.groups for f in g["fields"]}
            n = 0
            for k, v in sorted(data.items()):
                if k.startswith("SourceFile") or n >= 250:
                    continue
                key = k.split(":", 1)[-1]
                if key in existing:
                    continue
                self.add("exiftool", key, to_str(v, 500))
                n += 1
        except Exception as e:
            self.warnings.append("ExifTool scan failed: %s" % e)

    def extract_image(self):
        self.preview = {"type": "image", "mime": self.det["mime"]}
        if self.det["ext"] in (".heic", ".avif") and not HAVE_PIL:
            self.warnings.append("HEIC/AVIF decoding needs Pillow with libheif support; signature detection succeeded but pixel metadata could not be read.")
        if not HAVE_PIL:
            self.warnings.append("Pillow is not installed \u2014 image metadata is unavailable. Run: pip install Pillow")
            return
        try:
            im = Image.open(self.path)
        except Exception as e:
            self.warnings.append("Image could not be decoded by Pillow: %s (format detected, decoder may lack support)" % e)
            return
        w, h = im.size
        self.add("image", "Image Width", "%d pixels" % w)
        self.add("image", "Image Height", "%d pixels" % h)
        try:
            self.add("image", "Megapixels", "%.2f MP (%d total pixels)" % (w * h / 1000000.0, w * h))
            r = Fraction(w, h).limit_denominator(40)
            self.add("image", "Aspect Ratio", "%d:%d  (%.2f)" % (r.numerator, r.denominator, w / h))
        except Exception:
            pass
        self.add("image", "Color Mode", im.mode)
        if "dpi" in im.info:
            try:
                self.add("image", "Resolution (DPI)", "%d x %d" % tuple(_i(x) for x in im.info["dpi"][:2]))
            except Exception:
                pass
        if im.info.get("icc_profile"):
            self.add("image", "ICC Profile", "Present (%d bytes)" % len(im.info["icc_profile"]))
        if im.info.get("transparency") is not None:
            self.add("image", "Transparency", "Present")
        n_frames = getattr(im, "n_frames", 1)
        if n_frames > 1:
            self.add("image", "Frames", str(n_frames))
            if "loop" in im.info:
                self.add("image", "Loop Behavior", "Loops forever" if im.info["loop"] == 0 else "%s loops" % im.info["loop"])
        if im.mode == "P":
            self.add("image", "Palette Colors", str(len(im.getpalette() or []) // 3))
        dumpers = {".jpg": self._jpeg_dump, ".png": self._png_dump, ".gif": self._gif_dump,
                   ".bmp": self._bmp_dump, ".webp": self._webp_dump, ".tiff": self._tiff_dump,
                   ".ico": lambda im2: self.add("custom", "ICO Container", "Multi-size icon container decoded by Pillow")}
        dumper = dumpers.get(self.det["ext"])
        if dumper:
            try:
                dumper(im)
            except Exception as e:
                self.warnings.append("Format-specific scan failed: %s" % e)
        try:
            self._ai_detection()
        except Exception as e:
            self.warnings.append("AI indicator scan failed: %s" % e)
        self._exiftool_group()

    def _jpeg_dump(self, im):
        try:
            self._dump_exif(im.getexif())
        except Exception as e:
            self.warnings.append("EXIF could not be read: %s" % e)
        try:
            from PIL import IptcImagePlugin
            iptc = IptcImagePlugin.getiptcinfo(im)
        except Exception:
            iptc = None
        if iptc:
            for k in sorted(iptc.keys()):
                name = IPTC_NAMES.get(k, "IPTC Record %d, Dataset %d" % (k[0], k[1]))
                v = iptc[k]
                if isinstance(v, (bytes, bytearray)):
                    try:
                        txt = v.decode("utf-8")
                    except Exception:
                        txt = v.decode("latin-1", "replace")
                else:
                    txt = str(v)
                self.add("iptc", name, clamp(txt.strip(), 500))
        self._jpeg_segments()

    def _jpeg_segments(self):
        with open(self.path, "rb") as f:
            data = f.read(MAX_SCAN)
        MK = {0xC0: "SOF0 Baseline", 0xC2: "SOF2 Progressive", 0xC4: "DHT", 0xDB: "DQT", 0xDD: "DRI",
              0xDA: "SOS", 0xE0: "APP0", 0xE1: "APP1", 0xE2: "APP2", 0xEC: "APP12", 0xED: "APP13",
              0xEE: "APP14", 0xFE: "COM (Comment)"}
        i, segs, progressive, icc_count = 2, [], False, 0
        while i + 1 < len(data):
            if data[i] != 0xFF:
                break
            while i + 1 < len(data) and data[i] == 0xFF and data[i + 1] == 0xFF:
                i += 1
            if i + 1 >= len(data):
                break
            m = data[i + 1]
            if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
                i += 2; continue
            if m == 0xD9:
                segs.append("EOI"); break
            if i + 4 > len(data):
                break
            L = int.from_bytes(data[i + 2:i + 4], "big")
            if L < 2:
                break
            payload = data[i + 4:i + 2 + L]
            segs.append(MK.get(m, "0x%02X" % m))
            if m == 0xC2:
                progressive = True
            if m == 0xE0 and payload[:4] == b"JFIF\x00":
                try:
                    self.add("custom", "JFIF Version", "%d.%02d" % (payload[5], payload[6]))
                except Exception:
                    pass
            elif m == 0xE1 and payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                self._parse_xmp_group(payload[29:])
            elif m == 0xE2 and payload[:11] == b"ICC_PROFILE":
                icc_count += 1
            elif m == 0xEC and payload[:11] == b"Photoshop 3":
                self.add("custom", "Photoshop Resources (APP13)", "%d bytes, %d 8BIM blocks" % (L, payload.count(b"8BIM")))
            elif m == 0xEE and payload[:5] == b"Adobe":
                self.add("custom", "Adobe Segment (APP14)", "transform flag: %d" % (payload[11] if len(payload) > 11 else -1))
            elif m == 0xFE:
                self.add("custom", "JPEG Comment", clamp(payload.decode("latin-1", "replace").strip("\x00 "), 500))
            elif 0xE0 <= m <= 0xEF and m not in (0xE0, 0xE1, 0xE2, 0xEC, 0xEE):
                self.add("custom", "APP%d Segment (unrecognized, %d bytes)" % (m - 0xE0, L),
                         "%s%s" % (bytes(payload[:32]).hex(" "), " ..." if len(payload) > 32 else ""))
            i += 2 + L
            if m == 0xDA:
                break
        if icc_count:
            self.add("custom", "ICC Profile Segments", "%d APP2 ICC segment(s)" % icc_count)
        self.add("custom", "JPEG Encoding Process", "Progressive" if progressive else "Baseline (sequential)")
        self.add("custom", "JPEG Segment Map", ", ".join(segs[:60]) + (" ..." if len(segs) > 60 else ""))

    def _png_dump(self, im):
        with open(self.path, "rb") as f:
            data = f.read(MAX_SCAN)
        i, names = 8, []
        while i + 8 <= len(data):
            ln = int.from_bytes(data[i:i + 4], "big")
            typ = data[i + 4:i + 8]
            if not re.match(rb"^[A-Za-z]{4}$", typ):
                break
            tname = typ.decode()
            names.append(tname)
            body = data[i + 8:i + 8 + min(ln, 400000)]
            try:
                if typ == b"IHDR" and len(body) >= 13:
                    bd, ct, interlace = body[8], body[9], body[12]
                    ctn = {0: "Grayscale", 2: "RGB", 3: "Palette", 4: "Grayscale + Alpha", 6: "RGBA"}.get(ct, str(ct))
                    self.add("image", "Bit Depth", "%d bits per channel" % bd)
                    self.add("image", "PNG Color Type", ctn)
                    self.add("image", "Interlacing", "Adam7 interlaced" if interlace else "None")
                elif typ in (b"tEXt", b"zTXt", b"iTXt"):
                    if typ == b"tEXt":
                        k, _, v = body.partition(b"\x00")
                        v = v.decode("latin-1", "replace")
                    elif typ == b"zTXt":
                        k, _, rest = body.partition(b"\x00")
                        v = zlib.decompress(rest[1:]).decode("latin-1", "replace")
                    else:
                        k, _, rest = body.partition(b"\x00")
                        rest = rest[2:]
                        _lang, _, rest = rest.partition(b"\x00")
                        _trans, _, rest = rest.partition(b"\x00")
                        v = rest.decode("utf-8", "replace")
                    k = k.decode("latin-1", "replace")
                    if k == "XML:com.adobe.xmp":
                        self._parse_xmp_group(v.encode("utf-8", "replace"))
                    else:
                        self.add("custom", "PNG Text: " + k, clamp(v, 600))
                elif typ == b"tIME" and len(body) >= 7:
                    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
                    self.add("custom", "Last Modification (tIME)",
                             "%d %s %d, %02d:%02d:%02d UTC" % (body[2], months[body[1] - 1], int.from_bytes(body[0:2], "big"), body[3], body[4], body[5]))
                elif typ == b"pHYs" and len(body) >= 9 and body[8] == 1:
                    self.add("image", "Resolution (DPI)", "%d x %d" % (round(int.from_bytes(body[0:4], "big") * 0.0254),
                                                                       round(int.from_bytes(body[4:8], "big") * 0.0254)))
                elif typ == b"gAMA":
                    self.add("custom", "Gamma (gAMA)", str(round(int.from_bytes(body[0:4], "big") / 100000.0, 4)))
                elif typ == b"sRGB":
                    self.add("custom", "sRGB Intent", {0: "Perceptual", 1: "Relative colorimetric", 2: "Saturation", 3: "Absolute colorimetric"}.get(body[0] if body else -1, to_str(body)))
                elif typ == b"iCCP":
                    k, _, _rest = body.partition(b"\x00")
                    self.add("image", "ICC Profile (iCCP)", "%s (%d bytes compressed)" % (k.decode("latin-1", "replace"), ln))
                elif typ == b"acTL" and len(body) >= 8:
                    self.add("image", "APNG Animation (acTL)", "%d frames" % int.from_bytes(body[0:4], "big"))
                elif typ == b"eXIf":
                    self.add("custom", "EXIF chunk (eXIf)", "Present (%d bytes)" % ln)
                    self._load_raw_exif(bytes(body))
                elif typ not in (b"IHDR", b"PLTE", b"IDAT", b"IEND", b"fdAT", b"fcTL"):
                    self.add("custom", "Chunk %s (unknown/ancillary, %d bytes)" % (tname, ln),
                             "%s%s" % (bytes(body[:48]).hex(" "), " ..." if ln > 48 else ""))
            except Exception:
                pass
            i += 12 + ln
            if typ == b"IEND":
                break
        self.add("custom", "PNG Chunk Map (all chunks, in order)", ", ".join(names))

    def _gif_dump(self, im):
        with open(self.path, "rb") as f:
            hdr = f.read(32)
        try:
            flags = hdr[10]
            self.add("custom", "GIF Version", "GIF %s" % hdr[3:6].decode("latin-1"))
            self.add("custom", "Logical Screen", "%d x %d pixels" % (int.from_bytes(hdr[6:8], "little"), int.from_bytes(hdr[8:10], "little")))
            gct = bool(flags & 0x80)
            self.add("custom", "Global Color Table", "Present (%d colors)" % (2 ** ((flags & 7) + 1)) if gct else "Absent")
        except Exception:
            pass
        c = im.info.get("comment")
        if isinstance(c, (bytes, bytearray)):
            self.add("custom", "GIF Comment", clamp(fmt_bytes_value(c), 500))
        elif isinstance(c, str):
            self.add("custom", "GIF Comment", clamp(c, 500))

    def _bmp_dump(self):
        with open(self.path, "rb") as f:
            h = f.read(64)
        try:
            dib = int.from_bytes(h[14:18], "little")
            comp = int.from_bytes(h[30:34], "little")
            xppm = int.from_bytes(h[38:42], "little", signed=True)
            self.add("custom", "Dimensions (header)", "%d x %d pixels" % (abs(int.from_bytes(h[18:22], "little", signed=True)), abs(int.from_bytes(h[22:26], "little", signed=True))))
            self.add("custom", "Bit Depth", "%d bits per pixel" % int.from_bytes(h[28:30], "little"))
            self.add("custom", "Compression", {0: "Uncompressed (BI_RGB)", 1: "BI_RLE8", 2: "BI_RLE4", 3: "BI_BITFIELDS"}.get(comp, "Method %d" % comp))
            if xppm:
                self.add("custom", "Pixel Density", "%d pixels/meter (~%d DPI)" % (xppm, round(xppm * 0.0254)))
            self.add("custom", "DIB Header", "%d bytes (%s)" % (dib, {12: "BITMAPCOREHEADER", 40: "BITMAPINFOHEADER", 108: "BITMAPV4HEADER", 124: "BITMAPV5HEADER"}.get(dib, "variant")))
        except Exception as e:
            self.warnings.append("BMP header parse failed: %s" % e)

    def _webp_dump(self, im):
        with open(self.path, "rb") as f:
            data = f.read(MAX_SCAN)
        i, chunks, exif_data, xmp_data = 12, [], None, None
        while i + 8 <= len(data):
            cid = data[i:i + 4]
            cs = int.from_bytes(data[i + 4:i + 8], "little")
            end = i + 8 + cs + (cs % 2)
            if end > len(data):
                break
            chunks.append(cid.decode("latin-1", "replace") + " (%s)" % human_size(cs))
            body = data[i + 8:i + 8 + min(cs, 400000)]
            if cid == b"EXIF":
                exif_data = body
            elif cid == b"XMP ":
                xmp_data = body
            i = end
        self.add("custom", "WebP Chunk Map", ", ".join(chunks))
        if exif_data:
            if not self._load_raw_exif(bytes(exif_data)):
                self.add("custom", "EXIF chunk", "Present (%d bytes, could not be decoded)" % len(exif_data))
        if xmp_data:
            self._parse_xmp_group(bytes(xmp_data))

    def _tiff_dump(self, im):
        try:
            self._dump_exif(im.getexif())
        except Exception as e:
            self.warnings.append("TIFF tags could not be read: %s" % e)

    def extract_pdf(self):
        self.preview = {"type": "pdf", "mime": self.det["mime"]}
        if not HAVE_PYPDF:
            self.warnings.append("pypdf is not installed \u2014 PDF properties are unavailable. Run: pip install pypdf")
            return
        try:
            reader = PdfReader(self.path)
        except Exception as e:
            self.warnings.append("PDF could not be parsed: %s" % e)
            return
        try:
            ver = reader.pdf_header
            if isinstance(ver, bytes):
                ver = ver.decode("latin-1", "replace")
            self.add("pdf", "PDF Version", ver or "(unknown)")
        except Exception:
            pass
        try:
            self.add("pdf", "Encrypted", "Yes" if reader.is_encrypted else "No")
        except Exception:
            pass
        try:
            self.add("pdf", "Page Count", str(len(reader.pages)))
        except Exception:
            pass
        try:
            md = reader.metadata
            if md:
                pretty = {"/Title": "Title", "/Author": "Author", "/Subject": "Subject", "/Keywords": "Keywords",
                          "/Creator": "Creator (Application)", "/Producer": "Producer"}
                for k, v in dict(md).items():
                    if v is None or not str(v).strip():
                        continue
                    ks = str(k)
                    if ks in ("/CreationDate", "/ModDate"):
                        self.add("pdf", "Creation Date" if ks == "/CreationDate" else "Modification Date", self._pdf_date(str(v)))
                    else:
                        self.add("pdf", pretty.get(ks, "PDF Property: " + ks.lstrip("/")), str(v).strip())
        except Exception as e:
            self.warnings.append("PDF metadata dict could not be read: %s" % e)
        try:
            xmp = reader.xmp_metadata
            if xmp is not None:
                raw = xmp.stream.get_data()
                if isinstance(raw, str):
                    raw = raw.encode("utf-8", "replace")
                self._parse_xmp_group(bytes(raw[:200000]))
        except Exception:
            pass
        try:
            flds = reader.get_fields()
            if flds:
                self.add("pdf", "Form Fields", "%d interactive field(s)" % len(flds))
        except Exception:
            pass
        try:
            att = reader.attachments
            if att:
                self.add("pdf", "Embedded Files", "%d file(s): %s" % (len(att), ", ".join(list(att.keys())[:6])))
        except Exception:
            pass

    @staticmethod
    def _pdf_date(v):
        m = re.match(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?", str(v))
        if m:
            p = [x if x else "01" for x in m.groups()]
            try:
                return "%s %s %s %s:%s:%s" % (p[2], ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][int(p[1]) - 1], p[0], p[3], p[4], p[5])
            except Exception:
                pass
        return str(v)

    def extract_ooxml(self):
        try:
            with zipfile.ZipFile(self.path) as z:
                names = z.namelist()
                if "docProps/core.xml" in names:
                    try:
                        root = ET.fromstring(z.read("docProps/core.xml"))
                        dated = ("created", "modified", "lastPrinted")
                        for el in root.iter():
                            t = el.tag.split("}")[-1]
                            if t == "coreProperties":
                                continue
                            txt = (el.text or "").strip()
                            if not txt:
                                continue
                            label = {"creator": "Author", "lastModifiedBy": "Last Modified By"}.get(t, t[:1].upper() + t[1:])
                            self.add("office", label, iso_ts(txt) if t in dated else txt)
                    except Exception as e:
                        self.warnings.append("Core properties could not be parsed: %s" % e)
                if "docProps/app.xml" in names:
                    try:
                        root = ET.fromstring(z.read("docProps/app.xml"))
                        for el in root.iter():
                            t = el.tag.split("}")[-1]
                            if t == "Properties":
                                continue
                            txt = (el.text or "").strip()
                            if not txt:
                                continue
                            label = {"Application": "Application", "Company": "Company", "TotalTime": "Total Editing Time"}.get(t, "App Property: " + t)
                            self.add("office", label, (txt + " minutes") if t == "TotalTime" else txt)
                    except Exception as e:
                        self.warnings.append("Extended properties could not be parsed: %s" % e)
                if "docProps/custom.xml" in names:
                    try:
                        root = ET.fromstring(z.read("docProps/custom.xml"))
                        for prop in root:
                            pname = next((av for ak, av in prop.attrib.items() if ak.split("}")[-1] == "name"), None)
                            val = "".join(prop.itertext()).strip()
                            if pname:
                                self.add("office", "Custom Property: " + pname, val)
                    except Exception as e:
                        self.warnings.append("Custom properties could not be parsed: %s" % e)
                if self.det["ext"] == ".xlsx" and "xl/workbook.xml" in names:
                    try:
                        root = ET.fromstring(z.read("xl/workbook.xml"))
                        sheets, hidden = [], 0
                        for el in root.iter():
                            if el.tag.split("}")[-1] == "sheet":
                                nm = el.attrib.get("name", "?")
                                if el.attrib.get("state") == "hidden":
                                    sheets.append(nm + " (hidden)")
                                    hidden += 1
                                else:
                                    sheets.append(nm)
                        if sheets:
                            self.add("office", "Sheet Names", ", ".join(sheets[:40]))
                            if hidden:
                                self.add("office", "Hidden Sheets", str(hidden))
                    except Exception:
                        pass
                    self.add("office", "Worksheets", str(len([n for n in names if re.match(r"xl/worksheets/sheet\d+\.xml$", n)])))
                if self.det["ext"] == ".pptx":
                    self.add("office", "Slides", str(len([n for n in names if re.match(r"ppt/slides/slide\d+\.xml$", n)])))
        except Exception as e:
            self.warnings.append("Office package could not be opened: %s" % e)

    def extract_odf(self):
        try:
            with zipfile.ZipFile(self.path) as z:
                if "meta.xml" in z.namelist():
                    root = ET.fromstring(z.read("meta.xml"))
                    dated = ("creation-date", "date", "print-date")
                    for el in root.iter():
                        t = el.tag.split("}")[-1]
                        txt = (el.text or "").strip()
                        if t == "user-defined":
                            pname = next((el.attrib[ak] for ak in el.attrib if ak.split("}")[-1] == "name"), None)
                            if pname and txt:
                                self.add("office", "Custom Property: " + pname, txt)
                            continue
                        if not txt:
                            continue
                        self.add("office", "ODF Meta: " + t, iso_ts(txt) if t in dated else txt)
        except Exception as e:
            self.warnings.append("ODF metadata could not be parsed: %s" % e)

    def extract_epub(self):
        try:
            with zipfile.ZipFile(self.path) as z:
                self.add("office", "Files In Book", str(len(z.namelist())))
                try:
                    container = z.read("META-INF/container.xml").decode("utf-8", "replace")
                    m = re.search(r'full-path="([^"]+)"', container)
                    if m:
                        opf_path = m.group(1)
                        opf = z.read(opf_path).decode("utf-8", "replace")
                        self.add("office", "OPF Package File", opf_path)
                        for pat, label in [(r"<dc:title[^>]*>([^<]+)</dc:title>", "Title"),
                                           (r"<dc:creator[^>]*>([^<]+)</dc:creator>", "Author"),
                                           (r"<dc:language[^>]*>([^<]+)</dc:language>", "Language"),
                                           (r"<dc:identifier[^>]*>([^<]+)</dc:identifier>", "Identifier")]:
                            mm = re.search(pat, opf)
                            if mm:
                                self.add("office", label, mm.group(1).strip()[:200])
                except Exception:
                    pass
        except Exception as e:
            self.warnings.append("EPUB could not be inspected: %s" % e)

    def extract_zip(self):
        try:
            with zipfile.ZipFile(self.path) as z:
                infos = z.infolist()
                total_u = sum(i.file_size for i in infos)
                mnames = {0: "Store", 8: "Deflate", 12: "Bzip2", 14: "LZMA"}
                enc = sum(1 for i in infos if i.flag_bits & 0x1)
                self.add("archive", "Integrity Check", "Central directory readable \u2014 archive structure is valid")
                self.add("archive", "Total Entries", str(len(infos)))
                self.add("archive", "Directory Entries", str(sum(1 for i in infos if i.is_dir())))
                self.add("archive", "Uncompressed Size", size_str(total_u))
                self.add("archive", "Compressed Size (archive)", size_str(self.size))
                if total_u:
                    self.add("archive", "Compression Ratio", "%.1f%% saved" % (100.0 * (1 - self.size / total_u)))
                self.add("archive", "Compression Methods", ", ".join(mnames.get(m, "Method %d" % m) for m in sorted({i.compress_type for i in infos})) or "Unknown")
                if enc:
                    self.add("archive", "Encrypted Entries", "%d entr(y/ies) flagged as password-protected" % enc)
                if z.comment:
                    self.add("archive", "Archive Comment", z.comment.decode("utf-8", "replace")[:400])
                if infos:
                    big = max(infos, key=lambda i: i.file_size)
                    self.add("archive", "Largest Entry", "%s \u2014 %s" % (big.filename, size_str(big.file_size)))
                lines = []
                for i2 in infos[:MAX_ARCHIVE_ENTRIES]:
                    dt = datetime(*i2.date_time).strftime("%Y-%m-%d %H:%M") if i2.date_time[0] else "-"
                    lines.append("%-9s  %-10s  %-8s  CRC %08X  %s" % (
                        human_size(i2.file_size).split(" (")[0], dt,
                        mnames.get(i2.compress_type, "M%d" % i2.compress_type), i2.CRC, i2.filename[:70]))
                if len(infos) > MAX_ARCHIVE_ENTRIES:
                    lines.append("... and %d more entries" % (len(infos) - MAX_ARCHIVE_ENTRIES))
                self.add("archive", "Full Entry Listing (safe, nothing extracted)", "\n".join(lines))
                self._nested_archives(infos)
        except Exception as e:
            self.warnings.append("Archive could not be inspected: %s" % e)

    def _nested_archives(self, infos):
        nested = [i for i in infos if i.filename.lower().endswith((".zip", ".jar", ".apk", ".epub"))
                  and i.file_size <= NESTED_ARCHIVE_BYTES][:5]
        for item in nested:
            try:
                with zipfile.ZipFile(self.path) as z:
                    with zipfile.ZipFile(io.BytesIO(z.read(item.filename))) as inner:
                        names = inner.namelist()
                        self.add("archive", "Nested Archive: " + item.filename,
                                 "%d entries: %s%s" % (len(names), ", ".join(names[:30]), " ..." if len(names) > 30 else ""))
            except Exception:
                self.add("archive", "Nested Archive: " + item.filename,
                         "Present but could not be inspected (corrupt or encrypted)")

    def extract_tar(self):
        try:
            if self.det["family"] == "gz":
                self.add("archive", "Compression Layer", self.det["short"])
            with tarfile.open(self.path, "r:*") as tf:
                members = tf.getmembers()
                total_u = sum(m.size for m in members if m.isfile())
                self.add("archive", "Total Entries", str(len(members)))
                self.add("archive", "Files", str(sum(1 for m in members if m.isfile())))
                self.add("archive", "Directories", str(sum(1 for m in members if m.isdir())))
                self.add("archive", "Uncompressed Size", size_str(total_u))
                lines = []
                for m in members[:MAX_ARCHIVE_ENTRIES]:
                    lines.append("%-9s  %s  %s" % (human_size(m.size).split(" (")[0],
                                                   datetime.fromtimestamp(m.mtime).strftime("%Y-%m-%d %H:%M") if m.mtime else "-", m.name[:70]))
                if len(members) > MAX_ARCHIVE_ENTRIES:
                    lines.append("... and %d more" % (len(members) - MAX_ARCHIVE_ENTRIES))
                self.add("archive", "Full Entry Listing (safe, nothing extracted)", "\n".join(lines))
        except Exception as e:
            self.warnings.append("TAR/GZ could not be inspected: %s" % e)

    def extract_sevenz(self):
        if not HAVE_PY7ZR:
            self.add("archive", "7z Support", "Optional library py7zr is not installed \u2014 install with: pip install py7zr")
            self.warnings.append("7z parsing requires the optional py7zr package.")
            return
        try:
            with py7zr.SevenZipFile(self.path, mode="r") as z:
                infos = z.list()
                self.add("archive", "Total Entries", str(len(infos)))
                total_u = sum(getattr(f, "uncompressed", 0) or 0 for f in infos)
                self.add("archive", "Uncompressed Size", size_str(total_u))
                names = [getattr(f, "filename", "?") for f in infos[:MAX_ARCHIVE_ENTRIES]]
                self.add("archive", "Entry Listing (safe)", "\n".join(names))
        except Exception as e:
            self.warnings.append("7z could not be inspected: %s" % e)

    def extract_rar(self):
        if not HAVE_RARFILE:
            self.add("archive", "RAR Support", "Optional library rarfile (+ unrar backend) is not installed \u2014 detection only")
            self.warnings.append("RAR listing requires rarfile and an unrar backend on this system.")
            return
        try:
            with rarfile.RarFile(self.path) as rf:
                infos = rf.infolist()
                self.add("archive", "Total Entries", str(len(infos)))
                names = [i.filename for i in infos[:MAX_ARCHIVE_ENTRIES]]
                self.add("archive", "Entry Listing (safe)", "\n".join(names))
        except Exception as e:
            self.warnings.append("RAR could not be inspected: %s" % e)

    def extract_apk(self):
        try:
            with zipfile.ZipFile(self.path) as z:
                names = z.namelist()
                self.add("apk", "AndroidManifest.xml", "Present" if "AndroidManifest.xml" in names else "Missing (not a valid APK)")
                dex = [n for n in names if n.endswith(".dex")]
                self.add("apk", "DEX Files", ", ".join(dex) if dex else "None")
                abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and "/" in n[4:]})
                if abis:
                    self.add("apk", "Native ABIs", ", ".join(abis))
                sigs = [n for n in names if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC", ".SF"))]
                if sigs:
                    self.add("apk", "Signing Files", ", ".join(os.path.basename(s) for s in sigs[:8]))
                axml = None
                if "AndroidManifest.xml" in names:
                    axml = parse_axml(z.read("AndroidManifest.xml"))
                if axml:
                    pretty = {"package": "Package Name", "versionName": "Version Name", "versionCode": "Version Code"}
                    for k, v in sorted(axml["manifest"].items()):
                        if not k.startswith("android:"):
                            self.add("apk", pretty.get(k, "Manifest: " + k), v)
                    us = axml.get("uses_sdk", {})
                    for k in ("minSdkVersion", "targetSdkVersion"):
                        if k in us:
                            self.add("apk", {"minSdkVersion": "Minimum SDK (API)", "targetSdkVersion": "Target SDK (API)"}[k], us[k])
                    clabels = {"activity": "Activities Declared", "service": "Services Declared",
                               "receiver": "Receivers Declared", "provider": "Providers Declared"}
                    for cname, cnt in sorted(axml["counts"].items()):
                        self.add("apk", clabels.get(cname, cname), str(cnt))
                    if axml["features"]:
                        self.add("apk", "Uses Features", "\n".join(axml["features"][:40]))
                    if axml["permissions"]:
                        perms = sorted(set(axml["permissions"]))
                        self.add("apk", "Requested Permissions", "\n".join(perms[:80]) + ("\n... and %d more" % (len(perms) - 80) if len(perms) > 80 else ""))
                elif "AndroidManifest.xml" in names:
                    raw = z.read("AndroidManifest.xml")
                    perms = sorted(set(re.findall(rb"android\.permission\.[A-Z_]+", raw)))
                    if perms:
                        self.add("apk", "Requested Permissions (heuristic)", "\n".join(p.decode() for p in perms[:60]))
                    self.warnings.append("Binary manifest (AXML) could not be fully parsed; only structural findings are shown.")
        except Exception as e:
            self.warnings.append("APK could not be inspected: %s" % e)

    def extract_ole(self):
        if not HAVE_OLEFILE:
            self.add("ole", "Container", "OLE compound file (DOC/XLS/PPT/MSI). Install 'olefile' for property extraction: pip install olefile")
            self.warnings.append("Legacy OLE property extraction needs the optional olefile package.")
            return
        try:
            ole = olefile.OleFileIO(self.path)
            streams = ole.listdir()
            self.add("ole", "OLE Streams", "%d stream(s): %s" % (len(streams), ", ".join("/".join(s) for s in streams[:25])))
            try:
                md = ole.get_metadata()
                for attr, label in [("title", "Title"), ("subject", "Subject"), ("author", "Author"),
                                    ("last_saved_by", "Last Saved By"), ("company", "Company"),
                                    ("create_time", "Created (internal)"), ("last_saved_time", "Modified (internal)"),
                                    ("num_pages", "Pages"), ("num_words", "Words")]:
                    v = getattr(md, attr, None)
                    if v:
                        self.add("ole", label, iso_ts(str(v)) if "time" in attr else str(v))
            except Exception:
                pass
            ole.close()
        except Exception as e:
            self.warnings.append("OLE parse failed: %s" % e)

    def extract_exe(self):
        try:
            with open(self.path, "rb") as f:
                data = f.read(MAX_SCAN)
            res = parse_pe(data, self.path)
            if res:
                for k, v in res.items():
                    self.add("exe", k, v)
            if not HAVE_PEFILE:
                self.warnings.append("pefile is not installed \u2014 version resources and imports are limited. Run: pip install pefile")
        except Exception as e:
            self.warnings.append("PE structure could not be parsed: %s" % e)

    def extract_elf(self):
        try:
            with open(self.path, "rb") as f:
                data = f.read(4096)
            res = parse_elf(data)
            if res:
                for k, v in res.items():
                    self.add("elf", k, v)
        except Exception as e:
            self.warnings.append("ELF parse failed: %s" % e)

    def extract_media(self):
        audio = self.det["mime"].startswith("audio/") or self.det["ext"] in (".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".aiff", ".opus")
        self.preview = {"type": "audio" if audio else "video", "mime": self.det["mime"]}
        if self.det.get("brand"):
            self.add("media", "Container Major Brand", self.det["brand"])
        if FFPROBE:
            self._ffprobe()
        elif not audio:
            self.warnings.append("FFmpeg (ffprobe) is not installed \u2014 detailed video stream metadata is unavailable. Install FFmpeg and add it to PATH.")
        if not HAVE_MUTAGEN:
            self.warnings.append("mutagen is not installed \u2014 media tags are unavailable. Run: pip install mutagen")
            return
        try:
            f = MutagenFile(self.path)
        except Exception as e:
            self.warnings.append("Media file could not be parsed: %s" % e)
            return
        if f is None:
            return
        if f.info is not None:
            pretty = {"length": "Duration", "bitrate": "Bitrate", "sample_rate": "Sample Rate", "channels": "Channels",
                      "bits_per_sample": "Bits Per Sample", "codec": "Codec", "encoder_info": "Encoder", "mode": "Channel Mode"}
            for n in pretty.keys():
                if hasattr(f.info, n):
                    try:
                        v = getattr(f.info, n)
                    except Exception:
                        continue
                    if v is None:
                        continue
                    if n == "length":
                        try:
                            self.add("media", "Duration", "%d:%04.1f (%.1f seconds)" % (int(v // 60), v % 60, v))
                        except Exception:
                            pass
                    elif n == "bitrate":
                        try:
                            self.add("media", "Bitrate", "%d kbps" % round(v / 1000))
                        except Exception:
                            pass
                    elif n == "sample_rate":
                        self.add("media", "Sample Rate", "%d Hz" % v)
                    else:
                        self.add("media", pretty[n], to_str(v))
        tags = getattr(f, "tags", None)
        if tags:
            try:
                from mutagen.id3 import ID3 as _ID3
                is_id3 = isinstance(tags, _ID3)
            except Exception:
                is_id3 = False
            id3map = {"TIT2": "Title", "TPE1": "Artist", "TALB": "Album", "TDRC": "Date", "TCON": "Genre",
                      "TRCK": "Track Number", "TCOM": "Composer", "TPUB": "Publisher", "COMM": "Comment",
                      "USLT": "Lyrics", "TENC": "Encoded By", "TCOP": "Copyright", "TPOS": "Disc Number",
                      "TLAN": "Language", "TSRC": "ISRC", "TBPM": "BPM", "APIC": "Attached Picture"}
            for k, v in list(tags.items()):
                label = k if isinstance(k, str) else str(k)
                try:
                    if is_id3 and hasattr(v, "text") and v.__class__.__name__ not in ("APIC", "PRIV", "UFID"):
                        val = "; ".join(str(t) for t in v.text)[:500]
                        label = id3map.get(k, k)
                    elif is_id3 and v.__class__.__name__ == "APIC":
                        val = "%s picture, %d bytes" % (getattr(v, "mime", "?"), len(getattr(v, "data", b"")))
                        label = id3map.get(k, k)
                    elif isinstance(v, list):
                        val = "; ".join(fmt_bytes_value(x, 100) if isinstance(x, (bytes, bytearray)) else str(x) for x in v[:5])
                    elif isinstance(v, (bytes, bytearray)):
                        val = fmt_bytes_value(v)
                    else:
                        val = str(v)
                except Exception:
                    val = clamp(str(v), 300)
                self.add("media", label, clamp(val, 500))

    def _ffprobe(self):
        try:
            out = subprocess.run([FFPROBE, "-v", "quiet", "-print_format", "json",
                                  "-show_format", "-show_streams", self.path], capture_output=True, timeout=30)
            data = json.loads(out.stdout.decode("utf-8", "replace"))
            fmt = data.get("format", {})
            label_map = {"format_name": "Container Format", "duration": "Duration (s)", "size": "Container Size (s)", "bit_rate": "Bitrate (container)"}
            for k in ("format_name", "duration", "size", "bit_rate"):
                if k in fmt:
                    self.add("stream", label_map[k], to_str(fmt[k], 200))
            for tag_k, tag_v in list(fmt.get("tags", {}).items())[:20]:
                self.add("stream", "Container Tag: " + tag_k, to_str(tag_v, 300))
            for s in data.get("streams", [])[:8]:
                idx = s.get("index", "?")
                kind = s.get("codec_type", "?")
                summary = "codec=%s profile=%s %sx%s" % (s.get("codec_name", "?"), s.get("profile", "-"), s.get("width", "-"), s.get("height", "-"))
                if kind == "video":
                    summary += " fps=%s" % s.get("r_frame_rate", "-")
                elif kind == "audio":
                    summary += " rate=%s Hz ch=%s" % (s.get("sample_rate", "-"), s.get("channels", "-"))
                self.add("stream", "Stream #%s (%s)" % (idx, kind), summary)
                tags = s.get("tags", {}) or {}
                if tags.get("rotate"):
                    self.add("stream", "Rotation (stream %s)" % idx, tags["rotate"])
                if tags.get("language"):
                    self.add("stream", "Language (stream %s)" % idx, tags["language"])
        except Exception as e:
            self.warnings.append("ffprobe scan failed: %s" % e)

    def extract_text_like(self):
        with open(self.path, "rb") as f:
            raw = f.read(MAX_SCAN)
        enc, bom = "Latin-1 (assumed)", False
        if raw.startswith(b"\xef\xbb\xbf"):
            enc, bom = "UTF-8 with BOM", True
            text = raw[3:].decode("utf-8", "replace")
        elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            enc = "UTF-16"
            text = raw[2:].decode("utf-16", "replace")
        else:
            try:
                text = raw.decode("utf-8"); enc = "UTF-8"
            except Exception:
                text = raw.decode("latin-1")
        self.add("structure", "Encoding", enc)
        if bom:
            self.add("structure", "Byte-Order Mark", "Present")
        self.add("structure", "Line Count", str(text.count("\n") + 1))
        self.add("structure", "Word Count (approx.)", str(len(text.split())))
        self.add("structure", "Character Count", str(len(text)))
        ext = os.path.splitext(self.name)[1].lower()
        if ext.lstrip(".") in ("py", "js", "ts", "java", "c", "cpp", "h", "cs", "go", "rb", "php", "sh", "bat", "ps1", "sql", "md", "log", "ini", "cfg", "conf", "yaml", "yml", "toml"):
            self.add("structure", "Content Classification", "Source/config/log text (classified by filename convention; content verified as text)")
        fam = self.det["family"]
        if fam == "json":
            try:
                doc = json.loads(text)
                self.add("structure", "Root Type", "Object" if isinstance(doc, dict) else ("Array" if isinstance(doc, list) else type(doc).__name__))
                if isinstance(doc, dict):
                    keys = list(doc.keys())
                    self.add("structure", "Top-Level Keys", ", ".join(keys[:50]) + (" ..." if len(keys) > 50 else ""))
                count, depth = [0], [0]
                def walk(o, d):
                    count[0] += 1; depth[0] = max(depth[0], d)
                    if d > 60:
                        return
                    if isinstance(o, dict):
                        for v in o.values(): walk(v, d + 1)
                    elif isinstance(o, list):
                        for v in o[:200]: walk(v, d + 1)
                walk(doc, 1)
                self.add("structure", "Total Elements", str(count[0]))
                self.add("structure", "Max Depth", str(depth[0]))
            except Exception as e:
                self.warnings.append("JSON could not be parsed: %s" % e)
        elif fam == "xml":
            try:
                root = ET.fromstring(raw)
                self.add("structure", "Root Element", root.tag.split("}")[-1])
                elems = list(root.iter())
                self.add("structure", "Element Count", str(len(elems)))
                self.add("structure", "Attribute Count", str(sum(len(e.attrib) for e in elems)))
            except Exception as e:
                self.warnings.append("XML could not be parsed: %s" % e)
        elif fam == "rtf":
            m = re.search(rb"\{\\generator([^}]*)\}", raw)
            if m:
                self.add("structure", "Generator", m.group(1).decode("latin-1", "replace").strip())
        elif fam == "csv":
            try:
                sample = text[:8192]
                try:
                    delim = csv.Sniffer().sniff(sample).delimiter
                except Exception:
                    delim = ","
                self.add("structure", "Delimiter", repr(delim))
                rows = list(csv.reader(io.StringIO(text), delimiter=delim))
                if rows:
                    self.add("structure", "Column Names (header row)", ", ".join(c[:40] for c in rows[0][:50]))
                    self.add("structure", "Column Count", str(len(rows[0])))
                    self.add("structure", "Data Row Count", str(max(0, len(rows) - 1)))
            except Exception as e:
                self.warnings.append("CSV structure could not be parsed: %s" % e)
        elif fam == "html":
            try:
                class P(HTMLParser):
                    def __init__(self):
                        super().__init__()
                        self.title = ""; self._in_title = False
                        self.metas, self.og = [], []
                        self.counts = Counter()
                    def handle_starttag(self, tag, attrs):
                        self.counts[tag] += 1
                        if tag == "title":
                            self._in_title = True
                        d = dict(attrs)
                        if tag == "meta":
                            if d.get("property", "").startswith("og:"):
                                self.og.append((d["property"], d.get("content", "")[:150]))
                            elif d.get("name") in ("description", "keywords", "generator", "author"):
                                self.metas.append((d["name"], d.get("content", "")[:150]))
                    def handle_endtag(self, tag):
                        if tag == "title":
                            self._in_title = False
                    def handle_data(self, data):
                        if self._in_title and not self.title:
                            self.title = data.strip()[:200]
                p = P()
                p.feed(text[:400000])
                if p.title:
                    self.add("structure", "Title Tag", p.title)
                for nm, val in p.metas[:10]:
                    self.add("structure", "Meta: " + nm, val)
                for prop, val in p.og[:12]:
                    self.add("structure", "Open Graph: " + prop, val)
                for tag in ("script", "img", "a", "link", "iframe"):
                    if p.counts.get(tag):
                        self.add("structure", "Count of <%s> tags" % tag, str(p.counts[tag]))
            except Exception as e:
                self.warnings.append("HTML structure could not be parsed: %s" % e)
        elif fam == "txt" and ext == ".md":
            headings = re.findall(r"(?m)^#{1,6}\s+.+", text)
            links = re.findall(r"\[[^\]]+\]\([^)]+\)", text)
            self.add("structure", "Markdown Headings", str(len(headings)))
            if headings:
                self.add("structure", "Outline (first 10)", "\n".join(h[:60] for h in headings[:10]))
            self.add("structure", "Markdown Links", str(len(links)))

    def extract_sqlite(self):
        try:
            uri = "file:" + pathname2url(os.path.abspath(self.path)) + "?mode=ro"
            con = sqlite3.connect(uri, uri=True)
            cur = con.cursor()
            self.add("sqlite", "SQLite Library Version", sqlite3.sqlite_version)
            try:
                self.add("sqlite", "Page Size", str(cur.execute("PRAGMA page_size").fetchone()[0]) + " bytes")
                self.add("sqlite", "Text Encoding", str(cur.execute("PRAGMA encoding").fetchone()[0]))
            except Exception:
                pass
            tables = [r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            self.add("sqlite", "Tables", ", ".join(tables[:60]) if tables else "(no user tables)")
            for t in tables[:30]:
                if not re.match(r"^[\w ]+$", t):
                    continue
                try:
                    cols = [r[1] for r in cur.execute('PRAGMA table_info("%s")' % t.replace('"', '""'))]
                    cnt = cur.execute('SELECT COUNT(*) FROM "%s"' % t.replace('"', '""')).fetchone()[0]
                    self.add("sqlite", "Table: " + t, "%d rows; columns: %s" % (cnt, ", ".join(cols[:20])))
                except Exception:
                    pass
            idx = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")]
            if idx:
                self.add("sqlite", "Indexes", ", ".join(idx[:20]))
            con.close()
        except Exception as e:
            self.warnings.append("SQLite could not be inspected (read-only): %s" % e)

    def run(self):
        self.basic()
        fam = self.det["family"]
        try:
            if fam == "image":
                self.extract_image()
            elif fam == "pdf":
                self.extract_pdf()
            elif fam == "ooxml":
                self.extract_ooxml()
            elif fam == "odf":
                self.extract_odf()
            elif fam == "epub":
                self.extract_epub(); self.extract_zip()
            elif fam in ("zip", "jar"):
                self.extract_zip()
            elif fam in ("tar", "gz"):
                self.extract_tar()
            elif fam == "sevenz":
                self.extract_sevenz()
            elif fam == "rar":
                self.extract_rar()
            elif fam == "apk":
                self.extract_apk(); self.extract_zip()
            elif fam == "ole":
                self.extract_ole()
            elif fam == "exe":
                self.extract_exe()
            elif fam == "elf":
                self.extract_elf()
            elif fam == "media":
                self.extract_media()
            elif fam == "sqlite":
                self.extract_sqlite()
            elif fam in ("txt", "json", "xml", "rtf", "csv", "html"):
                self.extract_text_like()
            else:
                self.warnings.append("Format '%s' is not supported for deep extraction \u2014 only filesystem information is shown." % self.det["short"])
        except Exception as e:
            self.warnings.append("Extraction problem: %s" % e)
        if time.monotonic() - self._t0 > SLOW_EXTRACTION_SECONDS:
            self.warnings.append("Extraction took longer than %d s; results may be partial for very large files." % SLOW_EXTRACTION_SECONDS)
        self.groups = [g for g in self.groups if g["fields"]]
        return self.record()

    def record(self, token=None):
        # Terminal: real original path. Browser upload: NO path row at all.
        if self.source == "terminal":
            path_val, path_note = os.path.abspath(self.path), None
        else:
            path_val, path_note = None, None
        return {
            "token": token,
            "info": {"file_name": self.name, "badge": self.det["short"], "family": self.det["family"],
                     "mime": self.det["mime"], "size_h": size_str(self.size),
                     "created": ts(self.st.st_ctime), "modified": ts(self.st.st_mtime), "accessed": ts(self.st.st_atime),
                     "extension": os.path.splitext(self.name)[1].lstrip(".").lower(),
                     "path": path_val, "path_note": path_note, "source": self.source},
            "groups": self.groups, "gps": self.gps, "warnings": self.warnings,
            "preview": self.preview, "generated": datetime.now().strftime("%d %b %Y %H:%M:%S"),
        }

# ------------------------------------------------------------ metadata cleaning
def strip_jpeg_metadata(data):
    removed = []
    if data[:2] != b"\xff\xd8":
        return None, []
    out = bytearray(b"\xff\xd8")
    i, n = 2, len(data)
    while i + 1 < n:
        if data[i] != 0xFF:
            return None, []
        while i + 1 < n and data[i] == 0xFF and data[i + 1] == 0xFF:
            i += 1
        if i + 1 >= n:
            break
        marker = data[i + 1]
        if marker == 0xD9:
            out += b"\xff\xd9"; i += 2; break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            out += bytes([0xFF, marker]); i += 2; continue
        if i + 4 > n:
            return None, []
        seglen = int.from_bytes(data[i + 2:i + 4], "big")
        if seglen < 2:
            return None, []
        seg = data[i:i + 2 + seglen]
        if marker == 0xDA:
            out += seg
            j = i + 2 + seglen
            while j + 1 < n:
                if data[j] == 0xFF and data[j + 1] != 0x00 and not (0xD0 <= data[j + 1] <= 0xD7):
                    break
                j += 1
            out += data[i + 2 + seglen:j]
            i = j
            continue
        payload = seg[4:]
        drop = None
        if marker == 0xE1 and (payload.startswith(b"Exif\x00\x00") or payload.startswith(b"http://ns.adobe.com/xap/1.0/")):
            drop = "EXIF/XMP (APP1)"
        elif marker == 0xED:
            drop = "IPTC/Photoshop (APP13)"
        elif marker == 0xFE:
            drop = "Comment (COM)"
        elif marker == 0xE2 and payload[:11] == b"ICC_PROFILE":
            drop = "ICC Profile (APP2)"
        if drop:
            removed.append(drop)
        else:
            out += seg
        i += 2 + seglen
    if not out.endswith(b"\xff\xd9"):
        out += b"\xff\xd9"
    return bytes(out), removed

def strip_png_metadata(data):
    sig = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(sig):
        return None, []
    drop = {b"tEXt": "Text chunk (tEXt)", b"zTXt": "Compressed text (zTXt)", b"iTXt": "International text (iTXt)",
            b"eXIf": "EXIF chunk (eXIf)", b"tIME": "Modification time (tIME)"}
    out = bytearray(sig); i = 8; removed = []
    while i + 8 <= len(data):
        ln = int.from_bytes(data[i:i + 4], "big")
        typ = data[i + 4:i + 8]
        end = i + 12 + ln
        if end > len(data):
            return None, []
        if typ in drop:
            removed.append(drop[typ])
        else:
            out += data[i:end]
        i = end
        if typ == b"IEND":
            break
    return bytes(out), removed

def strip_webp_metadata(data):
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None, []
    out = bytearray(b"RIFF\x00\x00\x00\x00WEBP"); i = 12; removed = []
    while i + 8 <= len(data):
        cid = data[i:i + 4]
        cs = int.from_bytes(data[i + 4:i + 8], "little")
        end = i + 8 + cs + (cs % 2)
        if end > len(data):
            break
        if cid == b"EXIF":
            removed.append("EXIF chunk")
        elif cid == b"XMP ":
            removed.append("XMP chunk")
        else:
            out += data[i:end]
        i = end
    struct.pack_into("<I", out, 4, len(out) - 8)
    return bytes(out), removed

def clean_file(rec, stored_path):
    fam = rec["info"]["family"]
    ext = EXT_FOR.get(fam, ".bin")
    stem = os.path.splitext(safe_filename(rec["info"]["file_name"]))[0] or "file"
    out_name = stem + "_clean" + ext
    data = open(stored_path, "rb").read()
    removed, limitations = [], []

    def result(ok, data_bytes, message):
        return {"ok": ok, "message": message, "removed": removed, "limitations": limitations,
                "data": data_bytes, "filename": out_name}

    if fam == "image" and ext == ".jpg":
        cleaned, removed = strip_jpeg_metadata(data)
        if cleaned is None:
            im = Image.open(io.BytesIO(data))
            buf = io.BytesIO(); im.save(buf, "JPEG", quality=95)
            cleaned = buf.getvalue()
            removed = ["EXIF/APP metadata (via re-encode)"]
            limitations.append("Pixels were re-encoded (structure was not losslessly parseable).")
        return result(True, cleaned, "Cleaned JPEG produced; image pixels untouched (lossless segment removal).")
    if fam == "image" and ext == ".png":
        cleaned, removed = strip_png_metadata(data)
        if cleaned is None:
            return result(False, None, "PNG structure was not parseable; cleaning aborted to avoid a corrupt file.")
        return result(True, cleaned, "Cleaned PNG produced losslessly; pixel data untouched.")
    if fam == "image" and ext == ".webp":
        cleaned, removed = strip_webp_metadata(data)
        if cleaned is None:
            return result(False, None, "WebP structure was not parseable; cleaning aborted.")
        return result(True, cleaned, "Cleaned WebP produced losslessly; EXIF/XMP chunks removed.")
    if fam == "pdf" and HAVE_PYPDF:
        try:
            reader = PdfReader(io.BytesIO(data))
            writer = PdfWriter(); writer.append(reader); writer.add_metadata({})
            buf = io.BytesIO(); writer.write(buf)
            removed.append("Document information dictionary")
            limitations.append("XMP streams inside the document may remain.")
            return result(True, buf.getvalue(), "Cleaned PDF produced without its metadata dictionary.")
        except Exception as e:
            return result(False, None, "PDF cleaning failed: %s" % e)
    if fam in ("ooxml", "odf", "zip", "jar", "epub"):
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(buf, "w") as zout:
                for item in zin.infolist():
                    payload = zin.read(item.filename)
                    if fam == "ooxml" and item.filename == "docProps/core.xml":
                        zout.writestr(item.filename, b'<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title></dc:title><dc:creator></dc:creator><cp:lastModifiedBy></cp:lastModifiedBy></cp:coreProperties>')
                        removed.append("Core properties (author, dates)"); continue
                    if fam == "ooxml" and item.filename == "docProps/app.xml":
                        zout.writestr(item.filename, b'<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application></Application><Company></Company></Properties>')
                        removed.append("Extended properties"); continue
                    if fam == "ooxml" and item.filename.startswith("docProps/thumbnail"):
                        removed.append("Document thumbnail"); continue
                    if fam == "odf" and item.filename == "meta.xml":
                        zout.writestr(item.filename, b'<?xml version="1.0"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><office:meta/></office:document-meta>')
                        removed.append("ODF meta.xml properties"); continue
                    zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                    zi.compress_type = item.compress_type
                    zi.external_attr = item.external_attr
                    zout.writestr(zi, payload)
            limitations.append("Entry timestamps are part of the archive format and were preserved.")
            return result(True, buf.getvalue(), "Cleaned package produced; content unchanged.")
        except Exception as e:
            return result(False, None, "Package cleaning failed: %s" % e)
    if fam == "media" and HAVE_MUTAGEN:
        tmp_in = os.path.join(UPLOAD_DIR, "clean_tmp_%s%s" % (uuid.uuid4().hex[:8], ext))
        try:
            shutil.copy(stored_path, tmp_in)
            m = MutagenFile(tmp_in)
            if m is None or m.tags is None:
                return result(True, data, "No removable tags found; identical copy provided.")
            m.delete()
            cleaned = open(tmp_in, "rb").read()
            removed.append("Embedded tags")
            return result(True, cleaned, "Cleaned media file produced; audio/video streams untouched.")
        except Exception as e:
            return result(False, None, "Media cleaning failed: %s" % e)
        finally:
            try:
                os.remove(tmp_in)
            except Exception:
                pass
    if fam == "apk":
        return result(False, None, "APK cleaning is disabled: rebuilding invalidates signing blocks and would break the package.")
    if fam in ("exe", "elf"):
        return result(False, None, "Executable cleaning is disabled: removing embedded version resources risks corrupting the binary.")
    return result(False, None, "Cleaning is not supported for the detected format '%s'." % rec["info"]["badge"])

# ------------------------------------------------------------ reports
def _cell(v):
    return html_mod.escape(str(v))

def build_html_report(records):
    parts = ["""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Metadata Report</title>
<style>
 body{background:#0a0f1e;color:#e5eefb;font-family:'Segoe UI',system-ui,Arial,sans-serif;margin:0;padding:24px}
 h1{color:#fff;font-size:30px;margin:0}h1 span{color:#ef4444}
 .sub{color:#38bdf8;margin:4px 0 24px}
 h2{color:#7fb3ff;border-bottom:1px solid #1d2b45;padding-bottom:8px;margin-top:36px}
 h3{color:#bcd3f5;margin:22px 0 8px}
 table{border-collapse:collapse;width:100%;font-size:13px;margin-bottom:8px}
 th{background:#16233c;color:#dce7f7;text-align:left;padding:9px 10px;border:1px solid #1d2b45}
 td{padding:8px 10px;border:1px solid #1d2b45;vertical-align:top}
 tr:nth-child(even) td{background:#0d1526}
 tr.grp td{background:#132242!important;color:#7fb3ff;font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
 .kv td:first-child{color:#8aa0bf;width:180px}
 .warn{background:#3a1d1d;border:1px solid #7f1d1d;border-radius:8px;padding:10px 14px;margin:12px 0;color:#fca5a5}
 .gps{background:#0d1b2e;border:1px solid #1d4ed8;border-radius:8px;padding:10px 14px;margin:12px 0;color:#93c5fd}
 .foot{color:#5f7a9d;margin-top:36px;font-size:12.5px}
 img.prev{max-width:380px;border-radius:8px;border:1px solid #1d2b45;margin:10px 0}
 .val{white-space:pre-wrap;word-break:break-word}
 .exp{color:#8aa0bf;font-size:11.5px;margin-top:4px;font-weight:400;line-height:1.5}
</style></head><body>
<h1>Metadata <span>Tool</span></h1><div class="sub">Universal File Metadata Extractor</div>
"""]
    parts.append('<div class="sub">Report generated: %s</div>' % _cell(datetime.now().strftime("%d %b %Y %H:%M:%S")))
    for rec in records:
        info = rec["info"]
        parts.append("<h2>%s</h2>" % _cell(info["file_name"]))
        rows = [("Detected Type", info["badge"]), ("MIME Type", info["mime"]), ("File Size", info["size_h"]),
                ("Created", info["created"]), ("Modified", info["modified"]), ("Accessed", info["accessed"]),
                ("Extraction Date", rec.get("generated", ""))]
        if info.get("path"):
            rows.append(("File Path", info["path"]))
        parts.append('<table class="kv">')
        for k, v in rows:
            parts.append("<tr><td>%s</td><td class='val'>%s</td></tr>" % (_cell(k), _cell(v)))
        parts.append("</table>")
        for w in rec.get("warnings", []):
            parts.append('<div class="warn">[!] %s</div>' % _cell(w))
        if rec.get("gps"):
            g = rec["gps"]
            parts.append('<div class="gps">GPS coordinates present: %.6f, %.6f \u2014 review before sharing this file.</div>' % (g["latitude"], g["longitude"]))
        if rec.get("preview", {}).get("type") == "image" and rec.get("preview_b64"):
            parts.append('<img class="prev" src="data:%s;base64,%s" alt="preview">' % (_cell(rec["preview"]["mime"]), rec["preview_b64"]))
        parts.append("<h3>All Metadata</h3>")
        parts.append("<table><tr><th style='width:320px'>Metadata Field</th><th>Extracted Value</th></tr>")
        for g in rec["groups"]:
            parts.append("<tr class='grp'><td colspan='2'>%s \u2014 %d fields \u00b7 %s</td></tr>" % (
                _cell(g["name"]), len(g["fields"]), _cell(g.get("kind", ""))))
            for f in g["fields"]:
                exp = ("<div class='exp'>%s</div>" % _cell(f["explanation"])) if f.get("explanation") else ""
                parts.append("<tr><td>%s</td><td class='val'>%s%s</td></tr>" % (_cell(f["field"]), _cell(f["value"]), exp))
        parts.append("</table>")
    parts.append('<div class="foot">Generated locally by the Metadata Tool. Values reflect only what was actually extracted; '
                 'absence of a field means it was not present in the file or the required parser is not installed. '
                 'The AI result is an indicator-based scan, not proof. Nothing is invented.</div>')
    parts.append("</body></html>")
    return "\n".join(parts)

def _pdf_safe(s):
    s = str(s)
    try:
        s.encode("latin-1")
        return s
    except Exception:
        return s.encode("latin-1", "replace").decode("latin-1")

def build_pdf_report(records):
    if not HAVE_REPORTLAB:
        return None
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="Metadata Report", author="Metadata Tool",
                            leftMargin=36, rightMargin=36, topMargin=42, bottomMargin=42)
    h1 = ParagraphStyle("h1", fontSize=22, textColor=rl_colors.HexColor("#0f172a"), spaceAfter=2)
    h2 = ParagraphStyle("h2", fontSize=13, textColor=rl_colors.HexColor("#1d4ed8"), spaceBefore=6, spaceAfter=6)
    h3 = ParagraphStyle("h3", fontSize=11, textColor=rl_colors.HexColor("#334155"), spaceBefore=10, spaceAfter=4)
    cell = ParagraphStyle("cell", fontSize=8, leading=10.5)
    cellm = ParagraphStyle("cellm", fontSize=8, leading=10.5, textColor=rl_colors.HexColor("#475569"))
    grph = ParagraphStyle("grph", fontSize=8, leading=10.5, textColor=rl_colors.HexColor("#1d4ed8"))

    def P(t, st=cell):
        return Paragraph(html_mod.escape(_pdf_safe(t)).replace("\n", "<br/>"), st)

    story = [Paragraph("Metadata Report", h1),
             Paragraph("Universal File Metadata Extractor \u2014 generated %s" % datetime.now().strftime("%d %b %Y %H:%M:%S"), cellm),
             Spacer(1, 10)]
    for rec in records:
        info = rec["info"]
        story.append(Paragraph(_pdf_safe(info["file_name"]), h2))
        kv = [["Field", "Value"], ["Detected Type", info["badge"]], ["MIME Type", info["mime"]], ["File Size", info["size_h"]],
              ["Created", info["created"]], ["Modified", info["modified"]], ["Extraction Date", rec.get("generated", "")]]
        if info.get("path"):
            kv.append(["File Path", info["path"]])
        t = Table([[P(r[0]), P(r[1])] for r in kv], colWidths=[130, 385], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#16233c")),
                               ("GRID", (0, 0), (-1, -1), 0.4, rl_colors.HexColor("#94a3b8")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
        for w in rec.get("warnings", []):
            story.append(Paragraph("[!] " + html_mod.escape(_pdf_safe(w)), cellm))
        story.append(Paragraph("All Metadata", h3))
        rows = [["Metadata Field", "Extracted Value"]]
        expst = ParagraphStyle("exp", parent=cellm, fontSize=6.8, leading=8.5)
        for g in rec["groups"]:
            rows.append([Paragraph(_pdf_safe("%s (%d)" % (g["name"], len(g["fields"]))), grph), ""])
            for f in g["fields"]:
                inner = [P(f["value"])]
                if f.get("explanation"):
                    inner.append(Paragraph(html_mod.escape(_pdf_safe(f["explanation"])), expst))
                rows.append([P(f["field"]), inner])
        t = Table(rows, colWidths=[180, 335], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#16233c")),
                               ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
                               ("GRID", (0, 0), (-1, -1), 0.4, rl_colors.HexColor("#94a3b8")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("ROWBACKGROUNDS", (0, 1), (-1, -1), [rl_colors.white, rl_colors.HexColor("#f4f7fb")])]))
        story.append(t)
    try:
        doc.build(story)
        return buf.getvalue()
    except Exception:
        traceback.print_exc()
        return None

# ------------------------------------------------------------ server
RESULTS = {}
RESULTS_LOCK = threading.Lock()

def store_result(rec, stored_path):
    token = uuid.uuid4().hex[:24]
    rec["token"] = token
    with RESULTS_LOCK:
        RESULTS[token] = {"record": rec, "file": stored_path, "time": time.time()}
    return token

def cleanup_worker():
    while True:
        time.sleep(1800)
        cutoff = time.time() - 6 * 3600
        with RESULTS_LOCK:
            for t in [t for t, v in RESULTS.items() if v["time"] < cutoff]:
                try:
                    os.remove(RESULTS[t]["file"])
                except Exception:
                    pass
                del RESULTS[t]

def _dumps(obj):
    return json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")

def parse_multipart(body, content_type):
    m = re.search(r'boundary="?([^";]+)"?', content_type)
    if not m:
        raise ValueError("Missing multipart boundary")
    delim = b"--" + m.group(1).encode("latin-1")
    files = []
    for part in body.split(delim)[1:]:
        if part.startswith(b"--"):
            break
        part = part.lstrip(b"\r\n")
        if part.endswith(b"\r\n"):
            part = part[:-2]
        head, _, content = part.partition(b"\r\n\r\n")
        disp = ""
        for line in head.split(b"\r\n"):
            if b":" in line:
                k, v = line.split(b":", 1)
                if k.decode("latin-1").strip().lower() == "content-disposition":
                    disp = v.decode("latin-1").strip()
        fm = re.search(r'filename="([^"]*)"', disp)
        if fm:
            files.append({"filename": fm.group(1), "content": content})
    return files

def extract_uploaded(up):
    if not up["content"]:
        return None, "Uploaded file is empty."
    token_pre = uuid.uuid4().hex[:12]
    tmp = os.path.join(UPLOAD_DIR, "up_%s.tmp" % token_pre)
    with open(tmp, "wb") as f:
        f.write(up["content"])
    det = detect_format(tmp)
    if det["family"] == "unknown":
        try: os.remove(tmp)
        except Exception: pass
        return None, "Unsupported format: '%s' is not a supported file type." % safe_filename(up["filename"])
    final = os.path.join(UPLOAD_DIR, "up_%s%s" % (token_pre, det["ext"]))
    os.replace(tmp, final)
    rec = Extractor(final, det, original_name=safe_filename(up["filename"]), source="upload").run()
    store_result(rec, final)
    return rec, None

class Handler(BaseHTTPRequestHandler):
    server_version = "MetadataTool/" + VERSION
    protocol_version = "HTTP/1.0"
    timeout = 90

    def log_message(self, fmt, *args):
        try:
            sys.stderr.write(C.YELLOW + "[http] " + (fmt % args) + C.RESET + "\n")
            sys.stderr.flush()
        except Exception:
            pass

    def _headers(self, code, ctype, length, download_name=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        if download_name:
            safe = quote(download_name)
            self.send_header("Content-Disposition", "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (safe.replace('"', ""), safe))
        self.end_headers()

    def _json(self, code, obj):
        try:
            payload = _dumps(obj)
            self._headers(code, "application/json; charset=utf-8", len(payload))
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc()

    def _bytes(self, code, data, ctype, download_name=None):
        try:
            self._headers(code, ctype, len(data), download_name)
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc()

    def _fail(self, code, msg):
        try:
            self._json(code, {"error": msg})
        except Exception:
            try:
                self.send_error(code, str(msg)[:200])
            except Exception:
                pass

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path in ("/", "/index.html"):
                try:
                    with open(HTML_FILE, "rb") as f:
                        self._bytes(200, f.read(), "text/html; charset=utf-8")
                except Exception as e:
                    self._fail(500, "metadata.html could not be loaded: %s" % e)
                return
            if path == "/favicon.ico":
                self._bytes(200, b"", "image/x-icon"); return
            if path == "/api/ping":
                self._json(200, {"ok": True, "version": VERSION, "app": APP_NAME}); return
            if path == "/api/capabilities":
                self._json(200, {
                    "pillow": HAVE_PIL, "mutagen": HAVE_MUTAGEN, "pypdf": HAVE_PYPDF,
                    "pefile": HAVE_PEFILE, "olefile": HAVE_OLEFILE, "py7zr": HAVE_PY7ZR,
                    "rarfile": HAVE_RARFILE, "reportlab": HAVE_REPORTLAB,
                    "ffprobe": bool(FFPROBE), "exiftool": bool(EXIFTOOL), "version": VERSION})
                return
            m = re.match(r"^/api/preview/([0-9a-f]{24})$", path)
            if m:
                with RESULTS_LOCK:
                    entry = RESULTS.get(m.group(1))
                if not entry:
                    self._fail(404, "Unknown or expired result token."); return
                rec = entry["record"]
                if rec["preview"]["type"] == "none":
                    self._fail(404, "No preview available for this format."); return
                try:
                    with open(entry["file"], "rb") as f:
                        data = f.read()
                except Exception as e:
                    self._fail(500, "Preview read failed: %s" % e); return
                mime = rec["preview"].get("mime") or "application/octet-stream"
                if rec["preview"]["type"] == "text":
                    mime = "text/plain; charset=utf-8"
                    data = data[:2000000]
                self._bytes(200, data, mime)
                return
            m = re.match(r"^/api/report/(batch|([0-9a-f]{24}))/(html|pdf)$", path)
            if m:
                kind, token, fmt = m.group(1), m.group(2), m.group(3)
                recs = []
                if kind == "batch":
                    tokens = (parse_qs(parsed.query).get("tokens", [""])[0] or "").split(",")
                    with RESULTS_LOCK:
                        recs = [RESULTS[t.strip()]["record"] for t in tokens if t.strip() in RESULTS]
                    if not recs:
                        self._fail(404, "No valid tokens for batch report."); return
                else:
                    with RESULTS_LOCK:
                        entry = RESULTS.get(token)
                    if not entry:
                        self._fail(404, "Unknown or expired result token."); return
                    recs = [entry["record"]]
                    if recs[0].get("preview", {}).get("type") == "image":
                        try:
                            img = open(entry["file"], "rb").read()
                            if len(img) <= 4 * 1024 * 1024:
                                import base64
                                recs[0]["preview_b64"] = base64.b64encode(img).decode("ascii")
                        except Exception:
                            pass
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                if fmt == "html":
                    self._bytes(200, build_html_report(recs).encode("utf-8"), "text/html; charset=utf-8", "Metadata_Report_%s.html" % stamp)
                else:
                    pdf = build_pdf_report(recs)
                    if pdf is None:
                        self._fail(503, "PDF generation requires reportlab. Run: pip install reportlab"); return
                    self._bytes(200, pdf, "application/pdf", "Metadata_Report_%s.pdf" % stamp)
                return
            m = re.match(r"^/api/clean-info/([0-9a-f]{24})$", path)
            if m:
                with RESULTS_LOCK:
                    entry = RESULTS.get(m.group(1))
                if not entry:
                    self._fail(404, "Unknown or expired result token."); return
                try:
                    res = clean_file(entry["record"], entry["file"])
                except Exception as e:
                    traceback.print_exc()
                    self._fail(500, "Cleaning failed unexpectedly: %s" % e); return
                res.pop("data", None)
                self._json(200, res)
                return
            m = re.match(r"^/api/clean/([0-9a-f]{24})$", path)
            if m:
                with RESULTS_LOCK:
                    entry = RESULTS.get(m.group(1))
                if not entry:
                    self._fail(404, "Unknown or expired result token."); return
                try:
                    res = clean_file(entry["record"], entry["file"])
                except Exception as e:
                    traceback.print_exc()
                    self._fail(500, "Cleaning failed unexpectedly: %s" % e); return
                if not res["ok"] or not res["data"]:
                    self._fail(400, res["message"]); return
                self._bytes(200, res["data"], "application/octet-stream", res["filename"])
                return
            self._fail(404, "Not found.")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            traceback.print_exc()
            self._fail(500, "Internal server error: %s" % e)

    def do_POST(self):
        try:
            path = urlparse(self.path).path
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
            except Exception:
                length = 0
            if length > MAX_UPLOAD_BYTES:
                self.close_connection = True
                self._fail(413, "File too large. Limit is %d MB." % MAX_UPLOAD_MB); return
            try:
                body = self.rfile.read(length) if length else b""
            except Exception as e:
                self._fail(400, "Could not read upload body: %s" % e); return
            if path != "/api/extract":
                self._fail(404, "Not found."); return
            ctype = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in ctype:
                self._fail(400, "Expected multipart form upload."); return
            try:
                files = parse_multipart(body, ctype)
            except Exception as e:
                self._fail(400, "Malformed upload: %s" % e); return
            if not files:
                self._fail(400, "No file received."); return
            results, errors = [], []
            for up in files[:10]:
                rec, err = extract_uploaded(up)
                if err:
                    errors.append({"file": safe_filename(up["filename"]), "error": err})
                elif rec is not None:
                    results.append(rec)
            if not results and errors:
                self._json(415, {"error": errors[0]["error"], "errors": errors}); return
            if len(results) == 1 and not errors:
                self._json(200, results[0]); return
            self._json(200, {"batch": True, "results": results, "errors": errors})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            traceback.print_exc()
            self._fail(500, "Internal server error: %s" % e)

# ------------------------------------------------------------ terminal
def terminal_detect_line(path, det):
    print(C.WHITE + "File" + C.GRAY + " " * 6 + ": " + C.RESET + C.WHITE + os.path.abspath(path) + C.RESET)
    print(C.WHITE + "Type" + C.GRAY + " " * 6 + ": " + C.RESET + C.GREEN + det["short"] + C.RESET)
    print(C.WHITE + "Size" + C.GRAY + " " * 6 + ": " + C.RESET + C.CYAN + size_str(os.stat(path).st_size) + C.RESET)
    print(C.GRAY + "-" * 72 + C.RESET)

def open_in_browser(path):
    try:
        webbrowser.open("file:///" + os.path.abspath(path).replace("\\", "/"))
        return True
    except Exception:
        return False

def extract_flow():
    try:
        raw = input(C.CYAN + "\nEnter file path (file or folder): " + C.RESET)
    except (KeyboardInterrupt, EOFError):
        print("\n" + C.YELLOW + "[!] Cancelled." + C.RESET)
        return
    target = raw.strip().strip('"').strip("'")
    if not target or not os.path.exists(target):
        print(C.RED + "[!] Path does not exist: %s" % target + C.RESET)
        return
    records, files = [], []
    if os.path.isdir(target):
        skip_dirs = {REPORTS_DIR, UPLOAD_DIR}
        for root, dirs, names in os.walk(target):
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in skip_dirs]
            for n in sorted(names):
                files.append(os.path.join(root, n))
                if len(files) >= 200:
                    break
            if len(files) >= 200:
                break
    else:
        files = [target]
    if not files:
        print(C.YELLOW + "[!] No files found." + C.RESET)
        return
    for fp in files:
        try:
            det = detect_format(fp)
            if det["family"] == "unknown":
                print(C.YELLOW + "[!] Skipped unsupported: %s" % fp + C.RESET)
                continue
            print()
            terminal_detect_line(fp, det)
            print(C.CYAN + "[+] Reading file..." + C.RESET)
            print(C.CYAN + "[+] Extracting metadata..." + C.RESET)
            records.append(Extractor(fp, det, source="terminal").run())
            n = sum(len(g["fields"]) for g in records[-1]["groups"])
            print(C.GREEN + "[+] %d fields extracted" % n + C.RESET)
        except Exception as e:
            print(C.RED + "[!] Failed on %s: %s" % (fp, e) + C.RESET)
    if not records:
        print(C.RED + "[!] No metadata could be extracted. Report was not generated." + C.RESET)
        return
    print(C.CYAN + "[+] Generating report..." + C.RESET)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    out = os.path.join(REPORTS_DIR, "Metadata_Report_%s.html" % datetime.now().strftime("%Y%m%d_%H%M%S"))
    try:
        with open(out, "w", encoding="utf-8") as f:
            f.write(build_html_report(records))
    except Exception as e:
        print(C.RED + "[!] Report could not be saved: %s" % e + C.RESET)
        return
    print(C.CYAN + "[+] Metadata extraction completed!" + C.RESET)
    print(C.YELLOW + "\nReport saved to : " + C.GREEN + out + C.RESET)
    try:
        ans = input(C.WHITE + "Open report in browser? (Y/n): " + C.RESET).strip().lower()
    except (KeyboardInterrupt, EOFError):
        ans = "n"
    if ans in ("", "y", "yes"):
        print(C.CYAN + "Opening browser..." + C.RESET)
        if not open_in_browser(out):
            print(C.RED + "[!] Open manually: %s" % out + C.RESET)

def capability_matrix():
    def st(v, no="Optional Dependency Required"):
        return (C.GREEN + "Fully Supported" + C.RESET) if v else (C.YELLOW + no + C.RESET)
    print(C.CYAN + "\n[*] Capability matrix" + C.RESET)
    rows = [
        ("JPEG/PNG/GIF/BMP/TIFF/WebP/ICO + EXIF/IPTC/XMP/GPS", st(HAVE_PIL, no="Partial \u2014 needs Pillow")),
        ("AI File Detection (images, Yes/No)", C.GREEN + "Fully Supported (indicator-based, not proof)" + C.RESET),
        ("ExifTool deep scan (all vendor tags)", (C.GREEN + "Fully Supported" + C.RESET) if EXIFTOOL else (C.YELLOW + "Optional (exiftool binary)" + C.RESET)),
        ("MP3/WAV/FLAC/OGG/M4A tags", st(HAVE_MUTAGEN)),
        ("Video stream detail (MP4/MKV/AVI/WebM)", (C.GREEN + "Fully Supported" + C.RESET) if FFPROBE else (C.YELLOW + "Optional (FFmpeg)" + C.RESET)),
        ("PDF properties + cleaning", st(HAVE_PYPDF)),
        ("DOCX/XLSX/PPTX/ODF/EPUB/ZIP/JAR/TAR/GZ", C.GREEN + "Fully Supported (stdlib)" + C.RESET),
        ("7Z listing", (C.GREEN + "Fully Supported" + C.RESET) if HAVE_PY7ZR else (C.YELLOW + "Optional (py7zr)" + C.RESET)),
        ("RAR listing", (C.GREEN + "Fully Supported" + C.RESET) if HAVE_RARFILE else (C.YELLOW + "Optional (rarfile+unrar)" + C.RESET)),
        ("APK manifest (AXML static parse)", C.GREEN + "Fully Supported (never executed)" + C.RESET),
        ("EXE/DLL version info + imports", (C.GREEN + "Fully Supported" + C.RESET) if HAVE_PEFILE else (C.YELLOW + "Partial (pip install pefile)" + C.RESET)),
        ("Legacy DOC/XLS/PPT/MSI (OLE)", (C.GREEN + "Fully Supported" + C.RESET) if HAVE_OLEFILE else (C.YELLOW + "Optional (olefile)" + C.RESET)),
        ("ELF headers \u00b7 SQLite \u00b7 CSV/HTML/JSON/XML/MD", C.GREEN + "Fully Supported (stdlib)" + C.RESET),
        ("HEIC/AVIF", C.YELLOW + "Partial \u2014 depends on system libheif via Pillow" + C.RESET),
        ("PDF report generation", st(HAVE_REPORTLAB)),
    ]
    for name, status in rows:
        print("   %-52s %s" % (name, status))
    print()

# ------------------------------------------------------------ self-tests
def selftest():
    import tempfile
    results = []
    def t(name, cond):
        results.append((name, bool(cond)))
    def skipped(name):
        results.append((name + "  [SKIPPED]", True))
    td = tempfile.mkdtemp(prefix="metatest_")

    if HAVE_PIL:
        pai = os.path.join(td, "ai.jpg")
        ima = Image.new("RGB", (40, 40), (90, 20, 90))
        exa = Image.Exif(); exa[305] = "Stable Diffusion"
        ima.save(pai, exif=exa)
        rec_ai = Extractor(pai, detect_format(pai), source="terminal").run()
        ai_vals = {f["field"]: f["value"] for g in rec_ai["groups"] if g["id"] == "ai" for f in g["fields"]}
        t("AI: Stable Diffusion marker -> Yes", ai_vals.get("AI File Detected") == "Yes")

        p = os.path.join(td, "exif.jpg")
        im = Image.new("RGB", (60, 40), (10, 60, 130))
        ex = Image.Exif(); ex[271] = "Canon"; ex[272] = "EOS R5"; ex[306] = "2024:01:15 10:30:00"
        im.save(p, exif=ex)
        rec = Extractor(p, detect_format(p), source="terminal").run()
        labels = [f["field"] for g in rec["groups"] for f in g["fields"]]
        values = [f["value"] for g in rec["groups"] for f in g["fields"]]
        ai_vals2 = {f["field"]: f["value"] for g in rec["groups"] if g["id"] == "ai" for f in g["fields"]}
        t("AI: Canon EXIF only -> No", ai_vals2.get("AI File Detected") == "No")
        t("JPEG+EXIF: Make extracted", "Make" in labels and "Canon" in values)
        t("JPEG: value-aware explanation mentions device",
          any("Canon" in f.get("explanation", "") for g in rec["groups"] for f in g["fields"]))
        explens = [len(f.get("explanation", "").split()) for g in rec["groups"] for f in g["fields"]]
        t("JPEG: every field has an explanation", all(len(e) >= 8 for e in explens))
        up_rec = Extractor(p, detect_format(p), source="upload").run()
        t("JPEG: upload hides Path row entirely", up_rec["info"]["path"] is None)
        t("JPEG: no hashes category", all(g["id"] != "hashes" for g in rec["groups"]))

        pg = os.path.join(td, "gps.jpg")
        img = Image.new("RGB", (30, 30), (10, 130, 60))
        exg = Image.Exif()
        gps_ifd = exg.get_ifd(0x8825)
        gps_ifd[1] = "N"; gps_ifd[2] = ((28.0, 1), (36.0, 1), (50.04, 1))
        gps_ifd[3] = "E"; gps_ifd[4] = ((77.0, 1), (12.0, 1), (36.0, 1))
        img.save(pg, exif=exg)
        recg = Extractor(pg, detect_format(pg), source="terminal").run()
        gf = [f["field"] for g in recg["groups"] if g["id"] == "gps" for f in g["fields"]]
        gv = {f["field"]: f["value"] for g in recg["groups"] if g["id"] == "gps" for f in g["fields"]}
        t("GPS: only Latitude/Longitude shown", set(gf) <= {"GPS Latitude", "GPS Longitude"} and "GPS Latitude" in gf)
        t("GPS: no fake 0.000000", "0.000000" not in gv.get("GPS Latitude", ""))
        t("GPS: correct value", gv.get("GPS Latitude", "").startswith("28.613"))

        pz = os.path.join(td, "gps0.jpg")
        imz = Image.new("RGB", (20, 20), (0, 0, 0))
        exz = Image.Exif()
        gz = exz.get_ifd(0x8825)
        gz[1] = "N"; gz[2] = ((0, 1), (0, 1), (0, 1))
        gz[3] = "E"; gz[4] = ((0, 1), (0, 1), (0, 1))
        imz.save(pz, exif=exz)
        recz0 = Extractor(pz, detect_format(pz), source="terminal").run()
        gv0 = {f["field"]: f["value"] for g in recz0["groups"] if g["id"] == "gps" for f in g["fields"]}
        t("GPS: zero coords -> honest invalid message",
          "invalid" in gv0.get("GPS Coordinates", "").lower())

        p2 = os.path.join(td, "plain.jpg")
        Image.new("RGB", (40, 40), (5, 5, 5)).save(p2)
        rec_p = Extractor(p2, detect_format(p2), source="terminal").run()
        t("JPEG-no-EXIF: no empty EXIF group", "exif" not in [g["id"] for g in rec_p["groups"]])

        from PIL.PngImagePlugin import PngInfo
        p3 = os.path.join(td, "text.png")
        meta = PngInfo(); meta.add_text("Comment", "hello world")
        Image.new("RGB", (50, 50), (200, 10, 10)).save(p3, pnginfo=meta)
        rec3 = Extractor(p3, detect_format(p3), source="terminal").run()
        labels3 = [f["field"] for g in rec3["groups"] for f in g["fields"]]
        t("PNG+text: tEXt chunk extracted", "PNG Text: Comment" in labels3)
    else:
        skipped("JPEG/PNG fixtures (Pillow missing)")

    pzip = os.path.join(td, "multi.zip")
    with zipfile.ZipFile(pzip, "w") as z:
        z.writestr("docs/readme.txt", "hello")
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z2:
            z2.writestr("inner.txt", "nested")
        z.writestr("nested.zip", inner.getvalue())
    recz = Extractor(pzip, detect_format(pzip), source="terminal").run()
    lz = [f["field"] for g in recz["groups"] for f in g["fields"]]
    t("ZIP: listing + nested inspection", any("Full Entry Listing" in l for l in lz) and any("Nested Archive" in l for l in lz))

    pcsv = os.path.join(td, "t.csv")
    with open(pcsv, "w", encoding="utf-8") as fh:
        fh.write("name,age\nAlice,30\n")
    recc = Extractor(pcsv, detect_format(pcsv), source="terminal").run()
    t("CSV: header + row count", any(f["field"] == "Data Row Count" and f["value"] == "1" for g in recc["groups"] for f in g["fields"]))

    pdb = os.path.join(td, "t.sqlite")
    con = sqlite3.connect(pdb)
    con.execute("CREATE TABLE people (id INTEGER PRIMARY KEY, name TEXT)")
    con.execute("INSERT INTO people VALUES (1, 'x')")
    con.commit(); con.close()
    recdb = Extractor(pdb, detect_format(pdb), source="terminal").run()
    t("SQLite: table + rowcount (read-only)", any("Table: people" in f["field"] for g in recdb["groups"] for f in g["fields"]))

    recs = [r for r in ([rec] if HAVE_PIL else []) + [recz, recc, recdb] if r is not None]
    docrep = build_html_report(recs)
    t("HTML report: contains explanations", "camera" in docrep.lower() or "metadata" in docrep.lower())
    t("HTML report: escapes injection", "<script>" not in docrep)
    if HAVE_REPORTLAB:
        pdf = build_pdf_report(recs)
        t("PDF report: generated with %PDF header", bool(pdf) and pdf[:5] == b"%PDF-")
    else:
        skipped("PDF report (reportlab missing)")

    print()
    print(C.BOLD + "Metadata Tool \u2014 self-test v%s" % VERSION + C.RESET)
    print("-" * 62)
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        mark = (C.GREEN + "[PASS]  " + C.RESET) if ok else (C.RED + "[FAIL]  " + C.RESET)
        print("  %s%s" % (mark, name))
    print("-" * 62)
    print("  %d/%d checks passed." % (passed, len(results)))
    capability_matrix()
    try:
        shutil.rmtree(td, ignore_errors=True)
    except Exception:
        pass
    return 0 if passed == len(results) else 1

# ------------------------------------------------------------ main
def print_menu():
    print()
    print(" " + C.CYAN + "[1]" + C.RESET + " Extract Metadata")
    print(" " + C.CYAN + "[0]" + C.RESET + " Back")

def start_server():
    try:
        httpd = ThreadingHTTPServer((HOST, PORT), Handler)
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return True
    except OSError as e:
        print()
        print(C.RED + "[!] PORT %d IS BUSY \u2014 an old copy of this tool is probably still running." % PORT + C.RESET)
        print(C.YELLOW + "    Fix: taskkill /F /IM python.exe   then start again. (%s)" % e + C.RESET)
        print()
        return False

def main():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    if "--selftest" in sys.argv:
        return selftest()
    threading.Thread(target=cleanup_worker, daemon=True).start()
    print_banner()
    ok = start_server()
    url = "http://%s:%d" % (HOST, PORT)
    if ok:
        print(C.CYAN + "[*] Browser interface running at " + C.WHITE + url + C.RESET + C.CYAN + "  (v%s)" % VERSION + C.RESET)
        if "--no-browser" not in sys.argv:
            try:
                webbrowser.open(url)
            except Exception:
                pass
    capability_matrix()
    while True:
        print_menu()
        try:
            choice = input(C.WHITE + "\nEnter choice: " + C.RESET).strip()
        except (KeyboardInterrupt, EOFError):
            print("\n" + C.YELLOW + "[!] Interrupted \u2014 exiting cleanly." + C.RESET)
            return 0
        if choice == "1":
            extract_flow()
        elif choice == "0":
            print(C.CYAN + "\nGoodbye." + C.RESET)
            return 0
        else:
            print(C.RED + "[!] Invalid choice. Enter 1 or 0." + C.RESET)

if __name__ == "__main__":
    sys.exit(main())