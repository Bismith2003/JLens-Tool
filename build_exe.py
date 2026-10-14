"""
build_exe.py — JLens
============================================
Run this script on Windows to produce a self-contained JumpListForensics.exe

Usage:
    python build_exe.py

Requirements (auto-installed by this script):
    pip install pyinstaller reportlab olefile

The resulting .exe:
  - Embeds ALL Python dependencies (runs on ANY Windows PC — no Python needed)
  - Pure-Python EWF decoder (NO pyewf / C library required)
  - 1000+ AppID database (Spotify, Steam games, video editors, DAWs, etc.)
  - Multi-layer deleted file path reconstruction
  - Opens GUI on double-click
  - Can also be driven entirely from the command line

Output:  dist\\JLens.exe
"""

import subprocess
import sys
import os

TOOL_NAME   = "JLens"
MAIN_SCRIPT = "JLens.py"   # ← v4 script name

# ── Sanity check ────────────────────────────────────────────────────────────
if not os.path.exists(MAIN_SCRIPT):
    print(f"[ERROR] Main script '{MAIN_SCRIPT}' not found.")
    print(f"        Make sure {MAIN_SCRIPT} is in the same folder as this build script.")
    input("Press Enter to exit...")
    sys.exit(1)

def install(pkg):
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", pkg],
        stdout=subprocess.DEVNULL if "--quiet" in pkg else None,
    )

print("=" * 65)
print("  JLens v4.3 — EXE Builder")
print("=" * 65)
print()

# ── Install build dependencies ───────────────────────────────────────────────
for pkg in ["pyinstaller", "reportlab", "olefile"]:
    print(f"[*] Ensuring {pkg} is installed...")
    install(pkg)

print()
print("[*] Building standalone EXE with PyInstaller...")
print()

# ── PyInstaller command ──────────────────────────────────────────────────────
cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile",            # single .exe — easiest to distribute
    "--windowed",           # suppress console window on double-click (GUI mode)
    "--name", TOOL_NAME,
    "--icon", "NONE",

    # ── reportlab (PDF generation) ──────────────────────────────────────────
    "--hidden-import", "reportlab",
    "--hidden-import", "reportlab.lib",
    "--hidden-import", "reportlab.lib.pagesizes",
    "--hidden-import", "reportlab.lib.colors",
    "--hidden-import", "reportlab.lib.styles",
    "--hidden-import", "reportlab.lib.units",
    "--hidden-import", "reportlab.lib.enums",
    "--hidden-import", "reportlab.platypus",
    "--hidden-import", "reportlab.platypus.tables",
    "--hidden-import", "reportlab.platypus.flowables",
    "--hidden-import", "reportlab.platypus.paragraph",
    "--hidden-import", "reportlab.pdfgen",
    "--hidden-import", "reportlab.pdfgen.canvas",
    "--hidden-import", "reportlab.graphics",
    "--hidden-import", "reportlab.graphics.shapes",
    "--collect-all", "reportlab",

    # ── olefile (OLE/CFB compound file parser) ──────────────────────────────
    "--hidden-import", "olefile",
    "--collect-all", "olefile",

    # ── tkinter (GUI) ────────────────────────────────────────────────────────
    "--hidden-import", "tkinter",
    "--hidden-import", "tkinter.ttk",
    "--hidden-import", "tkinter.filedialog",
    "--hidden-import", "tkinter.messagebox",
    "--hidden-import", "tkinter.scrolledtext",
    "--hidden-import", "tkinter.font",

    # ── Python stdlib used by the tool ──────────────────────────────────────
    "--hidden-import", "struct",
    "--hidden-import", "hashlib",
    "--hidden-import", "logging",
    "--hidden-import", "logging.handlers",
    "--hidden-import", "threading",
    "--hidden-import", "queue",
    "--hidden-import", "datetime",
    "--hidden-import", "pathlib",
    "--hidden-import", "io",
    "--hidden-import", "zlib",
    "--hidden-import", "re",
    "--hidden-import", "os",
    "--hidden-import", "sys",
    "--hidden-import", "glob",
    "--hidden-import", "argparse",
    "--hidden-import", "traceback",

    MAIN_SCRIPT,
]

# ── Optional: pytsk3 for faster NTFS parsing ────────────────────────────────
# pytsk3 links against The Sleuth Kit C libraries. Including it makes NTFS
# traversal faster, but the tool works fine without it (pure-Python fallback).
try:
    import pytsk3
    cmd += ["--hidden-import", "pytsk3", "--collect-all", "pytsk3"]
    print("[+] pytsk3 found — bundling for faster NTFS parsing.")
except ImportError:
    print("[~] pytsk3 not found — pure-Python NTFS parser will be used (this is fine).")

print()

# ── Run PyInstaller ──────────────────────────────────────────────────────────
result = subprocess.run(cmd)

if result.returncode == 0:
    exe_path = os.path.join("dist", f"{TOOL_NAME}.exe")
    size_mb  = os.path.getsize(exe_path) / (1 << 20) if os.path.exists(exe_path) else 0

    print()
    print("=" * 65)
    print(f"[SUCCESS]  {exe_path}  ({size_mb:.1f} MB)")
    print()
    print("  Copy JLens.exe to any Windows machine and run.")
    print("  Double-click  →  GUI opens automatically.")
    print()
    print("  CLI examples:")
    print(f"    {TOOL_NAME}.exe --image C:\\Evidence\\disk.E01 --output report.pdf")
    print(f"    {TOOL_NAME}.exe --image C:\\Evidence\\disk.E01 --output report.pdf \\")
    print(f"                   --analyst \"Jane Smith\" --case CASE-2024-001")
    print(f"    {TOOL_NAME}.exe --live                    (analyse the current live PC)")
    print(f"    {TOOL_NAME}.exe --image C:\\Evidence\\disk.E01 --no-lnk  (skip LNK scan)")
    print("=" * 65)
else:
    print()
    print("[FAIL] PyInstaller build failed. Read the output above for details.")
    print()
    print("Common fixes:")
    print("  • Upgrade PyInstaller:  pip install --upgrade pyinstaller")
    print("  • Missing reportlab:    pip install reportlab")
    print("  • Missing olefile:      pip install olefile")
    print("  • UPX interfering:      add '--noupx' to the cmd list in this script")
    input("Press Enter to exit...")
    sys.exit(1)
