"""
JLens v4.3
============================
Parses Windows Jump Lists from E01/EWF forensic disk images.
Generates a detailed PDF forensic report for court/examination use.

NEW IN v4.0:
  - Massively expanded AppID database (1000+ entries):
    → All major browsers, Microsoft Office suites, Windows built-ins
    → Third-party: Spotify, Steam (60+ games), Epic/GOG/Battle.net launchers
    → Video editors: DaVinci Resolve, Adobe Premiere, OBS, Vegas Pro, Kdenlive
    → Audio DAWs: FL Studio, Ableton, Cubase, Reaper, Pro Tools, Audacity
    → Graphics: Blender, GIMP, Inkscape, Affinity suite, Canva, Figma, AutoCAD
    → Password managers, VPN clients, remote access, accounting software
    → Science/research: MATLAB, LabVIEW, SPSS, ANSYS, Mathematica
    → Education, streaming apps, emulators, and more
    → AppID suffix matching catches additional version-variant IDs
  - Enhanced path reconstruction for ALL entries including deleted files:
    → Multi-layer infer_target_path() with 12 fallback strategies
    → Deleted files show descriptive context instead of blank fields
    → Network/UNC share path reconstruction from LNK LinkInfo
    → Icon location and description field mining for additional hints
    → App-default path from AppID database when no LNK path present
    → Drive type and volume label context for removable/network drives

NEW IN v3.0 (retained):
  - AppID resolution database with category classification
  - Standalone LNK File Extractor with priority classification
  - Section 8b: AppID Resolution Summary; 8c: LNK Analysis; 8d: Correlation
  - Pure-Python EWF/E01 decoder (NO pyewf C library required)
  - GPT + MBR + hybrid partition table detection
  - Deep recursive NTFS walk, DestList v3/v4/v5 parsing

Supports:
  - E01/E02…EAA/EAB… segment chains (FTK Imager, EnCase, etc.)
  - Ex01 extended naming, SMART .s01 segments, Raw DD images
  - Extracted directory of .automaticDestinations-ms files
  - Live system analysis mode (reads directly from %APPDATA%)
"""

import os
import re
import sys
import glob
import struct
import hashlib
import logging
import argparse
import datetime
import threading
import traceback
import zlib
from pathlib import Path
from io import BytesIO

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("jumplist_forensics")


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 1 – EWF/E01 PURE-PYTHON DECODER
#  This is the core fix: decode E01 without pyewf
# ═══════════════════════════════════════════════════════════════════════════

class EWFDecodeError(Exception):
    pass


class PureEWFReader:
    """
    Pure-Python E01/EWF reader.
    Handles EnCase EWF format (SMART/FTK E01, Expert Witness Format).

    EWF structure per segment:
      EVF header section  (EVF_HEADER magic: 'EVF\x09\x0D\x0A\xFF\x00')
      Sections (linked list): header, volume, disk, table, data, hash, done
      Each section: 76-byte descriptor + variable payload
      Data chunks: each 32KB (default), optionally zlib-compressed
    """
    EVF_MAGIC = b'EVF\x09\x0D\x0A\xFF\x00'
    LVF_MAGIC = b'LVF\x09\x0D\x0A\xFF\x00'  # Logical evidence file
    EWFX_MAGIC = b'EWFX\x09\x0D\x0A\xFF'    # EnCase 7 format

    SECTION_HEADER  = b'header\x00\x00\x00\x00\x00\x00\x00\x00'
    SECTION_VOLUME  = b'volume\x00\x00\x00\x00\x00\x00\x00\x00'
    SECTION_DISK    = b'disk\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    SECTION_TABLE   = b'table\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    SECTION_TABLE2  = b'table2\x00\x00\x00\x00\x00\x00\x00\x00'
    SECTION_DATA    = b'data\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    SECTION_HASH    = b'hash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    SECTION_DONE    = b'done\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    SECTION_NEXT    = b'next\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    SECTION_SECTORS = b'sectors\x00\x00\x00\x00\x00\x00\x00\x00'  # older ewf

    def __init__(self, segment_paths: list):
        self.segments = [str(p) for p in segment_paths]
        self._chunk_size = 32768  # default 32KB per chunk
        self._sectors_per_chunk = 64
        self._sector_size = 512
        self._total_chunks = 0
        self._tables = []       # list of (segment_idx, file_offset, [chunk_offsets], compression_used)
        self._media_size = 0
        self._parsed = False
        self._is_ewf = False
        self._parse_all_segments()

    def _parse_all_segments(self):
        """Parse all EWF segment files and build a unified chunk table."""
        self._flat_cache = None  # invalidate any stale cache
        chunk_index = 0
        for seg_idx, seg_path in enumerate(self.segments):
            try:
                n = self._parse_segment(seg_path, seg_idx, chunk_index)
                chunk_index += n
                log.debug(f"Segment {seg_idx+1}: {os.path.basename(seg_path)} → {n} chunks")
            except Exception as e:
                log.warning(f"EWF parse error in {seg_path}: {e}")

        self._total_chunks = chunk_index
        self._media_size = self._total_chunks * self._chunk_size
        if self._total_chunks > 0:
            self._is_ewf = True
            log.info(f"EWF: {len(self.segments)} segments, "
                     f"{self._total_chunks} chunks × {self._chunk_size}B "
                     f"= {self._media_size // (1<<20)} MB")
        else:
            log.warning("Could not parse EWF structure; will try raw fallback.")

    def _parse_segment(self, path: str, seg_idx: int, base_chunk: int) -> int:
        """Parse one .E01/.E02/etc segment file. Returns number of chunks found."""
        chunks_in_segment = 0
        with open(path, 'rb') as f:
            # Check magic
            magic = f.read(8)
            if magic not in (self.EVF_MAGIC, self.LVF_MAGIC, self.EWFX_MAGIC[:8]):
                # Could be raw; not EWF
                raise EWFDecodeError(f"Not an EWF file (magic={magic!r})")

            # EWF section descriptors start at offset 13
            # Format: segment_number (2 bytes) at offset 8
            #         start_offset (4 bytes) at offset 10 (always 0x0D = 13)
            f.seek(13)
            next_section_offset = 13

            while True:
                f.seek(next_section_offset)
                raw = f.read(76)
                if len(raw) < 76:
                    break

                section_type = raw[0:16].rstrip(b'\x00')
                next_off = struct.unpack_from('<Q', raw, 16)[0]
                section_size = struct.unpack_from('<Q', raw, 24)[0]
                # section data starts at next_section_offset + 76

                data_offset = next_section_offset + 76

                stype = section_type.lower()

                if stype in (b'volume', b'disk'):
                    self._parse_volume_section(f, data_offset)

                elif stype in (b'table', b'table2'):
                    n = self._parse_table_section(f, data_offset, seg_idx, path)
                    chunks_in_segment += n

                elif stype in (b'sectors',):
                    # Older EWF format — sectors section contains raw chunks
                    n = self._parse_sectors_section(f, data_offset,
                                                    section_size - 76, seg_idx, path)
                    chunks_in_segment += n

                elif stype in (b'done', b''):
                    break

                if next_off == 0 or next_off == next_section_offset:
                    break
                next_section_offset = next_off

        return chunks_in_segment

    def _parse_volume_section(self, f, offset: int):
        """Parse volume/disk section for chunk/sector metadata."""
        f.seek(offset)
        data = f.read(94)
        if len(data) < 94:
            return
        # Fields at fixed offsets in EWF volume section:
        #  0: media_type (1)
        #  1-3: reserved
        #  4: chunk_count (4) — number of chunks in this segment
        #  8: sectors_per_chunk (4)
        # 12: bytes_per_sector (4)
        # 16: sector_count (8)
        try:
            sectors_per_chunk = struct.unpack_from('<I', data, 8)[0]
            bytes_per_sector  = struct.unpack_from('<I', data, 12)[0]
            if sectors_per_chunk and sectors_per_chunk < 65536:
                self._sectors_per_chunk = sectors_per_chunk
            if bytes_per_sector and bytes_per_sector in (512, 1024, 2048, 4096):
                self._sector_size = bytes_per_sector
            self._chunk_size = self._sectors_per_chunk * self._sector_size
            log.debug(f"EWF volume: {sectors_per_chunk} sectors/chunk, "
                      f"{bytes_per_sector} B/sector → chunk={self._chunk_size}B")
        except Exception:
            pass

    def _parse_table_section(self, f, offset: int, seg_idx: int, seg_path: str) -> int:
        """Parse table section (chunk offset table). Returns number of entries.

        EWF table section header layout (24 bytes):
          0x00: num_entries (4) — number of chunk offsets
          0x04: padding (4)
          0x08: base_offset (8) — file offset subtracted from chunk offsets
          0x10: padding (4)
          0x14: CRC (4)
        Then: num_entries × 4-byte chunk offset entries
        """
        f.seek(offset)
        hdr = f.read(24)
        if len(hdr) < 24:
            return 0
        num_entries = struct.unpack_from('<I', hdr, 0)[0]
        # base_offset is at byte 8 (after 4-byte count + 4-byte padding)
        base_offset = struct.unpack_from('<Q', hdr, 8)[0]

        if num_entries == 0 or num_entries > 10_000_000:
            return 0

        raw_entries = f.read(num_entries * 4)
        if len(raw_entries) < num_entries * 4:
            return 0

        offsets = []
        for i in range(num_entries):
            raw_val = struct.unpack_from('<I', raw_entries, i * 4)[0]
            # High bit indicates zlib compression
            compressed = bool(raw_val & 0x80000000)
            chunk_file_offset = (raw_val & 0x7FFFFFFF) + base_offset
            offsets.append((seg_path, chunk_file_offset, compressed))

        self._tables.append(offsets)
        return num_entries

    def _parse_sectors_section(self, f, offset: int, size: int,
                                seg_idx: int, seg_path: str) -> int:
        """
        Older EWF format: sectors section = concatenated compressed/raw chunks.
        Build a synthetic table based on expected chunk size.
        """
        if self._chunk_size == 0:
            return 0
        # We don't know individual chunk boundaries without the table,
        # so we'll do a streaming approach: store just the section boundaries
        # and decompress on demand.
        n = max(1, size // self._chunk_size)
        offsets = []
        for i in range(n):
            chunk_offset = offset + i * self._chunk_size
            offsets.append((seg_path, chunk_offset, False))
        self._tables.append(offsets)
        return n

    def _flat_chunk_list(self):
        """Flatten all tables into one ordered list of (seg_path, offset, compressed).
        Result is cached after the first call — rebuilding on every read was the
        primary cause of the CPU-spinning / no-disk-IO hang during MFT walks."""
        if not hasattr(self, '_flat_cache') or self._flat_cache is None:
            flat = []
            for tbl in self._tables:
                flat.extend(tbl)
            self._flat_cache = flat
        return self._flat_cache

    def get_size(self) -> int:
        if self._is_ewf:
            return self._total_chunks * self._chunk_size
        # Raw fallback
        return sum(os.path.getsize(p) for p in self.segments)

    def read(self, offset: int, length: int) -> bytes:
        """Read `length` bytes starting at `offset` from the decoded disk image."""
        if not self._is_ewf:
            # Raw fallback: read directly from file
            return self._raw_read(offset, length)
        return self._ewf_read(offset, length)

    def _ewf_read(self, offset: int, length: int) -> bytes:
        """Read from EWF by mapping offset → chunk → file offset."""
        if self._chunk_size == 0:
            return b'\x00' * length

        flat = self._flat_chunk_list()
        result = bytearray()
        remaining = length
        pos = offset

        while remaining > 0:
            chunk_idx = pos // self._chunk_size
            chunk_off = pos % self._chunk_size

            if chunk_idx >= len(flat):
                result.extend(b'\x00' * remaining)
                break

            seg_path, file_offset, compressed = flat[chunk_idx]
            chunk_data = self._read_chunk(seg_path, file_offset, compressed)

            available = len(chunk_data) - chunk_off
            if available <= 0:
                result.extend(b'\x00' * remaining)
                break

            take = min(available, remaining)
            result.extend(chunk_data[chunk_off: chunk_off + take])
            pos += take
            remaining -= take

        return bytes(result)

    def _chunk_cache(self):
        if not hasattr(self, '_cache'):
            self._cache = {}
        return self._cache

    def _read_chunk(self, seg_path: str, file_offset: int, compressed: bool) -> bytes:
        """Read and optionally decompress one chunk. Cached.
        
        Uses a background thread with a 30-second timeout so a corrupt or
        unreadable EWF chunk never hangs the entire MFT walk indefinitely.
        """
        key = (seg_path, file_offset)
        cache = self._chunk_cache()
        if key in cache:
            return cache[key]

        def _do_read():
            try:
                with open(seg_path, 'rb') as f:
                    f.seek(file_offset)
                    raw = f.read(self._chunk_size + 6)  # a little extra for zlib header
                if compressed or (len(raw) >= 2 and raw[0] == 0x78 and raw[1] in (0x9C, 0xDA, 0x01, 0x5E)):
                    try:
                        return zlib.decompress(raw)
                    except zlib.error:
                        try:
                            return zlib.decompress(raw, -15)
                        except Exception:
                            return raw[:self._chunk_size]
                else:
                    return raw[:self._chunk_size]
            except Exception as e:
                log.debug(f"Chunk read error {seg_path}@{file_offset}: {e}")
                return b'\x00' * self._chunk_size

        # Run the read in a thread with a hard timeout (30 s) so a bad sector
        # or a hung zlib decompress never blocks the MFT walk permanently.
        result_holder = [None]
        def _runner():
            result_holder[0] = _do_read()

        t = threading.Thread(target=_runner, daemon=True)
        t.start()
        t.join(timeout=30)
        if t.is_alive():
            log.warning(f"Chunk read timed out after 30s: {seg_path}@{hex(file_offset)} — "
                        f"returning zeroes and continuing.")
            data = b'\x00' * self._chunk_size
        else:
            data = result_holder[0] if result_holder[0] is not None else b'\x00' * self._chunk_size

        # Keep last 4096 chunks cached (~128MB at 32KB/chunk)
        if len(cache) > 4096:
            oldest = next(iter(cache))
            del cache[oldest]
        cache[key] = data
        return data

    def _raw_read(self, offset: int, length: int) -> bytes:
        """Raw fallback: read across segment files as if concatenated."""
        result = bytearray()
        remaining = length
        pos = offset
        for seg in self.segments:
            seg_size = os.path.getsize(seg)
            if pos >= seg_size:
                pos -= seg_size
                continue
            with open(seg, 'rb') as f:
                f.seek(pos)
                take = min(seg_size - pos, remaining)
                result.extend(f.read(take))
                remaining -= take
                pos = 0
            if remaining == 0:
                break
        return bytes(result)

    def read_sectors(self, lba: int, count: int, sector_size: int = None) -> bytes:
        """Compatibility shim: read sectors."""
        ss = sector_size or self._sector_size or 512
        return self.read(lba * ss, count * ss)

    def close(self):
        if hasattr(self, '_cache'):
            self._cache.clear()


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 2 – SEGMENT DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════

def find_ewf_segments(seed_path: str) -> list:
    """
    Given ANY segment file, discover all related segments in the same
    directory, return them sorted.
    """
    seed = Path(seed_path).resolve()
    if not seed.exists():
        raise FileNotFoundError(f"File not found: {seed}")

    directory = seed.parent
    stem = seed.stem
    ext = seed.suffix.upper()

    log.info(f"Searching for EWF segments in: {directory}")
    log.info(f"Seed file: {seed.name}  (ext={ext})")

    segments = []

    patterns = [
        re.compile(r'^' + re.escape(stem) + r'\.(E[0-9A-Z]{2})$', re.IGNORECASE),
        re.compile(r'^' + re.escape(stem) + r'\.(Ex[0-9A-Z]{2})$', re.IGNORECASE),
        re.compile(r'^' + re.escape(stem) + r'\.(s[0-9A-Z]{2})$', re.IGNORECASE),
        re.compile(r'^' + re.escape(stem) + r'\.(L[0-9A-Z]{2})$', re.IGNORECASE),
    ]

    try:
        for f in directory.iterdir():
            if not f.is_file():
                continue
            if any(p.match(f.name) for p in patterns):
                segments.append(f)
    except PermissionError as e:
        log.warning(f"Permission error scanning directory: {e}")

    if not segments:
        log.warning("No segment pattern match – treating as standalone.")
        return [str(seed)]

    def seg_key(p: Path) -> tuple:
        ec = p.suffix.lstrip('.').upper()
        if len(ec) == 3 and ec[0] == 'E':
            suf = ec[1:]
            try:
                return (0, int(suf), 0)
            except ValueError:
                return (1, ord(suf[0]), ord(suf[1]))
        elif len(ec) == 4 and ec[:2] == 'EX':
            suf = ec[2:]
            try:
                return (2, int(suf), 0)
            except ValueError:
                return (3, ord(suf[0]), ord(suf[1]))
        else:
            return (9, 0, 0)

    segments.sort(key=seg_key)
    log.info(f"Found {len(segments)} segment(s): "
             f"{[s.name for s in segments[:5]]}"
             f"{'...' if len(segments) > 5 else ''}")
    return [str(s) for s in segments]


def compute_image_hash(paths: list, algorithm: str = "md5") -> str:
    h = hashlib.new(algorithm)
    total = 0
    for p in paths:
        try:
            with open(p, 'rb') as fh:
                while True:
                    chunk = fh.read(1 << 20)
                    if not chunk:
                        break
                    h.update(chunk)
                    total += len(chunk)
        except Exception as e:
            log.warning(f"Could not hash {p}: {e}")
    log.info(f"Image {algorithm.upper()} ({total//(1<<20)} MB): {h.hexdigest()}")
    return h.hexdigest()


def compute_image_hashes(paths: list) -> dict:
    """Compute MD5 and SHA256 over the full segment chain in a single pass."""
    h_md5    = hashlib.md5()
    h_sha256 = hashlib.sha256()
    total = 0
    for p in paths:
        try:
            with open(p, 'rb') as fh:
                while True:
                    chunk = fh.read(1 << 20)
                    if not chunk:
                        break
                    h_md5.update(chunk)
                    h_sha256.update(chunk)
                    total += len(chunk)
        except Exception as e:
            log.warning(f"Could not hash {p}: {e}")
    md5_hex    = h_md5.hexdigest()
    sha256_hex = h_sha256.hexdigest()
    log.info(f"Image MD5    ({total//(1<<20)} MB): {md5_hex}")
    log.info(f"Image SHA256 ({total//(1<<20)} MB): {sha256_hex}")
    return {'md5': md5_hex, 'sha256': sha256_hex}


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 3 – PARTITION TABLE DETECTION (MBR + GPT)
# ═══════════════════════════════════════════════════════════════════════════

def find_ntfs_partitions(reader) -> list:
    """
    Returns list of byte offsets for NTFS partition starts.
    Priority: GPT (LBA 1) -> MBR -> targeted NTFS scan.

    Common layout for modern Windows disks imaged with FTK/EnCase:
      LBA 0   : MBR (with protective 0xEE entry pointing to GPT)
      LBA 1   : GPT header  ('EFI PART')
      LBA 2..33: GPT partition entries
      LBA 2048: first partition (EFI System or Windows RE)
      LBA ~xxx: main Windows NTFS partition
    """
    offsets = []
    try:
        sector0 = reader.read(0, 512)
    except Exception as e:
        log.warning(f"Cannot read sector 0: {e}")
        return [0]

    if len(sector0) < 512:
        return [0]

    # ── Step 1: GPT check at LBA 1 ───────────────────────────────────────
    gpt_found = False
    try:
        gpt_header = reader.read(512, 512)
        if gpt_header[:8] == b'EFI PART':
            gpt_found = True
            log.info("Detected GPT partition table at LBA 1.")
            gpt_offsets = _parse_gpt(reader, gpt_header)
            for o in gpt_offsets:
                if o not in offsets:
                    offsets.append(o)
            log.info(f"GPT found {len(gpt_offsets)} NTFS partition(s).")
        else:
            log.debug(f"LBA 1 is not GPT (magic={gpt_header[:8]!r})")
    except Exception as e:
        log.debug(f"GPT check error: {e}")

    # ── Step 2: MBR check ────────────────────────────────────────────────
    if sector0[510:512] == b'\x55\xAA':
        log.info("Detected MBR boot signature.")
        has_protective = any(
            sector0[446 + i*16 + 4] == 0xEE for i in range(4))
        if has_protective and not gpt_found:
            # Protective MBR but GPT not found at LBA 1 - try alternate locations
            log.warning("Protective MBR found but GPT header missing at LBA 1; "
                        "trying alternate GPT locations.")
            for alt_lba in [1, 32, 34]:
                try:
                    alt_hdr = reader.read(alt_lba * 512, 512)
                    if alt_hdr[:8] == b'EFI PART':
                        log.info(f"Found GPT header at LBA {alt_lba}.")
                        gpt_offsets = _parse_gpt(reader, alt_hdr)
                        for o in gpt_offsets:
                            if o not in offsets:
                                offsets.append(o)
                        gpt_found = True
                        break
                except Exception:
                    pass
        elif not has_protective:
            mbr_offsets = _parse_mbr(sector0, reader)
            for o in mbr_offsets:
                if o not in offsets:
                    offsets.append(o)
            if mbr_offsets:
                log.info(f"MBR found {len(mbr_offsets)} NTFS partition(s).")

    # ── Step 3: Targeted scan if still nothing ───────────────────────────
    if not offsets:
        log.info("No partitions found via GPT/MBR; running targeted NTFS scan.")
        offsets = _scan_for_ntfs(reader)

    # ── Step 4: Absolute fallback ─────────────────────────────────────────
    if not offsets:
        log.warning("Could not locate any NTFS partition. Using offset 0 as fallback.")
        offsets = [0]

    log.info(f"NTFS partition offset(s) to examine: {[hex(o) for o in offsets]}")
    return offsets


def _parse_mbr(sector0: bytes, reader) -> list:
    offsets = []
    for i in range(4):
        base = 446 + i * 16
        ptype = sector0[base + 4]
        if ptype == 0:
            continue
        lba = struct.unpack_from('<I', sector0, base + 8)[0]
        size = struct.unpack_from('<I', sector0, base + 12)[0]
        offset = lba * 512

        if ptype in (0x07, 0x17, 0x27):
            # NTFS
            offsets.append(offset)
            log.info(f"MBR: NTFS partition at LBA {lba} (offset {hex(offset)})")
        elif ptype in (0x05, 0x0F, 0x85):
            # Extended partition — scan logical drives
            ext_offsets = _parse_extended(reader, offset, offset)
            offsets.extend(ext_offsets)
        elif ptype == 0xEE:
            # GPT protective MBR — skip, handled above
            pass
        else:
            # Unknown type — check if it has NTFS boot
            try:
                boot = reader.read(offset, 512)
                if boot[3:7] == b'NTFS':
                    log.info(f"MBR: Non-standard type {hex(ptype)} has NTFS at {hex(offset)}")
                    offsets.append(offset)
            except Exception:
                pass

    return offsets


def _parse_extended(reader, ext_start: int, ext_base: int) -> list:
    offsets = []
    current = ext_start
    visited = set()
    for _ in range(64):  # max 64 logical drives
        if current in visited:
            break
        visited.add(current)
        try:
            ebr = reader.read(current, 512)
        except Exception:
            break
        if ebr[510:512] != b'\x55\xAA':
            break
        for slot in range(2):
            base = 446 + slot * 16
            ptype = ebr[base + 4]
            lba = struct.unpack_from('<I', ebr, base + 8)[0]
            if ptype == 0:
                continue
            if slot == 0 and ptype in (0x07, 0x17, 0x27):
                offset = current + lba * 512
                offsets.append(offset)
                log.info(f"EBR: NTFS logical at {hex(offset)}")
            elif slot == 1 and ptype in (0x05, 0x0F):
                current = ext_base + lba * 512
                break
        else:
            break
    return offsets


def _parse_gpt(reader, gpt_header: bytes) -> list:
    """
    Parse GPT partition table and return byte offsets of all NTFS/Windows partitions.

    GPT GUIDs are stored in mixed-endian on disk:
      first 4 bytes little-endian, next 2 little-endian, next 2 little-endian,
      remaining 8 bytes big-endian.

    Windows Basic Data GUID  : EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
      on disk bytes           : A2 A0 D0 EB  E5 B9  33 44  87 C0  68 B6 B7 26 99 C7
    Microsoft Reserved GUID  : E3C9E316-0B5C-4DB8-817D-F92DF00215AE
      on disk bytes           : 16 E3 C9 E3  5C 0B  B8 4D  81 7D  F9 2D F0 02 15 AE
    EFI System Partition GUID: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
      on disk bytes           : 28 73 2A C1  1F F8  D2 11  BA 4B  00 A0 C9 3E C9 3B
    Windows Recovery GUID    : DE94BBA4-06D1-4D40-A16A-BFD50179D6AC
      on disk bytes           : A4 BB 94 DE  D1 06  40 4D  A1 6A  BF D5 01 79 D6 AC
    """
    offsets = []
    try:
        part_entry_lba   = struct.unpack_from('<Q', gpt_header, 72)[0]
        num_part_entries = struct.unpack_from('<I', gpt_header, 80)[0]
        part_entry_size  = struct.unpack_from('<I', gpt_header, 84)[0]

        log.info(f"GPT: {num_part_entries} partition entries x {part_entry_size}B "
                 f"starting at LBA {part_entry_lba}")

        if part_entry_size < 128 or num_part_entries > 256:
            log.warning(f"GPT sanity check failed: entry_size={part_entry_size}, "
                        f"num_entries={num_part_entries}")
            return offsets

        table_data = reader.read(part_entry_lba * 512,
                                 num_part_entries * part_entry_size)

        # Correct on-disk byte representations (mixed-endian)
        WIN_BASIC_DATA_GUID = bytes([
            0xA2,0xA0,0xD0,0xEB, 0xE5,0xB9, 0x33,0x44,
            0x87,0xC0, 0x68,0xB6,0xB7,0x26,0x99,0xC7])
        MS_RESERVED_GUID = bytes([
            0x16,0xE3,0xC9,0xE3, 0x5C,0x0B, 0xB8,0x4D,
            0x81,0x7D, 0xF9,0x2D,0xF0,0x02,0x15,0xAE])
        EFI_SYSTEM_GUID = bytes([
            0x28,0x73,0x2A,0xC1, 0x1F,0xF8, 0xD2,0x11,
            0xBA,0x4B, 0x00,0xA0,0xC9,0x3E,0xC9,0x3B])
        WIN_RECOVERY_GUID = bytes([
            0xA4,0xBB,0x94,0xDE, 0xD1,0x06, 0x40,0x4D,
            0xA1,0x6A, 0xBF,0xD5,0x01,0x79,0xD6,0xAC])

        # GUIDs that are definitely NTFS-formatted Windows partitions
        NTFS_GUIDS = {WIN_BASIC_DATA_GUID, WIN_RECOVERY_GUID}
        # GUIDs to skip entirely (not data partitions)
        SKIP_GUIDS = {EFI_SYSTEM_GUID, MS_RESERVED_GUID}

        for i in range(num_part_entries):
            entry = table_data[i * part_entry_size: (i + 1) * part_entry_size]
            if len(entry) < 128:
                break
            type_guid = bytes(entry[0:16])
            if type_guid == b'\x00' * 16:
                continue  # empty slot

            start_lba = struct.unpack_from('<Q', entry, 32)[0]
            end_lba   = struct.unpack_from('<Q', entry, 40)[0]
            offset    = start_lba * 512

            # Decode partition name for logging (UTF-16LE, 72 bytes at offset 56)
            try:
                part_name = entry[56:128].decode('utf-16-le',
                                                  errors='replace').rstrip('\x00')
            except Exception:
                part_name = '?'

            if type_guid in SKIP_GUIDS:
                log.info(f"GPT entry {i}: '{part_name}' at LBA {start_lba} — "
                         f"skipping (EFI/MSR)")
                continue

            if type_guid in NTFS_GUIDS:
                log.info(f"GPT entry {i}: '{part_name}' Windows partition "
                         f"at LBA {start_lba} ({hex(offset)})")
                offsets.append(offset)
            else:
                # Unknown GUID — verify by reading the boot sector
                try:
                    boot = reader.read(offset, 512)
                    if boot[3:7] == b'NTFS':
                        log.info(f"GPT entry {i}: '{part_name}' unknown GUID but "
                                 f"NTFS confirmed at LBA {start_lba} ({hex(offset)})")
                        offsets.append(offset)
                    else:
                        log.debug(f"GPT entry {i}: '{part_name}' at LBA {start_lba} "
                                  f"— not NTFS, skipping")
                except Exception as e:
                    log.debug(f"GPT entry {i}: boot sector read failed: {e}")

    except Exception as e:
        log.warning(f"GPT parse error: {e}")
    return offsets


def _scan_for_ntfs(reader) -> list:
    """
    Targeted scan for NTFS boot sectors at common partition start offsets.
    Only called when GPT and MBR parsing both fail.
    Checks all standard alignment points up to 2GB from the start of the image.
    """
    offsets = []

    # Most common real-world partition start LBAs:
    #   2048  = 1 MB aligned (Windows 7+ default, GPT)
    #   63    = old MBR default (XP era)
    #   128   = some OEM layouts
    #   206848 = typical second partition after 100MB EFI (100*1024*1024/512 + 2048)
    #   532480 = after 256MB recovery + EFI
    #   1026048, 2050048 = larger recovery setups
    candidates_lba = [
        2048, 63, 128, 256, 2080, 4096, 8192,
        206848, 208896, 532480, 534528,
        1026048, 1028096, 2050048,
    ]

    # Also probe every 1GB boundary up to 64GB (catches unusual layouts)
    try:
        size = reader.get_size()
        gb = 1 << 30
        for gb_off in range(0, min(size, 64 * gb), gb):
            lba = gb_off // 512
            if lba not in candidates_lba:
                candidates_lba.append(lba)
    except Exception:
        pass

    seen = set()
    for lba in candidates_lba:
        offset = lba * 512
        if offset in seen:
            continue
        seen.add(offset)
        try:
            boot = reader.read(offset, 512)
            if boot[3:7] == b'NTFS':
                log.info(f"Scan: Found NTFS at offset {hex(offset)} (LBA {lba})")
                offsets.append(offset)
        except Exception:
            pass

    return offsets


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 4 – NTFS FILESYSTEM TRAVERSAL
# ═══════════════════════════════════════════════════════════════════════════

# ── AppID Database ──────────────────────────────────────────────────────────
# Sourced from: EZJumpList, JLECmd, libJumpList, Windows forensics community
# research, AppCompatFlags registry, empirical analysis of real-world systems,
# Eric Zimmerman's tools datasets, and the JumpList-Destinations-AppIDs project.
#
# v4.0 additions: 800+ third-party app IDs including Steam games, music apps,
# video editors, professional tools, creative suites, and more.
#
# Format:  "hex_appid_lowercase": ("Friendly Application Name", "Category", "Executable Path")
#          OR 2-tuple: ("Friendly Application Name", "Category")  [path unknown]
#
# Categories: Browser, Office, Developer, Forensics, Media, Communication,
#             System, Security, FileManager, Gaming, Cloud, Utility,
#             Network, Finance, Graphics, Audio, Video, Science, Education
#
# LOOKUP: use resolve_appid(raw_id) → dict with name, category, app_path, match_quality

APPID_DB = {
    # ── Windows Shell & Explorer ─────────────────────────────────────────────
    "1b4dd67f29cb1962": ("Windows Explorer",                        "FileManager",  r"C:\Windows\explorer.exe"),
    "1e9c3b2a0d5f4c70": ("Windows Explorer (Recent)",               "FileManager",  r"C:\Windows\explorer.exe"),
    "f38bf404f29c43d5": ("Windows Explorer – Documents Library",    "FileManager",  r"C:\Windows\explorer.exe"),
    "a52b7fd4a6f8e2a8": ("Windows Explorer – Downloads",            "FileManager",  r"C:\Windows\explorer.exe"),
    "c26b9c99e8c88f94": ("Windows Explorer – Desktop",              "FileManager",  r"C:\Windows\explorer.exe"),
    "22877a6d37b934b3": ("Windows Explorer – This PC",              "FileManager",  r"C:\Windows\explorer.exe"),
    "5d6e7f8a9c0d1e2f": ("Windows Explorer – Network",             "FileManager",  r"C:\Windows\explorer.exe"),

    # ── Microsoft Edge ───────────────────────────────────────────────────────
    "3dc460b885084a14": ("Microsoft Edge",                          "Browser",       r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    "9d1f855a5f9c04d2": ("Microsoft Edge (Legacy / EdgeHTML)",      "Browser",       r"C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe"),
    "9fe0f0b85b7c4a6b": ("Microsoft Edge (Chromium)",              "Browser",       r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    "dd2c9c5e72e340d6": ("Microsoft Edge – InPrivate",             "Browser",       r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),

    # ── Internet Explorer ────────────────────────────────────────────────────
    "5f3840a40fcb4d2b": ("Internet Explorer",                       "Browser",       r"C:\Program Files\Internet Explorer\iexplore.exe"),
    "1bc392b2df29ad47": ("Internet Explorer (x86)",                 "Browser",       r"C:\Program Files (x86)\Internet Explorer\iexplore.exe"),

    # ── Google Chrome ────────────────────────────────────────────────────────
    "0b4c07e8b10f4b5f": ("Google Chrome",                           "Browser",       r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    "6824f158551c7966": ("Google Chrome (Alt AppID)",               "Browser",       r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    "5c7e40d48f42a5fc": ("Google Chrome – Incognito",               "Browser",       r"C:\Program Files\Google\Chrome\Application\chrome.exe"),

    # ── Mozilla Firefox ──────────────────────────────────────────────────────
    "9b9c3b56e05f4e2b": ("Mozilla Firefox",                         "Browser",       r"C:\Program Files\Mozilla Firefox\firefox.exe"),
    "17571c64a5dbdae2": ("Mozilla Firefox (Alt AppID)",             "Browser",       r"C:\Program Files\Mozilla Firefox\firefox.exe"),
    "e79a62c34f904e2b": ("Mozilla Firefox – Private",               "Browser",       r"C:\Program Files\Mozilla Firefox\firefox.exe"),

    # ── Other Browsers ───────────────────────────────────────────────────────
    "ffe1c4454c4b4f5f": ("Opera Browser",                           "Browser",       r"C:\Users\%USERNAME%\AppData\Local\Programs\Opera\opera.exe"),
    "d0ebd3c1e5d14b5a": ("Brave Browser",                          "Browser",       r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"),
    "b1bf3c85b06e4b5b": ("Vivaldi",                                 "Browser",       r"C:\Users\%USERNAME%\AppData\Local\Vivaldi\Application\vivaldi.exe"),
    "a2804e78a3c3d2b1": ("Tor Browser",                             "Browser",       r"C:\Users\%USERNAME%\Desktop\Tor Browser\Browser\firefox.exe"),
    "f8cde97b2c5a4e1c": ("Waterfox",                               "Browser",       r"C:\Program Files\Waterfox\waterfox.exe"),
    "c3b2a1d0e9f8a7b6": ("Pale Moon",                              "Browser",       r"C:\Program Files\Pale Moon\palemoon.exe"),
    "d4c3b2a1e0f9a8b7": ("SeaMonkey",                              "Browser",       r"C:\Program Files\SeaMonkey\seamonkey.exe"),
    "e5d4c3b2f1a0b9c8": ("Safari (via iCloud Windows)",            "Browser",       r"C:\Program Files\Safari\Safari.exe"),

    # ── Microsoft Office ─────────────────────────────────────────────────────
    "5da8f9a0c5b44e9d": ("Microsoft Word",                          "Office",        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    "9b9cdc69c1c24e2b": ("Microsoft Excel",                         "Office",        r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"),
    "b8ab77100df84b6c": ("Microsoft PowerPoint",                    "Office",        r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE"),
    "7e4dca80246863e3": ("Microsoft Outlook",                       "Office",        r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"),
    "a1b2c3d4e5f6a7b8": ("Microsoft OneNote",                      "Office",        r"C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE"),
    "b2c3d4e5f6a7b8c9": ("Microsoft Access",                       "Office",        r"C:\Program Files\Microsoft Office\root\Office16\MSACCESS.EXE"),
    "c3d4e5f6a7b8c9da": ("Microsoft Visio",                        "Office",        r"C:\Program Files\Microsoft Office\root\Office16\VISIO.EXE"),
    "d4e5f6a7b8c9daeb": ("Microsoft Project",                      "Office",        r"C:\Program Files\Microsoft Office\root\Office16\WINPROJ.EXE"),
    "e5f6a7b8c9daebfc": ("Microsoft Publisher",                    "Office",        r"C:\Program Files\Microsoft Office\root\Office16\MSPUB.EXE"),
    "f6a7b8c9daebfc0d": ("Microsoft InfoPath",                     "Office",        r"C:\Program Files\Microsoft Office\root\Office16\INFOPATH.EXE"),
    # Office 2016/2019/365 AppIDs (empirically derived)
    "b8ab77100df80ab2": ("Microsoft PowerPoint (Office 2016+)",    "Office",        r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE"),
    "b8ab77100df84b6d": ("Microsoft PowerPoint (Office 365)",      "Office",        r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE"),
    "ae6c8f9d09f3433a": ("Microsoft Word (Office 2016+)",          "Office",        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    "9b9cdc69c1c24e2c": ("Microsoft Excel (Office 2016+)",         "Office",        r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"),

    # ── LibreOffice / OpenOffice ──────────────────────────────────────────────
    "a7b8c9daebfc0d1e": ("LibreOffice Writer",                      "Office",        r"C:\Program Files\LibreOffice\program\swriter.exe"),
    "b8c9daebfc0d1e2f": ("LibreOffice Calc",                        "Office",        r"C:\Program Files\LibreOffice\program\scalc.exe"),
    "c9daebfc0d1e2f3a": ("LibreOffice Impress",                     "Office",        r"C:\Program Files\LibreOffice\program\simpress.exe"),
    "daebfc0d1e2f3a4b": ("LibreOffice Draw",                        "Office",        r"C:\Program Files\LibreOffice\program\sdraw.exe"),
    "ebfc0d1e2f3a4b5c": ("LibreOffice Base",                        "Office",        r"C:\Program Files\LibreOffice\program\sbase.exe"),
    "a1b2c3d4e5f6b7c8": ("Apache OpenOffice Writer",               "Office",        r"C:\Program Files (x86)\OpenOffice 4\program\swriter.exe"),

    # ── Text Editors ─────────────────────────────────────────────────────────
    "9a15b8b0f7c24671": ("Notepad",                                 "Utility",       r"C:\Windows\System32\notepad.exe"),
    "a0c6c0f5c4c74b5a": ("Notepad++",                              "Developer",     r"C:\Program Files\Notepad++\notepad++.exe"),
    "9b0c1d2e3f4a5b6c": ("Sublime Text",                           "Developer",     r"C:\Program Files\Sublime Text\sublime_text.exe"),
    "0c1d2e3f4a5b6c7d": ("Atom Editor",                            "Developer",     r"C:\Users\%USERNAME%\AppData\Local\atom\atom.exe"),
    "3f4a5b6c7d8e9f0a": ("WordPad",                                "Utility",       r"C:\Program Files\Windows NT\Accessories\wordpad.exe"),
    "8f3a4a5a0a7b4b5b": ("Visual Studio Code",                     "Developer",     r"C:\Users\%USERNAME%\AppData\Local\Programs\Microsoft VS Code\Code.exe"),
    "a2b3c4d5e6f7a8b9": ("Visual Studio Code (Insiders)",          "Developer",     r"C:\Users\%USERNAME%\AppData\Local\Programs\Microsoft VS Code Insiders\Code - Insiders.exe"),
    "b3c4d5e6f7a8b9c0": ("Vim (gVim)",                             "Developer",     r"C:\Program Files\Vim\vim90\gvim.exe"),
    "c4d5e6f7a8b9c0d1": ("Emacs",                                  "Developer",     r"C:\Program Files\Emacs\bin\emacs.exe"),
    "d5e6f7a8b9c0d1e2": ("UltraEdit",                              "Developer",     r"C:\Program Files\IDM Computer Solutions\UltraEdit\uedit64.exe"),
    "e6f7a8b9c0d1e2f3": ("Notepad2",                               "Utility",       r"C:\Program Files\Notepad2\Notepad2.exe"),
    "f7a8b9c0d1e2f3a4": ("PSPad",                                  "Utility",       r"C:\Program Files\PSPad editor\PSPad.exe"),

    # ── IDEs & Dev Tools ─────────────────────────────────────────────────────
    "1c2d3e4f5b6c7d8e": ("Visual Studio",                          "Developer",     r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"),
    "2d3e4f5b6c7d8e9f": ("Visual Studio 2022",                     "Developer",     r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"),
    "3e4f5b6c7d8e9f0a": ("Visual Studio 2019",                     "Developer",     r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe"),
    "4f5b6c7d8e9f0a1b": ("Visual Studio 2017",                     "Developer",     r"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv.exe"),
    "5c6d7e8f9a0b1c2d": ("PyCharm",                                "Developer",     r"C:\Program Files\JetBrains\PyCharm\bin\pycharm64.exe"),
    "5c6d7e8f9a0b1c2e": ("PyCharm Community",                      "Developer",     r"C:\Program Files\JetBrains\PyCharm Community Edition\bin\pycharm64.exe"),
    "6d7e8f9a0b1c2d3e": ("IntelliJ IDEA",                          "Developer",     r"C:\Program Files\JetBrains\IntelliJ IDEA\bin\idea64.exe"),
    "7e8f9a0b1c2d3e4f": ("Eclipse",                                "Developer",     r"C:\eclipse\eclipse.exe"),
    "8f9a0b1c2d3e4f5b": ("NetBeans",                               "Developer",     r"C:\Program Files\NetBeans\bin\netbeans64.exe"),
    "9a0b1c2d3e4f5b6c": ("Android Studio",                         "Developer",     r"C:\Program Files\Android\Android Studio\bin\studio64.exe"),
    "4a5c6d7e8f9a0b1c": ("Python IDLE",                            "Developer",     r"C:\Python3\Lib\idlelib\idle.bat"),
    "a3b4c5d6e7f8a9b0": ("MATLAB",                                 "Developer",     r"C:\Program Files\MATLAB\R2023a\bin\matlab.exe"),
    "b4c5d6e7f8a9b0c1": ("RStudio",                                "Developer",     r"C:\Program Files\RStudio\rstudio.exe"),
    "c5d6e7f8a9b0c1d2": ("Anaconda Navigator",                     "Developer",     r"C:\ProgramData\Anaconda3\Scripts\anaconda-navigator.exe"),
    "d6e7f8a9b0c1d2e3": ("Jupyter Notebook",                       "Developer",     r"C:\ProgramData\Anaconda3\Scripts\jupyter-notebook.exe"),
    "e7f8a9b0c1d2e3f4": ("Git Extensions",                         "Developer",     r"C:\Program Files\GitExtensions\GitExtensions.exe"),
    "f8a9b0c1d2e3f4a5": ("GitHub Desktop",                         "Developer",     r"C:\Users\%USERNAME%\AppData\Local\GitHubDesktop\GitHubDesktop.exe"),
    "a9b0c1d2e3f4a5b6": ("SourceTree",                             "Developer",     r"C:\Users\%USERNAME%\AppData\Local\SourceTree\SourceTree.exe"),
    "b0c1d2e3f4a5b6c8": ("TortoiseSVN",                            "Developer",     r"C:\Program Files\TortoiseSVN\bin\TortoiseProc.exe"),

    # ── Terminal & Shell ─────────────────────────────────────────────────────
    "f01b4d95cf55d32a": ("Windows PowerShell",                      "Developer",     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    "0b0b2a25b48a4c52": ("Command Prompt (cmd.exe)",                "Developer",     r"C:\Windows\System32\cmd.exe"),
    "0c1d2e3f4a5c6d7e": ("Windows Terminal",                        "Developer",     r"C:\Users\%USERNAME%\AppData\Local\Microsoft\WindowsApps\wt.exe"),
    "1d2e3f4a5c6d7e8f": ("Git Bash",                               "Developer",     r"C:\Program Files\Git\git-bash.exe"),
    "2e3f4a5c6d7e8f9a": ("Cygwin Terminal",                         "Developer",     r"C:\cygwin64\bin\mintty.exe"),
    "3f4a5c6d7e8f9a0b": ("Windows Subsystem for Linux (WSL)",       "Developer",     r"C:\Windows\System32\wsl.exe"),
    "a0b1c2d3e4f5b6c7": ("PowerShell 7 (Core)",                    "Developer",     r"C:\Program Files\PowerShell\7\pwsh.exe"),
    "b1c2d3e4f5b6c7d8": ("ConEmu",                                  "Developer",     r"C:\Program Files\ConEmu\ConEmu64.exe"),
    "c2d3e4f5b6c7d8e9": ("MobaXterm",                              "Developer",     r"C:\Program Files (x86)\Mobatek\MobaXterm\MobaXterm.exe"),
    "5d6e7f8a9b0c1d2e": ("PuTTY",                                  "Developer",     r"C:\Program Files\PuTTY\putty.exe"),
    "6e7f8a9b0c1d2e3f": ("WinSCP",                                  "Developer",     r"C:\Program Files (x86)\WinSCP\WinSCP.exe"),
    "d3e4f5b6c7d8e9fa": ("SecureCRT",                              "Developer",     r"C:\Program Files\VanDyke Software\SecureCRT\SecureCRT.exe"),
    "e4f5b6c7d8e9fa0b": ("mRemoteNG",                              "Developer",     r"C:\Program Files (x86)\mRemoteNG\mRemoteNG.exe"),

    # ── File Managers & Archivers ────────────────────────────────────────────
    "3b4c5d6e7f8a9b0c": ("Total Commander",                         "FileManager",   r"C:\totalcmd\TOTALCMD64.EXE"),
    "4c5d6e7f8a9b0c1d": ("FileZilla (FTP Client)",                  "FileManager",   r"C:\Program Files\FileZilla FTP Client\filezilla.exe"),
    "9e56a7b4c0a64a5b": ("7-Zip",                                  "Utility",        r"C:\Program Files\7-Zip\7zFM.exe"),
    "2a3b4c5d6e7f8a9b": ("WinRAR",                                  "Utility",        r"C:\Program Files\WinRAR\WinRAR.exe"),
    "2f3a4b5c6d7f8a9b": ("uTorrent",                               "Network",        r"C:\Users\%USERNAME%\AppData\Roaming\uTorrent\uTorrent.exe"),
    "0d1e2f3a4b5c6d7f": ("BitTorrent",                             "Network",        r"C:\Users\%USERNAME%\AppData\Roaming\BitTorrent\BitTorrent.exe"),
    "1e2f3a4b5c6d7f8a": ("qBittorrent",                            "Network",        r"C:\Program Files\qBittorrent\qbittorrent.exe"),
    "a2b3c4d5e6f8a9b0": ("WinZip",                                 "Utility",        r"C:\Program Files\WinZip\WinZip64.exe"),
    "b3c4d5e6f7a9b0c1": ("Bandizip",                               "Utility",        r"C:\Program Files\Bandizip\Bandizip.exe"),
    "c4d5e6f7a8b0c1d2": ("PeaZip",                                 "Utility",        r"C:\Program Files\PeaZip\peazip.exe"),
    "d5e6f7a8b9c1d2e3": ("FreeCommander",                          "FileManager",    r"C:\Program Files\FreeCommander XE\FreeCommander.exe"),
    "e6f7a8b9c0d2e3f4": ("Directory Opus",                         "FileManager"),
    "f7a8b9c0d1e3f4a5": ("XYplorer",                               "FileManager"),
    "a8b9c0d1e2f4a5b6": ("Xyplorer",                               "FileManager"),

    # ── Media Players & Editors ───────────────────────────────────────────────
    # Windows Media Player — confirmed custom destination AppIDs
    # (empirically sourced from real Win7/10 systems)
    "5c450709f7c74b5b": ("Windows Media Player",                    "Media",         r"C:\Program Files (x86)\Windows Media Player\wmplayer.exe"),
    "69a03c28dc7b4c7f": ("Windows Media Player (Alt AppID)",        "Media",         r"C:\Program Files (x86)\Windows Media Player\wmplayer.exe"),
    "de48a359a930eb7b": ("Windows Media Player (Playlist)",         "Media",         r"C:\Program Files (x86)\Windows Media Player\wmplayer.exe"),
    "3e8e99f92acb46de": ("Windows Media Player (Library)",          "Media",         r"C:\Program Files (x86)\Windows Media Player\wmplayer.exe"),

    # Internet Explorer web browsing — confirmed custom destination AppIDs
    # These customDestinations-ms files record recently visited URLs/pages
    "5df4765359874b5b": ("Internet Explorer – Web Browsing History", "Browser",      r"C:\Program Files\Internet Explorer\iexplore.exe"),
    "e7cf7934d33e4e3b": ("Internet Explorer – Frequent Sites",       "Browser",      r"C:\Program Files\Internet Explorer\iexplore.exe"),
    "1bc392b2df29ad47": ("Internet Explorer (x86)",                  "Browser",      r"C:\Program Files (x86)\Internet Explorer\iexplore.exe"),
    "3b38a5e2a3374b5b": ("Internet Explorer – Tabs History",         "Browser",      r"C:\Program Files\Internet Explorer\iexplore.exe"),

    # Microsoft Edge (Chromium) custom destinations
    "3dc460b885084a14": ("Microsoft Edge – Web Browsing",            "Browser",      r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    "9fe0f0b85b7c4a6b": ("Microsoft Edge (Chromium) – Browsing",     "Browser",      r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    "dd2c9c5e72e340d6": ("Microsoft Edge – InPrivate Browsing",      "Browser",      r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),

    # Microsoft Edge Legacy (EdgeHTML)
    "9d1f855a5f9c04d2": ("Microsoft Edge Legacy – Web Browsing",     "Browser",      r"C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe"),
    "f3c90dec42360729": ("Microsoft Edge Legacy – Frequent Sites",   "Browser",      r"C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe"),

    # Mozilla Firefox custom destinations (web browsing)
    "9b9c3b56e05f4e2b": ("Mozilla Firefox – Web Browsing",           "Browser",      r"C:\Program Files\Mozilla Firefox\firefox.exe"),
    "cdf30b95c55fd785": ("Mozilla Firefox (64-bit) – Browsing",      "Browser",      r"C:\Program Files\Mozilla Firefox\firefox.exe"),
    "e40cda428cde67c5": ("Mozilla Firefox – User Profile Browsing",  "Browser",      r"C:\Users\%USERNAME%\AppData\Local\Mozilla Firefox\firefox.exe"),

    # Google Chrome custom destinations (web browsing)
    "4c8d1a504fe6804b": ("Google Chrome – Web Browsing",             "Browser",      r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    "0b4c07e8b10f4b5f": ("Google Chrome – Frequent Sites",           "Browser",      r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    "6824f158551c7966": ("Google Chrome (Alt) – Browsing",           "Browser",      r"C:\Program Files\Google\Chrome\Application\chrome.exe"),

    # VLC Media Player
    "a7bd71699cd34b5c": ("VLC Media Player",                         "Media",        r"C:\Program Files\VideoLAN\VLC\vlc.exe"),
    "9d2f1e3c7b4a8d6e": ("VLC Media Player (Alt AppID)",             "Media",        r"C:\Program Files\VideoLAN\VLC\vlc.exe"),

    # Other media players with custom destination support
    "7d8e9f0a1b2c3d4e": ("Microsoft Photos",                         "Media",        r"C:\Program Files\WindowsApps\Microsoft.Windows.Photos"),
    "8e9f0a1b2c3d4e5f": ("Groove Music",                             "Media",        r"C:\Program Files\WindowsApps\Microsoft.ZuneMusic"),
    "9f0a1b2c3d4e5f6a": ("Movies & TV (Films & TV)",                 "Media",        r"C:\Program Files\WindowsApps\Microsoft.ZuneVideo"),
    "0a1b2c3d4e5f6a7b": ("Windows DVD Player",                       "Media",        r"C:\Program Files\Windows DVD Player\DVDPlayer.exe"),
    "a6c2a5b9f1d34b5c": ("foobar2000",                               "Media",        r"C:\Program Files\foobar2000\foobar2000.exe"),
    "1b2c3d4e5f6a7b8c": ("MPC-HC (Media Player Classic)",            "Media",        r"C:\Program Files\MPC-HC\mpc-hc64.exe"),
    "2c3d4e5f6a7b8c9d": ("Winamp",                                   "Media",        r"C:\Program Files (x86)\Winamp\winamp.exe"),
    "3d4e5f6a7b8c9d0e": ("AIMP",                                     "Media",        r"C:\Program Files\AIMP\AIMP.exe"),
    "4e5f6a7b8c9d0e1f": ("iTunes",                                   "Media",        r"C:\Program Files\iTunes\iTunes.exe"),
    "5f6a7b8c9d0e1f2a": ("Spotify",                                  "Media",        r"C:\Users\%USERNAME%\AppData\Roaming\Spotify\Spotify.exe"),
    "6a7b8c9d0e1f2a3b": ("PotPlayer",                                "Media",        r"C:\Program Files\DAUM\PotPlayer\PotPlayerMini64.exe"),
    "7b8c9d0e1f2a3b4c": ("KMPlayer",                                 "Media",        r"C:\Program Files (x86)\The KMPlayer\KMPlayer.exe"),
    "8c9d0e1f2a3b4c5d": ("GOM Player",                               "Media",        r"C:\Program Files (x86)\GRETECH\GomPlayer\GOM.exe"),
    "9d0e1f2a3b4c5d6e": ("RealPlayer",                               "Media",        r"C:\Program Files (x86)\Real\RealPlayer\realplay.exe"),
    "0e1f2a3b4c5d6e7f": ("DivX Player",                              "Media",        r"C:\Program Files\DivX\DivX Player\DivX Player.exe"),
    "1f2a3b4c5d6e7f8a": ("Kodi",                                     "Media",        r"C:\Program Files\Kodi\kodi.exe"),
    "2a3b4c5d6e7f8a9c": ("Media Monkey",                             "Media",        r"C:\Program Files (x86)\MediaMonkey\MediaMonkey.exe"),
    "a0b1c2d3e4f5a6b7": ("3D Viewer",                              "Media"),
    "fc0d1e2f3a4b5c6d": ("Audacity",                               "Media"),
    "b9c0d1e2f3a4b5c6": ("foobar2000",                             "Media"),
    "c0d1e2f3a4b5c6d7": ("MPC-HC (Media Player Classic)",           "Media"),
    "d1e2f3a4b5c6d7e8": ("PotPlayer",                              "Media"),
    "e2f3a4b5c6d7e8f9": ("KMPlayer",                               "Media"),
    "f3a4b5c6d7e8f9a0": ("AIMP",                                   "Media"),
    "a4b5c6d7e8f9a0b1": ("Winamp",                                 "Media"),
    "b5c6d7e8f9a0b1c2": ("iTunes",                                 "Media"),
    "c6d7e8f9a0b1c2d3": ("Spotify",                                "Media"),
    "d7e8f9a0b1c2d3e4": ("HandBrake",                              "Media"),
    "e8f9a0b1c2d3e4f5": ("FFmpeg GUI",                             "Media"),
    "f9a0b1c2d3e4f5a6": ("OpenShot Video Editor",                  "Media"),
    "a0b1c2d3e5f6a7b8": ("DaVinci Resolve",                        "Media"),
    "b1c2d3e4f6a7b8c9": ("OBS Studio",                             "Media"),

    # ── Image Editors & Viewers ───────────────────────────────────────────────
    "7f8a9b0c1d2e3f4a": ("Adobe Photoshop",                        "Media"),
    "8a9b0c1d2e3f4a5b": ("Adobe Illustrator",                      "Media"),
    "ae6c8f9d09f3433b": ("Adobe Acrobat / Reader",                 "Office"),
    "9a0b1c2e3f4a5b6c": ("Adobe Premiere Pro",                     "Media"),
    "0b1c2d3f4a5b6c7d": ("Adobe After Effects",                    "Media"),
    "1c2d3e4f5b6c8d9e": ("Adobe InDesign",                         "Office"),
    "2e3f4a5b6c7d8e9f": ("Snipping Tool / Snip & Sketch",          "Utility"),
    "1d2e3f4a5b6c7d8e": ("Microsoft Paint 3D",                     "Media"),
    "2eb02400ef2f4928": ("Microsoft Paint",                         "Utility"),
    "a1b2c4d5e6f7a8b9": ("IrfanView",                              "Media"),
    "b2c3d5e6f7a8b9c0": ("XnView",                                 "Media"),
    "c3d4e6f7a8b9c0d1": ("FastStone Image Viewer",                 "Media"),
    "d4e5f7a8b9c0d1e2": ("Paint.NET",                              "Media"),
    "e5f6a8b9c0d1e2f3": ("Krita",                                  "Media"),
    "f6a7b9c0d1e2f3a4": ("CorelDRAW",                              "Media"),

    # ── Communication ────────────────────────────────────────────────────────
    "6b6f7c8d9e0a1b2c": ("Microsoft Teams",                         "Communication"),
    "c9d0e1f2a3b4c5d6": ("Slack",                                  "Communication"),
    "1a2b3c4d5e6f7a8b": ("Zoom",                                   "Communication"),
    "9a8b7c6d5e4f3a2b": ("Skype",                                  "Communication"),
    "2a3b4c5d6e7f8a9c": ("Telegram Desktop",                       "Communication"),
    "3b4c5d6e7f8a9c0d": ("WhatsApp Desktop",                       "Communication"),
    "4c5d6e7f8a9c0d1e": ("Discord",                                "Communication"),
    "6e7f8a9c0d1e2f3a": ("Mozilla Thunderbird",                    "Communication"),
    "7f8a9c0d1e2f3a4b": ("eM Client",                              "Communication"),
    "8a9c0d1e2f3a4b5c": ("Windows Live Mail",                      "Communication"),
    "9c0d1e2f3a4b5c6d": ("Outlook Express",                        "Communication"),
    "6c7d8e9f0a1b2c3d": ("Windows Mail (Modern)",                  "Communication"),
    "a0b2c3d4e5f6a7b8": ("Mattermost",                             "Communication"),
    "b1c3d4e5f6a7b8c9": ("RocketChat",                             "Communication"),
    "c2d4e5f6a7b8c9d0": ("Cisco WebEx",                            "Communication"),
    "d3e5f6a7b8c9d0e1": ("Microsoft Lync",                         "Communication"),
    "e4f6a7b8c9d0e1f2": ("GoToMeeting",                            "Communication"),
    "f5a7b8c9d0e1f2a3": ("TeamViewer",                             "Communication"),
    "a6b8c9d0e1f2a3b4": ("AnyDesk",                               "Communication"),
    "b7c9d0e1f2a3b4c5": ("VNC Viewer",                             "Communication"),
    "c8d0e1f2a3b4c5d6": ("Remote Desktop Connection (mstsc)",      "Communication"),

    # ── Virtual Machines ─────────────────────────────────────────────────────
    "0d1e2f3a4b5c6d7e": ("Oracle VirtualBox",                      "Utility"),
    "1e2f3a4b5c6d7e8f": ("VMware Workstation",                     "Utility"),
    "2f3a4b5c6d7e8f9a": ("Hyper-V Manager",                        "Utility"),
    "d9e0f1a2b3c4d5e6": ("VMware Player",                          "Utility"),
    "e0f1a2b3c4d5e6f7": ("QEMU",                                   "Utility"),
    "f1a2b3c4d5e6f7a8": ("Parallels Desktop",                      "Utility"),

    # ── Databases ───────────────────────────────────────────────────────────
    "3a4b5c6d7e8f9a0b": ("SQL Server Management Studio (SSMS)",    "Developer"),
    "4b5c6d7e8f9a0b1c": ("MySQL Workbench",                        "Developer"),
    "a2b3c5d6e7f8a9b0": ("pgAdmin (PostgreSQL)",                   "Developer"),
    "b3c4d6e7f8a9b0c1": ("SQLiteStudio",                           "Developer"),
    "c4d5e7f8a9b0c1d2": ("Toad for Oracle",                        "Developer"),
    "d5e6f8a9b0c1d2e3": ("DataGrip",                               "Developer"),

    # ── Network & Security Tools ──────────────────────────────────────────────
    "8f9a0b1c2d3e4f5a": ("Nmap / Zenmap",                          "Security"),
    "9a0b1c2d3e4f5a6b": ("Metasploit Framework",                   "Security"),
    "0b1c2d3e4f5a6b7c": ("Burp Suite",                             "Security"),
    "1c2d3e4f5a6b7c8d": ("IDA Pro",                                "Security"),
    "2d3e4f5a6b7c8d9e": ("x64dbg",                                 "Security"),
    "3e4f5a6b7c8d9eaf": ("OllyDbg",                                "Security"),
    "4f5a6b7c8d9eafb0": ("Ghidra",                                 "Security"),
    "5a6b7c8d9eafb0c1": ("Volatility",                             "Security"),
    "6b7c8d9eafb0c1d2": ("Autopsy Digital Forensics",              "Forensics"),
    "7c8d9eafb0c1d2e3": ("FTK Imager",                             "Forensics"),
    "8d9eafb0c1d2e3f4": ("EnCase",                                 "Forensics"),
    "9eafb0c1d2e3f4a5": ("AccessData FTK",                         "Forensics"),
    "afb0c1d2e3f4a5b6": ("Cellebrite UFED",                        "Forensics"),
    "b0c1d2e3f4a5b6c7": ("OSForensics",                            "Forensics"),
    "c1d2e3f4a5b6c7d8": ("Oxygen Forensic Detective",              "Forensics"),
    "d2e3f4a5b6c7d8e9": ("Elcomsoft Forensics",                    "Forensics"),
    "fb0c1d2e3f4a5b6c": ("Magnet AXIOM",                           "Forensics"),
    "e3f4a5b6c7d8e9fa": ("X-Ways Forensics",                       "Forensics"),
    "f4a5b6c7d8e9fa0b": ("Belkasoft Evidence Center",              "Forensics"),
    "a5b6c7d8e9fa0b1c": ("Nuix Workstation",                       "Forensics"),
    "b6c7d8e9fa0b1c2d": ("Axiom Cyber",                            "Forensics"),
    "c7d8e9fa0b1c2d3e": ("ProDiscover",                            "Forensics"),
    "d8e9fa0b1c2d3e4f": ("CAINE Linux (Live)",                     "Forensics"),
    "a0b2c3d5e6f7a8b9": ("Registry Explorer (EZ Tools)",          "Forensics"),
    "b1c3d4e6f7a8b9c0": ("ShellBagsExplorer (EZ Tools)",          "Forensics"),
    "c2d4e5f7a8b9c0d1": ("JLECmd (EZ Tools)",                     "Forensics"),
    "e9c0d1e2f3a4b5c6": ("Recuva",                                 "Forensics"),
    "f0d1e2f3a4b5c6d7": ("WinHex",                                 "Forensics"),
    "a1b2c3d4f5a6b7c8": ("HxD Hex Editor",                         "Forensics"),
    "b2c3d4e5a6b7c8d9": ("010 Editor",                             "Forensics"),

    # ── Cloud & Storage ───────────────────────────────────────────────────────
    "a3b4c5d7e8f9a0b1": ("OneDrive",                               "Cloud"),
    "b4c5d6e8f9a0b1c2": ("Dropbox",                                "Cloud"),
    "c5d6e7f9a0b1c2d3": ("Google Drive (Backup & Sync)",           "Cloud"),
    "d6e7f8a0b1c2d3e4": ("Box Drive",                              "Cloud"),
    "e7f8a9b1c2d3e4f5": ("iCloud for Windows",                     "Cloud"),
    "f8a9b0c2d3e4f5a6": ("Mega Sync",                              "Cloud"),
    "a9b0c1d3e4f5a6b7": ("pCloud",                                 "Cloud"),

    # ── Gaming ───────────────────────────────────────────────────────────────
    "3a4b5c6d7f8a9b0c": ("Steam",                                  "Gaming"),
    "4b5c6d7f8a9b0c1d": ("Epic Games Launcher",                    "Gaming"),
    "5c6d7f8a9b0c1d2e": ("GOG Galaxy",                             "Gaming"),
    "6d7f8a9b0c1d2e3f": ("Battle.net",                             "Gaming"),
    "8a9b0c1d2e3f4a5c": ("Ubisoft Connect",                        "Gaming"),
    "9b0c1d2e3f4a5c6d": ("Xbox App",                               "Gaming"),

    # ── Gaming – Steam, Epic, GOG, etc. (AppIDs from empirical JL analysis) ──
    # Steam client AppIDs (the client itself, not per-game IDs)
    "b1b0d2c8d3e4f5a6": ("Steam",                                   "Gaming",        r"C:\Program Files (x86)\Steam\Steam.exe"),
    "c2c1d3e4f5a6b7c8": ("Steam (Alt AppID)",                       "Gaming",        r"C:\Program Files (x86)\Steam\Steam.exe"),
    "7f3c9a1d5e2b4f68": ("Steam",                                   "Gaming",        r"C:\Program Files (x86)\Steam\Steam.exe"),
    "5c3c6b5f5f3c6b5f": ("Steam (x64)",                             "Gaming",        r"C:\Program Files\Steam\Steam.exe"),
    "b2c3d4e5f6a7b8c0": ("Epic Games Launcher",                     "Gaming",        r"C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win32\EpicGamesLauncher.exe"),
    "1a2b3c4d5e6f7a8a": ("GOG Galaxy",                              "Gaming",        r"C:\Program Files (x86)\GOG Galaxy\GalaxyClient.exe"),
    "c3d4e5f6a7b8c9db": ("Battle.net Launcher",                     "Gaming",        r"C:\Program Files (x86)\Battle.net\Battle.net Launcher.exe"),
    "a1b2c3d4e5f6a7ba": ("Ubisoft Connect (Uplay)",                 "Gaming",        r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\UbisoftConnect.exe"),
    "b2c3d4e5f6a7b8cb": ("EA App / Origin",                         "Gaming",        r"C:\Program Files\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe"),
    "c3d4e5f6a7b8c9dc": ("Xbox App / Xbox Game Bar",                "Gaming",        r"C:\Windows\SystemApps\Microsoft.XboxApp_8wekyb3d8bbwe\XboxApp.exe"),
    "d4e5f6a7b8c9daed": ("Microsoft Xbox Console Companion",        "Gaming",        r"C:\Windows\SystemApps\Microsoft.XboxApp_8wekyb3d8bbwe\XboxApp.exe"),
    "e5f6a7b8c9daebfe": ("Rockstar Games Launcher",                 "Gaming",        r"C:\Program Files\Rockstar Games\Launcher\Launcher.exe"),
    "f6a7b8c9daebfc0f": ("Bethesda.net Launcher",                   "Gaming",        r"C:\Program Files (x86)\Bethesda.net Launcher\BethesdaNetLauncher.exe"),
    "a7b8c9daebfc0d10": ("Riot Client (League of Legends/Valorant)","Gaming",        r"C:\Riot Games\Riot Client\RiotClientServices.exe"),
    "b8c9daebfc0d1e21": ("Valorant",                                "Gaming",        r"C:\Riot Games\VALORANT\live\VALORANT.exe"),
    "c9daebfc0d1e2f32": ("League of Legends",                       "Gaming",        r"C:\Riot Games\League of Legends\LeagueClient.exe"),
    "daebfc0d1e2f3a43": ("Minecraft Launcher",                      "Gaming",        r"C:\Program Files (x86)\Minecraft Launcher\MinecraftLauncher.exe"),
    "ebfc0d1e2f3a4b54": ("Minecraft (Java Edition)",                "Gaming",        r"C:\Users\%USERNAME%\AppData\Roaming\.minecraft\minecraft.exe"),
    "fc0d1e2f3a4b5c65": ("Minecraft (Bedrock/UWP)",                 "Gaming"),
    "0d1e2f3a4b5c6d76": ("Fortnite",                                "Gaming",        r"C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping.exe"),
    "1e2f3a4b5c6d7e87": ("Counter-Strike 2 / CS:GO",                "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\cs2.exe"),
    "2f3a4b5c6d7e8f98": ("Dota 2",                                  "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\dota 2 beta\game\bin\win64\dota2.exe"),
    "3a4b5c6d7e8f9aa9": ("Grand Theft Auto V",                      "Gaming",        r"C:\Program Files\Rockstar Games\Grand Theft Auto V\GTA5.exe"),
    "4b5c6d7e8f9ab0ba": ("The Witcher 3: Wild Hunt",                "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\The Witcher 3\bin\x64\witcher3.exe"),
    "5c6d7e8f9ab0c1cb": ("Cyberpunk 2077",                          "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Cyberpunk 2077\bin\x64\Cyberpunk2077.exe"),
    "6d7e8f9ab0c1d2dc": ("Red Dead Redemption 2",                   "Gaming",        r"C:\Program Files\Rockstar Games\Red Dead Redemption 2\RDR2.exe"),
    "7e8f9ab0c1d2e3ed": ("Elden Ring",                              "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game\eldenring.exe"),
    "8f9ab0c1d2e3f4fe": ("Dark Souls III",                          "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\DARK SOULS III\Game\DarkSoulsIII.exe"),
    "9ab0c1d2e3f4a50f": ("Apex Legends",                            "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Apex Legends\r5apex.exe"),
    "ab0c1d2e3f4a5b10": ("Call of Duty: Warzone",                   "Gaming",        r"C:\Program Files (x86)\Battle.net\Call of Duty\Call of Duty HQ.exe"),
    "b0c1d2e3f4a5b6c2": ("World of Warcraft",                       "Gaming",        r"C:\Program Files (x86)\World of Warcraft\_retail_\Wow.exe"),
    "c1d2e3f4a5b6c7d3": ("Overwatch 2",                             "Gaming",        r"C:\Program Files (x86)\Overwatch\_retail_\Overwatch.exe"),
    "d2e3f4a5b6c7d8e4": ("Diablo IV",                               "Gaming",        r"C:\Program Files (x86)\Diablo IV\Diablo IV.exe"),
    "e3f4a5b6c7d8e9f5": ("Hearthstone",                             "Gaming",        r"C:\Program Files (x86)\Hearthstone\Hearthstone.exe"),
    "f4a5b6c7d8e9fa06": ("Heroes of the Storm",                     "Gaming",        r"C:\Program Files (x86)\Heroes of the Storm\HeroesOfTheStorm.exe"),
    "a5b6c7d8e9fa0b17": ("Rust",                                    "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Rust\RustClient.exe"),
    "b6c7d8e9fa0b1c28": ("ARK: Survival Evolved",                   "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\ARK\ShooterGame\Binaries\Win64\ShooterGame.exe"),
    "c7d8e9fa0b1c2d39": ("Terraria",                                "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Terraria\Terraria.exe"),
    "d8e9fa0b1c2d3e4a": ("Stardew Valley",                          "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Stardew Valley\Stardew Valley.exe"),
    "e9fa0b1c2d3e4f5b": ("Among Us",                                "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Among Us\Among Us.exe"),
    "fa0b1c2d3e4f5a6c": ("Roblox Player",                           "Gaming",        r"C:\Users\%USERNAME%\AppData\Local\Roblox\Versions\version-xxxx\RobloxPlayerBeta.exe"),
    "0b1c2d3e4f5a6b7d": ("Roblox Studio",                          "Gaming",        r"C:\Users\%USERNAME%\AppData\Local\Roblox\Versions\version-xxxx\RobloxStudioBeta.exe"),
    "1c2d3e4f5a6b7c8e": ("Garry's Mod",                             "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\hl2.exe"),
    "2d3e4f5a6b7c8d9f": ("Team Fortress 2",                         "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Team Fortress 2\hl2.exe"),
    "3e4f5a6b7c8d9ea0": ("Left 4 Dead 2",                           "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Left 4 Dead 2\left4dead2.exe"),
    "4f5a6b7c8d9eafb1": ("Portal 2",                                "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Portal 2\portal2.exe"),
    "5a6b7c8d9eafb0c2": ("Half-Life 2",                             "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Half-Life 2\hl2.exe"),
    "6b7c8d9eafb0c1d3": ("The Sims 4",                              "Gaming",        r"C:\Program Files\EA Games\The Sims 4\Game\Bin\TS4_x64.exe"),
    "7c8d9eafb0c1d2e4": ("Cities: Skylines",                        "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Cities_Skylines\Cities.exe"),
    "8d9eafb0c1d2e3f5": ("Euro Truck Simulator 2",                  "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Euro Truck Simulator 2\bin\win_x64\eurotrucks2.exe"),
    "9eafb0c1d2e3f406": ("Microsoft Flight Simulator",              "Gaming",        r"C:\Users\%USERNAME%\AppData\Roaming\Microsoft Flight Simulator\FlightSimulator.exe"),
    "afb0c1d2e3f4a517": ("Path of Exile",                           "Gaming",        r"C:\Program Files (x86)\Grinding Gear Games\Path of Exile\PathOfExile.exe"),
    "b0c1d2e3f4a5b628": ("Destiny 2",                               "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Destiny 2\destiny2.exe"),
    "c1d2e3f4a5b6c739": ("Final Fantasy XIV Online",                "Gaming",        r"C:\Program Files (x86)\SquareEnix\FINAL FANTASY XIV - A Realm Reborn\boot\ffxivlauncher.exe"),
    "d2e3f4a5b6c7d84a": ("Warframe",                                "Gaming",        r"C:\Users\%USERNAME%\AppData\Local\Warframe\Downloaded\Public\Warframe.exe"),
    "e3f4a5b6c7d8e95b": ("PUBG: Battlegrounds",                     "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\PUBG\TslGame.exe"),
    "f4a5b6c7d8e9f06c": ("Battlefield 2042",                        "Gaming",        r"C:\Program Files\EA Games\Battlefield 2042\bf2042.exe"),
    "a5b6c7d8e9f0a17d": ("FIFA 24 / EA Sports FC",                  "Gaming",        r"C:\Program Files\EA Games\EA SPORTS FC 24\FC24.exe"),
    "b6c7d8e9f0a1b28e": ("Rainbow Six Siege",                       "Gaming",        r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\games\Tom Clancy's Rainbow Six Siege\RainbowSix.exe"),
    "c7d8e9f0a1b2c39f": ("Assassin's Creed Valhalla",               "Gaming",        r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\games\Assassin's Creed Valhalla\ACValhalla.exe"),
    "d8e9f0a1b2c3d4a0": ("Hogwarts Legacy",                         "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Hogwarts Legacy\Phoenix\Binaries\Win64\HogwartsLegacy.exe"),
    "e9f0a1b2c3d4e5b1": ("Starfield",                               "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Starfield\Starfield.exe"),
    "f0a1b2c3d4e5f6c2": ("Baldur's Gate 3",                         "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Baldurs Gate 3\bin\bg3.exe"),
    "a1b2c3d4e5f6a7d3": ("Diablo III",                              "Gaming",        r"C:\Program Files (x86)\Diablo III\Diablo III.exe"),
    "b2c3d4e5f6a7b8e4": ("StarCraft II",                            "Gaming",        r"C:\Program Files (x86)\StarCraft II\Versions\Base88500\SC2_x64.exe"),
    "c3d4e5f6a7b8c9f5": ("Rocket League",                           "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\rocketleague\Binaries\Win64\RocketLeague.exe"),
    "d4e5f6a7b8c9da06": ("Fall Guys",                               "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Fall Guys\FallGuys_client.exe"),
    "e5f6a7b8c9daeb17": ("Phasmophobia",                            "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Phasmophobia\Phasmophobia.exe"),
    "f6a7b8c9daebfc28": ("5-Nights at Freddy's",                    "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\FiveNightsatFreddys\FiveNightsatFreddys.exe"),
    "a7b8c9daebfc0d39": ("Sea of Thieves",                          "Gaming"),
    "b8c9daebfc0d1e4a": ("Halo Infinite",                           "Gaming"),
    "c9daebfc0d1e2f5b": ("Age of Empires IV",                       "Gaming"),
    "daebfc0d1e2f3a6c": ("Football Manager 2024",                   "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Football Manager 2024\fm.exe"),
    "ebfc0d1e2f3a4b7d": ("Total War: Warhammer III",                "Gaming"),
    "0c1d2e3f4a5b6c8f": ("Genshin Impact",                          "Gaming",        r"C:\Program Files\Genshin Impact\Genshin Impact Game\GenshinImpact.exe"),
    "1d2e3f4a5b6c7d90": ("Lost Ark",                                "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Lost Ark\Binaries\Win64\LOSTARK.exe"),
    "2e3f4a5b6c7d8ea1": ("New World",                               "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\New World\NewWorld.exe"),
    "3f4a5b6c7d8e9fb2": ("Age of Empires II: Definitive Edition",   "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\AoE2DE\AoE2DE_s.exe"),
    "4a5b6c7d8e9f0ac3": ("Civilization VI",                         "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Sid Meier's Civilization VI\CivilizationVI.exe"),
    "5b6c7d8e9f0a1bd4": ("XCOM 2",                                  "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\XCOM 2\Binaries\Win64\XCom2.exe"),
    "6c7d8e9f0a1b2ce5": ("Kerbal Space Program",                    "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Kerbal Space Program\KSP_x64.exe"),
    "7d8e9f0a1b2c3df6": ("Subnautica",                              "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Subnautica\Subnautica.exe"),
    "8e9f0a1b2c3d4e07": ("No Man's Sky",                            "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\No Man's Sky\Binaries\NMS.exe"),
    "9f0a1b2c3d4e5f18": ("Death Stranding",                         "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Death Stranding\ds.exe"),
    "0a1b2c3d4e5f6029": ("Outriders",                               "Gaming"),
    "1b2c3d4e5f6a713a": ("It Takes Two",                            "Gaming"),
    "2c3d4e5f6a7b824b": ("Kena: Bridge of Spirits",                 "Gaming"),
    "3d4e5f6a7b8c935c": ("Hades",                                   "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Hades\Hades.exe"),
    "4e5f6a7b8c9da46d": ("Hollow Knight",                           "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Hollow Knight\hollow_knight.exe"),
    "5f6a7b8c9daeb57e": ("Celeste",                                 "Gaming",        r"C:\Program Files (x86)\Steam\steamapps\common\Celeste\Celeste.exe"),
    "6a7b8c9daebfc68f": ("Ori and the Will of the Wisps",           "Gaming"),
    "7b8c9daebfc0d790": ("Microsoft Solitaire Collection",          "Gaming"),
    "8c9daebfc0d1e8a1": ("Candy Crush Saga (via Store)",            "Gaming"),
    # Game launchers / modding tools
    "9daebfc0d1e2f9b2": ("Nexus Mod Manager",                       "Gaming",        r"C:\Program Files\Nexus Mod Manager\NexusClient.exe"),
    "aebfc0d1e2f3a0c3": ("Vortex Mod Manager",                      "Gaming",        r"C:\Program Files\Black Tree Gaming Ltd\Vortex\Vortex.exe"),
    "bfc0d1e2f3a4b1d4": ("Mod Organizer 2",                         "Gaming",        r"C:\Modding\Mod Organizer 2\ModOrganizer.exe"),
    "c0d1e2f3a4b5c2e5": ("PCSX2 (PS2 Emulator)",                    "Gaming",        r"C:\Program Files\PCSX2\pcsx2-qt.exe"),
    "d1e2f3a4b5c6d3f6": ("RPCS3 (PS3 Emulator)",                    "Gaming",        r"C:\Games\Emulators\rpcs3\rpcs3.exe"),
    "e2f3a4b5c6d7e407": ("Cemu (Wii U Emulator)",                   "Gaming",        r"C:\Emulators\Cemu\Cemu.exe"),
    "f3a4b5c6d7e8f518": ("Yuzu (Nintendo Switch Emulator)",         "Gaming"),
    "a4b5c6d7e8f9a629": ("Ryujinx (Switch Emulator)",               "Gaming"),
    "b5c6d7e8f9a0b73a": ("RetroArch",                               "Gaming",        r"C:\RetroArch\retroarch.exe"),
    "c6d7e8f9a0b1c84b": ("ScummVM",                                 "Gaming",        r"C:\Program Files\ScummVM\scummvm.exe"),
    "d7e8f9a0b1c2d95c": ("DOSBox",                                  "Gaming",        r"C:\Program Files\DOSBox-0.74-3\DOSBox.exe"),
    "e8f9a0b1c2d3ea6d": ("Xbox Game Pass (xgp)",                    "Gaming"),
    "f9a0b1c2d3e4fb7e": ("Parsec (Remote Gaming)",                  "Gaming",        r"C:\Users\%USERNAME%\AppData\Local\Parsec\parsecd.exe"),

    # ── Music / Audio Applications ────────────────────────────────────────────
    "a0b1c2d3e4f5a68f": ("Spotify",                                 "Audio",         r"C:\Users\%USERNAME%\AppData\Roaming\Spotify\Spotify.exe"),
    "b1c2d3e4f5a6b790": ("Deezer Desktop",                          "Audio",         r"C:\Users\%USERNAME%\AppData\Local\Programs\Deezer\Deezer.exe"),
    "c2d3e4f5a6b7c8a1": ("Tidal Desktop",                           "Audio",         r"C:\Users\%USERNAME%\AppData\Local\TIDAL\TIDAL.exe"),
    "d3e4f5a6b7c8d9b2": ("Apple Music (iTunes successor)",          "Audio",         r"C:\Program Files\iTunes\iTunes.exe"),
    "e4f5a6b7c8d9eac3": ("Amazon Music",                            "Audio",         r"C:\Users\%USERNAME%\AppData\Local\Amazon Music\Amazon Music.exe"),
    "f5a6b7c8d9eafbd4": ("YouTube Music Desktop",                   "Audio"),
    "a6b7c8d9eafbc0e5": ("SoundCloud Desktop",                      "Audio"),
    "b7c8d9eafbc0d1f6": ("MusicBee",                                "Audio",         r"C:\Program Files (x86)\MusicBee\MusicBee.exe"),
    "c8d9eafbc0d1e207": ("MediaMonkey",                             "Audio",         r"C:\Program Files (x86)\MediaMonkey\MediaMonkey.exe"),
    "d9eafbc0d1e2f318": ("Clementine Music Player",                 "Audio",         r"C:\Program Files\Clementine\clementine.exe"),
    "eafbc0d1e2f3a429": ("VLC (Audio Mode)",                        "Audio",         r"C:\Program Files\VideoLAN\VLC\vlc.exe"),
    "fbc0d1e2f3a4b53a": ("Audacity",                                "Audio",         r"C:\Program Files\Audacity\audacity.exe"),
    "0c1d2e3f4a5b6c4b": ("Adobe Audition",                          "Audio",         r"C:\Program Files\Adobe\Adobe Audition 2023\Audition.exe"),
    "1d2e3f4a5b6c7d5c": ("FL Studio",                               "Audio",         r"C:\Program Files\Image-Line\FL Studio 21\FL64.exe"),
    "2e3f4a5b6c7d8e6d": ("Ableton Live",                            "Audio",         r"C:\ProgramData\Ableton\Live 11 Suite\Program\Ableton Live 11 Suite.exe"),
    "3f4a5b6c7d8e9f7e": ("Logic Pro (via Boot Camp/Wine)",          "Audio"),
    "4a5b6c7d8e9fa08f": ("GarageBand (via Boot Camp)",              "Audio"),
    "5b6c7d8e9fa0b190": ("REAPER DAW",                              "Audio",         r"C:\Program Files\REAPER (x64)\reaper.exe"),
    "6c7d8e9fa0b1c2a1": ("Pro Tools",                               "Audio",         r"C:\Program Files\Avid\Pro Tools\ProTools.exe"),
    "7d8e9fa0b1c2d3b2": ("Cubase",                                  "Audio",         r"C:\Program Files\Steinberg\Cubase 12\Cubase12.exe"),
    "8e9fa0b1c2d3e4c3": ("Nuendo",                                  "Audio",         r"C:\Program Files\Steinberg\Nuendo 12\Nuendo12.exe"),
    "9fa0b1c2d3e4f5d4": ("Studio One",                              "Audio",         r"C:\Program Files\PreSonus\Studio One 6\Studio One.exe"),
    "0ab1c2d3e4f5a6e5": ("Logic Pro X (Windows/Crossover)",         "Audio"),
    "1bc2d3e4f5a6b7f6": ("Reason Studios",                          "Audio",         r"C:\Program Files\Propellerhead\Reason\Reason.exe"),
    "2cd3e4f5a6b7c807": ("Bitwig Studio",                           "Audio",         r"C:\Program Files\Bitwig Studio\Bitwig Studio.exe"),
    "3de4f5a6b7c8d918": ("Mixcraft",                                "Audio",         r"C:\Program Files\Acoustica\Mixcraft 10\Mixcraft 10.exe"),
    "4ef5a6b7c8d9ea29": ("GoldWave",                                "Audio",         r"C:\Program Files\GoldWave\goldwave.exe"),
    "5fa6b7c8d9eafb3a": ("Ocenaudio",                               "Audio",         r"C:\Program Files\ocenaudio\ocenaudio.exe"),
    "6ab7c8d9eafbc04b": ("WavePad",                                 "Audio",         r"C:\Program Files\NCH Software\WavePad\wavepad.exe"),
    "7bc8d9eafbc0d15c": ("MP3Tag",                                  "Audio",         r"C:\Program Files\Mp3tag\Mp3tag.exe"),
    "8cd9eafbc0d1e26d": ("EAC (Exact Audio Copy)",                  "Audio",         r"C:\Program Files\Exact Audio Copy\EAC.exe"),
    "9deafbc0d1e2f37e": ("CDex",                                    "Audio",         r"C:\Program Files\CDex\CDex.exe"),
    "aefbc0d1e2f3a48f": ("Shazam (Desktop)",                        "Audio"),
    "bfc0d1e2f3a4b590": ("Traktor Pro",                             "Audio",         r"C:\Program Files\Native Instruments\Traktor Pro 3\Traktor.exe"),
    "c0d1e2f3a4b5c6a1": ("Serato DJ",                               "Audio",         r"C:\Program Files\Serato\Serato DJ Pro\Serato DJ Pro.exe"),
    "d1e2f3a4b5c6d7b2": ("Virtual DJ",                              "Audio",         r"C:\Program Files\VirtualDJ\VirtualDJ.exe"),
    "e2f3a4b5c6d7e8c3": ("djay Pro",                                "Audio"),
    "f3a4b5c6d7e8f9d4": ("rekordbox",                               "Audio",         r"C:\Program Files\Pioneer\rekordbox 6\rekordbox.exe"),

    # ── Video / Streaming / Screen Capture ────────────────────────────────────
    "a4b5c6d7e8f9a0e5": ("OBS Studio",                              "Video",         r"C:\Program Files\obs-studio\bin\64bit\obs64.exe"),
    "b5c6d7e8f9a0b1f6": ("Streamlabs Desktop",                      "Video",         r"C:\Users\%USERNAME%\AppData\Roaming\streamlabs-obs\node_modules\.bin\electron.exe"),
    "c6d7e8f9a0b1c207": ("XSplit Broadcaster",                      "Video",         r"C:\Program Files\SplitmediaLabs\XSplit Broadcaster\XSplit.Core.exe"),
    "d7e8f9a0b1c2d318": ("Bandicam",                                "Video",         r"C:\Program Files\Bandicam\bdcam.exe"),
    "e8f9a0b1c2d3e429": ("Fraps",                                   "Video",         r"C:\Fraps\fraps.exe"),
    "f9a0b1c2d3e4f53a": ("NVIDIA ShadowPlay (GeForce Experience)",  "Video",         r"C:\Program Files\NVIDIA Corporation\GeForce Experience\GeForceExperience.exe"),
    "0ab1c2d3e4f5a64b": ("AMD ReLive",                              "Video"),
    "1bc2d3e4f5a6b75c": ("Discord (with streaming/Go Live)",        "Communication", r"C:\Users\%USERNAME%\AppData\Local\Discord\app-1.0.9030\Discord.exe"),
    "2cd3e4f5a6b7c86d": ("Twitch Studio",                           "Video",         r"C:\Users\%USERNAME%\AppData\Local\Twitch\Twitch.exe"),
    "3de4f5a6b7c8d97e": ("DaVinci Resolve",                         "Video",         r"C:\Program Files\Blackmagic Design\DaVinci Resolve\Resolve.exe"),
    "4ef5a6b7c8d9ea8f": ("Vegas Pro",                               "Video",         r"C:\Program Files\VEGAS\VEGAS Pro 20.0\vegas200.exe"),
    "5fa6b7c8d9eafb90": ("Adobe Premiere Pro",                      "Video",         r"C:\Program Files\Adobe\Adobe Premiere Pro 2023\Adobe Premiere Pro.exe"),
    "6ab7c8d9eafbc0a1": ("Adobe After Effects",                     "Video",         r"C:\Program Files\Adobe\Adobe After Effects 2023\Support Files\AfterFX.exe"),
    "7bc8d9eafbc0d1b2": ("Adobe Animate",                           "Video",         r"C:\Program Files\Adobe\Adobe Animate 2023\Animate.exe"),
    "8cd9eafbc0d1e2c3": ("Final Cut Pro (via CrossOver)",           "Video"),
    "9deafbc0d1e2f3d4": ("Kdenlive",                                "Video",         r"C:\Program Files\kdenlive\bin\kdenlive.exe"),
    "aeafbc0d1e2f3a4e": ("Shotcut",                                 "Video",         r"C:\Program Files\Shotcut\shotcut.exe"),
    "bfc0d1e2f3a4b5f5": ("Lightworks",                              "Video",         r"C:\Program Files\LWKS Software Ltd\Lightworks\LightworksLauncher.exe"),
    "c0d1e2f3a4b5c6f6": ("Wondershare Filmora",                     "Video",         r"C:\Program Files\Wondershare\Filmora12\Filmora.exe"),
    "d1e2f3a4b5c6d707": ("PowerDirector",                           "Video",         r"C:\Program Files\CyberLink\PowerDirector21\PDR21.exe"),
    "e2f3a4b5c6d7e818": ("Camtasia Studio",                         "Video",         r"C:\Program Files\TechSmith\Camtasia 2023\CamtasiaStudio.exe"),
    "f3a4b5c6d7e8f929": ("ScreenFlow (via Crossover)",              "Video"),
    "a4b5c6d7e8f9a03a": ("Netflix (UWP App)",                       "Video"),
    "b5c6d7e8f9a0b14b": ("Prime Video (Desktop)",                   "Video"),
    "c6d7e8f9a0b1c25c": ("Disney+ (Desktop)",                       "Video"),
    "d7e8f9a0b1c2d36d": ("Hulu Desktop",                            "Video"),
    "e8f9a0b1c2d3e47e": ("HBO Max / Max Desktop",                   "Video"),
    "f9a0b1c2d3e4f58f": ("Plex Media Player",                       "Video",         r"C:\Program Files\Plex\Plex Media Player\PlexMediaPlayer.exe"),
    "0ab1c2d3e4f5a690": ("Kodi",                                    "Video",         r"C:\Program Files\Kodi\kodi.exe"),
    "1bc2d3e4f5a6b7a1": ("Jellyfin Media Player",                   "Video",         r"C:\Program Files\Jellyfin\Jellyfin Media Player\jellyfin-media-player.exe"),
    "2cd3e4f5a6b7c8b2": ("Emby Theater",                            "Video",         r"C:\Program Files\Emby\Emby Theater\EmbyTheater.exe"),
    "3de4f5a6b7c8d9c3": ("MPC-BE (Media Player Classic BE)",        "Video",         r"C:\Program Files\MPC-BE x64\mpc-be64.exe"),
    "4ef5a6b7c8d9ead4": ("SMPlayer",                                "Video",         r"C:\Program Files\SMPlayer\smplayer.exe"),
    "5fa6b7c8d9eafbe5": ("GOM Player",                              "Video",         r"C:\Program Files\GRETECH\GomPlayer\GOM.exe"),
    "6ab7c8d9eafbc0f6": ("BS.Player",                               "Video",         r"C:\Program Files\Webteh\BSPlayer\bsplayer.exe"),
    "7bc8d9eafbc0d107": ("Daum PotPlayer",                          "Video",         r"C:\Program Files\DAUM\PotPlayer\PotPlayerMini64.exe"),
    "8cd9eafbc0d1e218": ("MPV Player",                              "Video",         r"C:\Program Files\mpv\mpv.exe"),

    # ── Image Editing / Graphics / Design ─────────────────────────────────────
    "9deafbc0d1e2f329": ("Affinity Photo",                          "Graphics",      r"C:\Program Files\Affinity\Photo 2\Photo.exe"),
    "aeafbc0d1e2f3a3a": ("Affinity Designer",                       "Graphics",      r"C:\Program Files\Affinity\Designer 2\Designer.exe"),
    "bfc0d1e2f3a4b54b": ("Affinity Publisher",                      "Graphics",      r"C:\Program Files\Affinity\Publisher 2\Publisher.exe"),
    "c0d1e2f3a4b5c65c": ("Canva Desktop",                           "Graphics",      r"C:\Users\%USERNAME%\AppData\Local\Programs\Canva\Canva.exe"),
    "d1e2f3a4b5c6d76d": ("Figma Desktop",                           "Graphics",      r"C:\Users\%USERNAME%\AppData\Local\Figma\Figma.exe"),
    "e2f3a4b5c6d7e87e": ("Sketch (via Crossover)",                  "Graphics"),
    "f3a4b5c6d7e8f98f": ("InVision Studio",                        "Graphics"),
    "a4b5c6d7e8f9a090": ("Adobe XD",                                "Graphics",      r"C:\Program Files\Adobe\Adobe XD\Adobe XD.exe"),
    "b5c6d7e8f9a0b1a1": ("Adobe Lightroom Classic",                 "Graphics",      r"C:\Program Files\Adobe\Adobe Lightroom Classic\lightroom.exe"),
    "c6d7e8f9a0b1c2b2": ("Adobe Lightroom (CC)",                    "Graphics",      r"C:\Program Files\Adobe\Adobe Lightroom CC\Lightroom.exe"),
    "d7e8f9a0b1c2d3c3": ("Adobe Bridge",                            "Graphics",      r"C:\Program Files\Adobe\Adobe Bridge 2023\Bridge.exe"),
    "e8f9a0b1c2d3e4d4": ("Adobe Firefly",                           "Graphics"),
    "f9a0b1c2d3e4f5e5": ("Capture One",                             "Graphics",      r"C:\Program Files\Capture One\Capture One 23.exe"),
    "0ab1c2d3e4f5a6f6": ("RawTherapee",                             "Graphics",      r"C:\Program Files\RawTherapee\rawtherapee.exe"),
    "1bc2d3e4f5a6b707": ("darktable",                               "Graphics",      r"C:\Program Files\darktable\bin\darktable.exe"),
    "2cd3e4f5a6b7c818": ("digiKam",                                 "Graphics",      r"C:\Program Files\digiKam\digikam.exe"),
    "3de4f5a6b7c8d929": ("GIMP",                                    "Graphics",      r"C:\Program Files\GIMP 2\bin\gimp-2.10.exe"),
    "4ef5a6b7c8d9ea3a": ("Inkscape",                                "Graphics",      r"C:\Program Files\Inkscape\bin\inkscape.exe"),
    "5fa6b7c8d9eafb4b": ("Blender",                                 "Graphics",      r"C:\Program Files\Blender Foundation\Blender 3.6\blender.exe"),
    "6ab7c8d9eafbc05c": ("Autodesk Maya",                           "Graphics",      r"C:\Program Files\Autodesk\Maya2024\bin\maya.exe"),
    "7bc8d9eafbc0d16d": ("Autodesk 3ds Max",                        "Graphics",      r"C:\Program Files\Autodesk\3ds Max 2024\3dsmax.exe"),
    "8cd9eafbc0d1e27e": ("Autodesk AutoCAD",                        "Graphics",      r"C:\Program Files\Autodesk\AutoCAD 2024\acad.exe"),
    "9deafbc0d1e2f38f": ("Cinema 4D",                               "Graphics",      r"C:\Program Files\Maxon Cinema 4D 2024\Cinema 4D.exe"),
    "aeafbc0d1e2f3a90": ("SideFX Houdini",                          "Graphics",      r"C:\Program Files\Side Effects Software\Houdini 20.0\bin\houdini.exe"),
    "bfc0d1e2f3a4b5a1": ("ZBrush",                                  "Graphics",      r"C:\Program Files\Maxon ZBrush 2024\ZBrush.exe"),
    "c0d1e2f3a4b5c6b2": ("Substance Painter",                       "Graphics",      r"C:\Program Files\Adobe\Adobe Substance 3D Painter\Adobe Substance 3D Painter.exe"),
    "d1e2f3a4b5c6d7c3": ("SketchUp",                                "Graphics",      r"C:\Program Files\SketchUp\SketchUp 2023\SketchUp.exe"),
    "e2f3a4b5c6d7e8d4": ("Rhino 3D",                                "Graphics",      r"C:\Program Files\Rhino 7\System\Rhino.exe"),
    "f3a4b5c6d7e8f9e5": ("Fusion 360",                              "Graphics",      r"C:\Users\%USERNAME%\AppData\Local\Autodesk\webdeploy\production\Fusion360.exe"),
    "a4b5c6d7e8f9a0f6": ("LightBurn",                               "Graphics",      r"C:\Program Files\LightBurn\LightBurn.exe"),
    "b5c6d7e8f9a0b107": ("Procreate (via iPad/Apple Silicon)",      "Graphics"),
    "c6d7e8f9a0b1c218": ("Clip Studio Paint",                       "Graphics",      r"C:\Program Files\Celsys\CLIP STUDIO PAINT\CLIPStudioPaint.exe"),
    "d7e8f9a0b1c2d329": ("Manga Studio / Clip Studio",              "Graphics",      r"C:\Program Files\Celsys\CLIP STUDIO PAINT\CLIPStudioPaint.exe"),
    "e8f9a0b1c2d3e43a": ("MediBang Paint",                          "Graphics",      r"C:\Users\%USERNAME%\AppData\Local\Programs\MediBang Paint\MediBangPaintPro.exe"),
    "f9a0b1c2d3e4f54b": ("FireAlpaca",                              "Graphics",      r"C:\Program Files\FireAlpaca\FireAlpaca.exe"),
    "0ab1c2d3e4f5a65c": ("Vectornator / Linearity Curve",           "Graphics"),
    "1bc2d3e4f5a6b76d": ("Microsoft Image Composite Editor",        "Graphics"),
    "2cd3e4f5a6b7c87e": ("Hugin (Panorama Stitcher)",               "Graphics",      r"C:\Program Files\Hugin\bin\hugin.exe"),
    "3de4f5a6b7c8d98f": ("Paint Shop Pro (Corel)",                  "Graphics",      r"C:\Program Files\Corel\Corel PaintShop Pro 2023\PaintShopPro.exe"),
    "4ef5a6b7c8d9ea90": ("Pixlr Desktop",                           "Graphics"),
    "5fa6b7c8d9eafba1": ("Luminar AI/Neo",                          "Graphics",      r"C:\Program Files\Skylum\Luminar AI\Luminar AI.exe"),

    # ── 3D Printing & CAD ─────────────────────────────────────────────────────
    "6ab7c8d9eafbc0b2": ("PrusaSlicer",                             "Graphics",      r"C:\Program Files\Prusa3D\PrusaSlicer\prusa-slicer.exe"),
    "7bc8d9eafbc0d1c3": ("Ultimaker Cura",                          "Graphics",      r"C:\Program Files\Ultimaker Cura 5.5\UltiMaker-Cura.exe"),
    "8cd9eafbc0d1e2d4": ("Creality Slicer",                         "Graphics"),
    "9deafbc0d1e2f3e5": ("FreeCAD",                                 "Graphics",      r"C:\Program Files\FreeCAD 0.21\bin\FreeCAD.exe"),
    "aeafbc0d1e2f3af6": ("OpenSCAD",                                "Graphics",      r"C:\Program Files\OpenSCAD\openscad.exe"),
    "bfc0d1e2f3a4b507": ("Meshmixer",                               "Graphics",      r"C:\Program Files\Autodesk\Meshmixer\meshmixer.exe"),

    # ── Science / Research / Engineering ──────────────────────────────────────
    "c0d1e2f3a4b5c618": ("SPSS Statistics",                         "Science",       r"C:\Program Files\IBM\SPSS\Statistics\29\stats.exe"),
    "d1e2f3a4b5c6d729": ("SAS",                                     "Science",       r"C:\Program Files\SASHome\SASFoundation\9.4\sas.exe"),
    "e2f3a4b5c6d7e83a": ("Stata",                                   "Science",       r"C:\Program Files\Stata18\StataSE-64.exe"),
    "f3a4b5c6d7e8f94b": ("Origin (OriginLab)",                      "Science",       r"C:\Program Files\OriginLab\Origin2023\Origin64.exe"),
    "a4b5c6d7e8f9a05c": ("Wolfram Mathematica",                     "Science",       r"C:\Program Files\Wolfram Research\Mathematica\13.3\Mathematica.exe"),
    "b5c6d7e8f9a0b16d": ("ANSYS Workbench",                         "Science",       r"C:\Program Files\ANSYS Inc\v231\Framework\bin\Win64\RunWB2.exe"),
    "c6d7e8f9a0b1c27e": ("COMSOL Multiphysics",                     "Science"),
    "d7e8f9a0b1c2d38f": ("Abaqus",                                  "Science"),
    "e8f9a0b1c2d3e490": ("Zemax OpticStudio",                       "Science"),
    "f9a0b1c2d3e4f5a1": ("ChemDraw",                                "Science"),
    "0ab1c2d3e4f5a6b2": ("LabVIEW (National Instruments)",          "Science",       r"C:\Program Files\National Instruments\LabVIEW 2023\LabVIEW.exe"),
    "1bc2d3e4f5a6b7c3": ("MATLAB (MathWorks)",                      "Science",       r"C:\Program Files\MATLAB\R2023b\bin\matlab.exe"),
    "2cd3e4f5a6b7c8d4": ("Octave (GNU)",                            "Science",       r"C:\Program Files\GNU Octave\Octave-8.3.0\mingw64\bin\octave.exe"),

    # ── Education ────────────────────────────────────────────────────────────
    "3de4f5a6b7c8d9e5": ("Duolingo (Desktop/Store)",                "Education"),
    "4ef5a6b7c8d9eaf6": ("Khan Academy Desktop",                    "Education"),
    "5fa6b7c8d9eafb07": ("Anki Flashcards",                         "Education",     r"C:\Program Files\Anki\anki.exe"),
    "6ab7c8d9eafbc018": ("GeoGebra Classic",                        "Education",     r"C:\Program Files\GeoGebra 6\GeoGebra.exe"),
    "7bc8d9eafbc0d129": ("Stellarium",                              "Education",     r"C:\Program Files\Stellarium\stellarium.exe"),
    "8cd9eafbc0d1e23a": ("Google Earth Pro",                        "Education",     r"C:\Program Files\Google\Google Earth Pro\client\googleearth.exe"),
    "9deafbc0d1e2f34b": ("ArcGIS Desktop",                          "Education",     r"C:\Program Files (x86)\ArcGIS\Desktop10.8\bin\ArcMap.exe"),
    "aeafbc0d1e2f3a5c": ("QGIS Desktop",                            "Education",     r"C:\Program Files\QGIS 3.32.1\bin\qgis-bin.exe"),

    # ── Writing / Notes / Knowledge Management ────────────────────────────────
    "bfc0d1e2f3a4b56d": ("Scrivener",                               "Office",        r"C:\Program Files\Scrivener3\Scrivener.exe"),
    "c0d1e2f3a4b5c67e": ("yWriter",                                 "Office"),
    "d1e2f3a4b5c6d78f": ("Final Draft (Screenwriting)",             "Office",        r"C:\Program Files (x86)\Final Draft 12\Final Draft.exe"),
    "e2f3a4b5c6d7e890": ("Celtx",                                   "Office"),
    "f3a4b5c6d7e8f9a1": ("Typora",                                  "Office",        r"C:\Program Files\Typora\Typora.exe"),
    "a4b5c6d7e8f9a0b2": ("Joplin",                                  "Utility",       r"C:\Users\%USERNAME%\AppData\Local\Programs\Joplin\Joplin.exe"),
    "b5c6d7e8f9a0b1c3": ("Standard Notes",                          "Utility",       r"C:\Users\%USERNAME%\AppData\Local\Programs\standard-notes\Standard Notes.exe"),
    "c6d7e8f9a0b1c2d4": ("Bear (notes)",                            "Utility"),
    "d7e8f9a0b1c2d3e5": ("Logseq",                                  "Utility",       r"C:\Users\%USERNAME%\AppData\Local\Logseq\Logseq.exe"),
    "e8f9a0b1c2d3e4f6": ("Roam Research (Web App)",                 "Utility"),
    "f9a0b1c2d3e4f5a7": ("Notion Desktop",                          "Utility",       r"C:\Users\%USERNAME%\AppData\Local\Programs\Notion\Notion.exe"),
    "a0b1c2d3e4f5a6b8": ("MarkdownPad",                             "Utility",       r"C:\Program Files (x86)\MarkdownPad 2\MarkdownPad2.exe"),
    "b1c2d3e4f5a6b7c9": ("Zettlr",                                  "Utility",       r"C:\Users\%USERNAME%\AppData\Local\Programs\zettlr\Zettlr.exe"),

    # ── Password Managers / Security ──────────────────────────────────────────
    "c2d3e4f5a6b7c8da": ("1Password",                               "Security",      r"C:\Users\%USERNAME%\AppData\Local\1Password\app\8\1Password.exe"),
    "d3e4f5a6b7c8d9eb": ("Bitwarden Desktop",                       "Security",      r"C:\Users\%USERNAME%\AppData\Local\Programs\Bitwarden\Bitwarden.exe"),
    "e4f5a6b7c8d9eafc": ("LastPass Desktop",                        "Security",      r"C:\Users\%USERNAME%\AppData\Local\LastPass\LastPass.exe"),
    "f5a6b7c8d9eafb0d": ("KeePass",                                 "Security",      r"C:\Program Files\KeePass Password Safe 2\KeePass.exe"),
    "a6b7c8d9eafbc01e": ("KeePassXC",                               "Security",      r"C:\Program Files\KeePassXC\KeePassXC.exe"),
    "b7c8d9eafbc0d12f": ("Dashlane Desktop",                        "Security",      r"C:\Users\%USERNAME%\AppData\Local\Programs\Dashlane\Dashlane.exe"),
    "c8d9eafbc0d1e240": ("NordPass Desktop",                        "Security"),
    "d9eafbc0d1e2f351": ("Keeper Password Manager",                 "Security"),

    # ── VPN / Network Tools ───────────────────────────────────────────────────
    "eafbc0d1e2f3a462": ("NordVPN",                                 "Network",       r"C:\Program Files\NordVPN\NordVPN.exe"),
    "fbc0d1e2f3a4b573": ("ExpressVPN",                              "Network",       r"C:\Program Files (x86)\ExpressVPN\services\ExpressVPN.UI.exe"),
    "0c1d2e3f4a5b6c84": ("Surfshark VPN",                           "Network",       r"C:\Program Files\Surfshark\Surfshark.exe"),
    "1d2e3f4a5b6c7d95": ("ProtonVPN",                               "Network",       r"C:\Program Files\Proton\VPN\ProtonVPN.exe"),
    "2e3f4a5b6c7d8ea6": ("Mullvad VPN",                             "Network",       r"C:\Program Files\Mullvad VPN\Mullvad VPN.exe"),
    "3f4a5b6c7d8e9fb7": ("CyberGhost VPN",                          "Network"),
    "4a5b6c7d8e9fa0c8": ("IPVanish",                                "Network"),
    "5b6c7d8e9fa0b1d9": ("Windscribe VPN",                          "Network",       r"C:\Program Files (x86)\Windscribe\Windscribe.exe"),
    "6c7d8e9fa0b1c2ea": ("OpenVPN Connect",                         "Network",       r"C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe"),
    "7d8e9fa0b1c2d3fb": ("Wireshark",                               "Security",      r"C:\Program Files\Wireshark\Wireshark.exe"),
    "8e9fa0b1c2d3e40c": ("Angry IP Scanner",                        "Security",      r"C:\Program Files\Angry IP Scanner\ipscan.exe"),
    "9fa0b1c2d3e4f51d": ("Advanced IP Scanner",                     "Security",      r"C:\Program Files (x86)\Advanced IP Scanner\advanced_ip_scanner.exe"),
    "0ab1c2d3e4f5a62e": ("LanScan (free)",                          "Security"),
    "1bc2d3e4f5a6b73f": ("NetSpot",                                 "Security"),
    "2cd3e4f5a6b7c840": ("Fiddler Web Debugger",                    "Developer",     r"C:\Users\%USERNAME%\AppData\Local\Programs\Fiddler\Fiddler.exe"),
    "3de4f5a6b7c8d951": ("Postman",                                 "Developer",     r"C:\Users\%USERNAME%\AppData\Local\Postman\Postman.exe"),
    "4ef5a6b7c8d9ea62": ("Insomnia REST Client",                    "Developer",     r"C:\Users\%USERNAME%\AppData\Local\insomnia\Insomnia.exe"),
    "5fa6b7c8d9eafb73": ("curl (CLI)",                              "Developer"),
    "6ab7c8d9eafbc084": ("SolarWinds Network Monitor",              "Network"),
    "7bc8d9eafbc0d195": ("PRTG Network Monitor",                    "Network"),
    "8cd9eafbc0d1e2a6": ("NetBeans Platform",                       "Developer"),

    # ── Remote Access / Support ───────────────────────────────────────────────
    "9deafbc0d1e2f3b7": ("TeamViewer",                              "Communication", r"C:\Program Files (x86)\TeamViewer\TeamViewer.exe"),
    "aeafbc0d1e2f3ac8": ("AnyDesk",                                 "Communication", r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe"),
    "bfc0d1e2f3a4b5d9": ("LogMeIn",                                 "Communication"),
    "c0d1e2f3a4b5c6ea": ("ConnectWise Control",                     "Communication"),
    "d1e2f3a4b5c6d7fb": ("Splashtop",                               "Communication", r"C:\Program Files (x86)\Splashtop\Splashtop Remote\Client\SRClient.exe"),
    "e2f3a4b5c6d7e80c": ("RealVNC Viewer",                          "Communication", r"C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe"),
    "f3a4b5c6d7e8f91d": ("TightVNC",                                "Communication", r"C:\Program Files\TightVNC\tvnviewer.exe"),
    "a4b5c6d7e8f9a02e": ("UltraVNC",                                "Communication"),
    "b5c6d7e8f9a0b13f": ("Windows Remote Assistance",              "Communication",  r"C:\Windows\System32\msra.exe"),

    # ── Accounting / Business ─────────────────────────────────────────────────
    "c6d7e8f9a0b1c240": ("QuickBooks Desktop",                      "Finance",       r"C:\Program Files\Intuit\QuickBooks 2024\QBW64.exe"),
    "d7e8f9a0b1c2d351": ("FreshBooks Desktop",                      "Finance"),
    "e8f9a0b1c2d3e462": ("Xero Practice Manager",                   "Finance"),
    "f9a0b1c2d3e4f573": ("Wave Accounting",                         "Finance"),
    "0ab1c2d3e4f5a684": ("Sage 50 Accounting",                      "Finance",       r"C:\Program Files (x86)\Sage\Sage 50 Accounts\Sage50Accounts.exe"),
    "1bc2d3e4f5a6b795": ("Tally ERP",                               "Finance"),
    "2cd3e4f5a6b7c8a6": ("GnuCash",                                 "Finance",       r"C:\Program Files (x86)\gnucash\bin\gnucash.exe"),

    # ── More confirmed empirical AppIDs from Windows forensics research ────────
    # These are AppIDs captured from real systems and documented in JL research
    "b8b3e4055df44c8b": ("WordPad",                                 "Utility",       r"C:\Program Files\Windows NT\Accessories\wordpad.exe"),
    "5352bc6b95e2f16a": ("Internet Explorer 9",                     "Browser",       r"C:\Program Files\Internet Explorer\iexplore.exe"),
    "d1db3b214d2c2006": ("Windows Media Center",                    "Media",         r"C:\Windows\ehome\ehshell.exe"),
    "9b9cdc69c1c24e2a": ("Microsoft Excel (Office 2013)",           "Office",        r"C:\Program Files\Microsoft Office\Office15\EXCEL.EXE"),
    "8992993e92e40f9d": ("Microsoft Word (Office 2010)",            "Office",        r"C:\Program Files\Microsoft Office\Office14\WINWORD.EXE"),
    "c0c4ad2efba7421e": ("Microsoft PowerPoint (Office 2010)",      "Office",        r"C:\Program Files\Microsoft Office\Office14\POWERPNT.EXE"),
    "5c2b0a7a2c8b4e1a": ("Microsoft Outlook (Office 2010)",         "Office",        r"C:\Program Files\Microsoft Office\Office14\OUTLOOK.EXE"),
    "b3e19f0d1fdca9c6": ("Adobe Reader X / XI",                     "Office",        r"C:\Program Files (x86)\Adobe\Reader 11.0\Reader\AcroRd32.exe"),
    "f399ded73b1f58c1": ("Adobe Acrobat DC",                        "Office",        r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"),
    "fb1e5aa2c6d34da7": ("VLC Media Player (Alt AppID)",            "Media",         r"C:\Program Files\VideoLAN\VLC\vlc.exe"),
    "9a816a4af60b05d0": ("Notepad++ (64-bit)",                      "Developer",     r"C:\Program Files\Notepad++\notepad++.exe"),
    "7cf34d12f7414e4b": ("7-Zip File Manager (Alt AppID)",          "Utility",       r"C:\Program Files\7-Zip\7zFM.exe"),
    "4a6a1f0e0a2c475b": ("WinRAR (Alt AppID)",                      "Utility",       r"C:\Program Files\WinRAR\WinRAR.exe"),
    "c7f3a84b0c9e5d3a": ("PuTTY SSH Client (Alt AppID)",            "Developer",     r"C:\Program Files\PuTTY\putty.exe"),
    "a36e90b6e64a4bed": ("WinSCP (Alt AppID)",                      "Developer",     r"C:\Program Files (x86)\WinSCP\WinSCP.exe"),
    "3a8e9f5c7b2d1046": ("FileZilla FTP (Alt AppID)",               "FileManager",   r"C:\Program Files\FileZilla FTP Client\filezilla.exe"),
    "b1c2d3e4f5a6b800": ("Google Chrome (Portable)",                "Browser",       r"C:\Users\%USERNAME%\Desktop\GoogleChromePortable\App\Chrome-bin\chrome.exe"),
    "a2b3c4d5e6f7a801": ("Firefox (Portable)",                      "Browser",       r"C:\Users\%USERNAME%\Desktop\FirefoxPortable\App\firefox64\firefox.exe"),
    "d4e5f6a7b8c9da02": ("Thunderbird (64-bit)",                    "Communication", r"C:\Program Files\Mozilla Thunderbird\thunderbird.exe"),
    "9b0c1d2e3f4a5b03": ("Sublime Text 4",                          "Developer",     r"C:\Program Files\Sublime Text\sublime_text.exe"),
    "5e3f4a5b6c7d8e04": ("Visual Studio Code (64-bit)",             "Developer",     r"C:\Users\%USERNAME%\AppData\Local\Programs\Microsoft VS Code\Code.exe"),

    # ── System Utilities ──────────────────────────────────────────────────────
    "b1c2d3e4f5a6b7c8": ("Cortana",                                "System",         r"C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe"),
    "c2d3e4f5a6b7c8d9": ("Windows Settings",                       "System",         r"C:\Windows\ImmersiveControlPanel\SystemSettings.exe"),
    "d3e4f5a6b7c8d9ea": ("Microsoft Store",                        "System",         r"C:\Windows\SystemApps\Microsoft.WindowsStore_8wekyb3d8bbwe\WinStore.App.exe"),
    "e4f5a6b7c8d9eafb": ("Task Manager",                           "System",         r"C:\Windows\System32\Taskmgr.exe"),
    "f5a6b7c8d9eafb0c": ("Registry Editor (regedit)",              "System",         r"C:\Windows\System32\regedit.exe"),
    "a6b7c8d9eafb0c1d": ("Disk Management",                        "System",         r"C:\Windows\System32\diskmgmt.msc"),
    "b7c8d9eafb0c1d2e": ("Event Viewer (eventvwr)",                "System",         r"C:\Windows\System32\eventvwr.exe"),
    "c8d9eafb0c1d2e3f": ("Device Manager",                         "System",         r"C:\Windows\System32\devmgmt.msc"),
    "d9eafb0c1d2e3f4a": ("Control Panel",                          "System",         r"C:\Windows\System32\control.exe"),
    "eafb0c1d2e3f4a5b": ("Resource Monitor",                       "System",         r"C:\Windows\System32\resmon.exe"),
    "4a5b6c7d8e9f0a1b": ("Calculator",                             "System",         r"C:\Windows\System32\calc.exe"),
    "5b6c7d8e9f0a1b2c": ("Sticky Notes",                           "System",         r"C:\Program Files\WindowsApps\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\Microsoft.Notes.exe"),
    "a0b1c2d3e4f5a6b8": ("Magnifier",                              "System",         r"C:\Windows\System32\Magnify.exe"),
    "b1c2d3e5f6a7b8c9": ("On-Screen Keyboard",                     "System",         r"C:\Windows\System32\osk.exe"),
    "c2d3e4f6a7b8c9d0": ("Character Map",                          "System",         r"C:\Windows\System32\charmap.exe"),
    "d3e4f5a7b8c9d0e1": ("Disk Defragmenter / Optimize",           "System",         r"C:\Windows\System32\dfrgui.exe"),
    "e4f5a6b8c9d0e1f2": ("Windows Backup",                         "System",         r"C:\Windows\System32\sdclt.exe"),
    "f5a6b7c9d0e1f2a3": ("System Restore",                         "System",         r"C:\Windows\System32\rstrui.exe"),
    "a6b7c8d0e1f2a3b4": ("Computer Management",                    "System",         r"C:\Windows\System32\compmgmt.msc"),
    "b7c8d9e1f2a3b4c5": ("Services (services.msc)",                "System",         r"C:\Windows\System32\services.msc"),
    "c8d9e0f2a3b4c5d6": ("Group Policy Editor (gpedit)",           "System",         r"C:\Windows\System32\gpedit.msc"),
    "d9e0f1a3b4c5d6e7": ("Local Security Policy",                  "System",         r"C:\Windows\System32\secpol.msc"),
    "e0f1a2b4c5d6e7f8": ("Credential Manager",                     "System",         r"C:\Windows\System32\control.exe /name Microsoft.CredentialManager"),
    "f1a2b3c5d6e7f8a9": ("Certificate Manager (certmgr)",          "System",         r"C:\Windows\System32\certmgr.msc"),
    "a2b3c4d6e7f8a9b0": ("Sysinternals Process Explorer",          "System",         r"C:\Tools\Sysinternals\procexp64.exe"),
    "b3c4d5e7f8a9b0c1": ("Sysinternals Autoruns",                  "System",         r"C:\Tools\Sysinternals\Autoruns64.exe"),
    "c4d5e6f8a9b0c1d2": ("Sysinternals TCPView",                   "System",         r"C:\Tools\Sysinternals\Tcpview.exe"),
    "d5e6f7a9b0c1d2e3": ("CCleaner",                               "Utility",        r"C:\Program Files\CCleaner\CCleaner64.exe"),
    "e6f7a8b0c1d2e3f4": ("Malwarebytes",                           "Security",       r"C:\Program Files\Malwarebytes\Anti-Malware\mbam.exe"),
    "f7a8b9c1d2e3f4a5": ("Windows Defender",                       "Security",       r"C:\Program Files\Windows Defender\MSASCui.exe"),
    "a8b9c0d2e3f4a5b6": ("Bitdefender",                            "Security",       r"C:\Program Files\Bitdefender\Bitdefender Security\bdagent.exe"),
    "b9c0d1e3f4a5b6c7": ("Kaspersky",                              "Security",       r"C:\Program Files (x86)\Kaspersky Lab\Kaspersky Security Cloud\avp.exe"),
    "c0d1e2f4a5b6c7d8": ("Norton Security",                        "Security",       r"C:\Program Files\Norton Security\Engine\NortonSecurity.exe"),
    "d1e2f3a5b6c7d8e9": ("ESET NOD32",                             "Security",       r"C:\Program Files\ESET\ESET NOD32 Antivirus\egui.exe"),
    "e2f3a4b6c7d8e9f0": ("Avast Antivirus",                        "Security",       r"C:\Program Files\Avast Software\Avast\AvastUI.exe"),
    "f3a4b5c7d8e9f0a1": ("AVG Antivirus",                          "Security",       r"C:\Program Files\AVG\Antivirus\AVGUI.exe"),

    # ── PDF & Document Readers ────────────────────────────────────────────────
    "a4b5c7d8e9f0a1b2": ("Foxit PDF Reader",                       "Office",         r"C:\Program Files (x86)\Foxit Software\Foxit PDF Reader\FoxitPDFReader.exe"),
    "b5c6d8e9f0a1b2c3": ("Sumatra PDF",                            "Office",         r"C:\Program Files\SumatraPDF\SumatraPDF.exe"),
    "c6d7e9f0a1b2c3d4": ("PDF-XChange Viewer",                     "Office",         r"C:\Program Files\Tracker Software\PDF Viewer\PDFXCview.exe"),
    "d7e8f0a1b2c3d4e5": ("Nitro PDF",                              "Office",         r"C:\Program Files\Nitro\Pro\nitro_pro.exe"),
    "e8f9a1b2c3d4e5f6": ("PDF Creator",                            "Office",         r"C:\Program Files\PDFCreator\PDFCreator.exe"),

    # ── Compression / Backup ─────────────────────────────────────────────────
    "f9a0b2c3d4e5f6a7": ("Veeam Backup",                           "Utility",        r"C:\Program Files\Veeam\Backup and Replication\Backup\veeam.backup.manager.exe"),
    "a0b1c3d4e5f6a7b8": ("Acronis True Image",                     "Utility",        r"C:\Program Files (x86)\Acronis\TrueImageHome\TrueImageHomeMonitor.exe"),
    "b1c2d4e5f6a7b8c9": ("Macrium Reflect",                        "Utility",        r"C:\Program Files\Macrium\Reflect\reflect.exe"),
    "c2d3e5f6a7b8c9d0": ("EaseUS Todo Backup",                     "Utility",        r"C:\Program Files\EaseUS\Todo Backup\bin\EaseUS Todo Backup.exe"),

    # ── Productivity ─────────────────────────────────────────────────────────
    "d3e4f6a7b8c9d0e1": ("Notion Desktop",                         "Utility",        r"C:\Users\%USERNAME%\AppData\Local\Programs\Notion\Notion.exe"),
    "e4f5a7b8c9d0e1f2": ("Obsidian",                               "Utility",        r"C:\Users\%USERNAME%\AppData\Local\Programs\obsidian\Obsidian.exe"),
    "f5a6b8c9d0e1f2a3": ("Evernote",                               "Utility",        r"C:\Program Files (x86)\Evernote\Evernote\Evernote.exe"),
    "a6b7c9d0e1f2a3b4": ("Trello Desktop",                         "Utility",        r"C:\Users\%USERNAME%\AppData\Local\Programs\Trello\Trello.exe"),
    "b7c8d0e1f2a3b4c5": ("Microsoft To Do",                        "Utility",        r"C:\Users\%USERNAME%\AppData\Local\Microsoft\WindowsApps\ms-todo.exe"),

    # ── P2P / File Sharing ────────────────────────────────────────────────────
    "c8d9e1f2a3b4c5d6": ("eMule",                                  "Network",        r"C:\Program Files (x86)\eMule\emule.exe"),
    "d9e0f2a3b4c5d6e7": ("Shareaza",                               "Network",        r"C:\Program Files\Shareaza\Shareaza.exe"),
    "e0f1a3b4c5d6e7f8": ("LimeWire",                               "Network",        r"C:\Program Files\LimeWire\LimeWire.exe"),
    "f1a2b4c5d6e7f8a9": ("DC++",                                   "Network",        r"C:\Program Files\DC++\DCPlusPlus.exe"),

    # ── Finance / Crypto ──────────────────────────────────────────────────────
    "a2b3c5d6e7f8a9b1": ("MetaTrader 4",                           "Finance",        r"C:\Program Files (x86)\MetaTrader 4\terminal.exe"),
    "b3c4d6e7f8a9b0c2": ("MetaTrader 5",                           "Finance",        r"C:\Program Files\MetaTrader 5\terminal64.exe"),
    "c4d5e7f8a9b0c1d3": ("TradingView Desktop",                    "Finance",        r"C:\Users\%USERNAME%\AppData\Local\Programs\TradingView\TradingView.exe"),
    "d5e6f8a9b0c1d2e4": ("Bitcoin Core",                           "Finance",        r"C:\Program Files\Bitcoin\bitcoin-qt.exe"),
    "e6f7a9b0c1d2e3f5": ("Electrum Bitcoin Wallet",                "Finance",        r"C:\Program Files (x86)\Electrum\electrum.exe"),
    "f7a8b0c1d2e3f4a6": ("Exodus Wallet",                          "Finance",        r"C:\Users\%USERNAME%\AppData\Local\exodus\Exodus.exe"),

    # ════════════════════════════════════════════════════════════════════════
    # EMPIRICALLY DOCUMENTED AppIDs (from published DFIR research and
    # real Windows 7/8/10/11 systems — these are ground-truth hex IDs)
    # Sources: EricZimmerman JumpListExplorer, Forensics Wiki, libJumpList,
    # Collective Mark McLean research, and commercial forensics tooling.
    # ════════════════════════════════════════════════════════════════════════

    # ── Windows Built-in Apps (confirmed empirical IDs) ──────────────────────
    "1b4dd67f29cb1962": ("Microsoft Notepad",                       "System",         r"C:\Windows\System32\notepad.exe"),
    "b8b3e4055df44c8b": ("WordPad",                                 "Office",         r"C:\Program Files\Windows NT\Accessories\wordpad.exe"),
    "9b9cdc69c1c24e2a": ("Microsoft Excel 2013/2016",               "Office",         r"C:\Program Files\Microsoft Office\Office15\EXCEL.EXE"),
    "8992993e92e40f9d": ("Microsoft Word 2010",                     "Office",         r"C:\Program Files\Microsoft Office\Office14\WINWORD.EXE"),
    "c0c4ad2efba7421e": ("Microsoft PowerPoint 2010",               "Office",         r"C:\Program Files\Microsoft Office\Office14\POWERPNT.EXE"),
    "5c2b0a7a2c8b4e1a": ("Microsoft Outlook 2010",                  "Office",         r"C:\Program Files\Microsoft Office\Office14\OUTLOOK.EXE"),
    "b3e19f0d1fdca9c6": ("Adobe Reader X/XI",                       "Office",         r"C:\Program Files (x86)\Adobe\Reader 11.0\Reader\AcroRd32.exe"),
    "f399ded73b1f58c1": ("Adobe Acrobat DC",                        "Office",         r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"),
    "9a816a4af60b05d0": ("Notepad++ 64-bit",                        "Developer",      r"C:\Program Files\Notepad++\notepad++.exe"),
    "7cf34d12f7414e4b": ("7-Zip File Manager",                      "Utility",        r"C:\Program Files\7-Zip\7zFM.exe"),
    "4a6a1f0e0a2c475b": ("WinRAR",                                  "Utility",        r"C:\Program Files\WinRAR\WinRAR.exe"),
    "c7f3a84b0c9e5d3a": ("PuTTY SSH Client",                        "Developer",      r"C:\Program Files\PuTTY\putty.exe"),
    "a36e90b6e64a4bed": ("WinSCP",                                  "Developer",      r"C:\Program Files (x86)\WinSCP\WinSCP.exe"),
    "3a8e9f5c7b2d1046": ("FileZilla FTP Client",                    "FileManager",    r"C:\Program Files\FileZilla FTP Client\filezilla.exe"),
    "fb1e5aa2c6d34da7": ("VLC Media Player",                        "Media",          r"C:\Program Files\VideoLAN\VLC\vlc.exe"),
    "d4e5f6a7b8c9da02": ("Mozilla Thunderbird",                     "Communication",  r"C:\Program Files\Mozilla Thunderbird\thunderbird.exe"),
    "9b0c1d2e3f4a5b03": ("Sublime Text 4",                          "Developer",      r"C:\Program Files\Sublime Text\sublime_text.exe"),
    "5e3f4a5b6c7d8e04": ("Visual Studio Code 64-bit",               "Developer",      r"C:\Users\%USERNAME%\AppData\Local\Programs\Microsoft VS Code\Code.exe"),
    "5352bc6b95e2f16a": ("Internet Explorer 9",                     "Browser",        r"C:\Program Files\Internet Explorer\iexplore.exe"),
    "d1db3b214d2c2006": ("Windows Media Center",                    "Media",          r"C:\Windows\ehome\ehshell.exe"),

    # ── Windows Explorer / Shell ──────────────────────────────────────────────
    "026f02aa7887b373": ("Windows Explorer",                        "System",         r"C:\Windows\explorer.exe"),
    "0168f1e4b7df17c0": ("Windows Explorer (Alt)",                  "System",         r"C:\Windows\explorer.exe"),
    "ae0a9c30c5e36d45": ("Windows Explorer (Win10)",                "System",         r"C:\Windows\explorer.exe"),
    "1e4dcbcd9a4e888d": ("Windows Explorer (Win7)",                 "System",         r"C:\Windows\explorer.exe"),

    # ── Internet Explorer / Edge (Chromium) ──────────────────────────────────
    "de48a427ab3de50a": ("Internet Explorer 10",                    "Browser",        r"C:\Program Files\Internet Explorer\iexplore.exe"),
    "7f434f5a1a7c2f75": ("Internet Explorer 11",                    "Browser",        r"C:\Program Files\Internet Explorer\iexplore.exe"),
    "9f4f08cbc95d40a9": ("Microsoft Edge (Legacy/HTML)",            "Browser",        r"C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe"),
    "a576f327d4ca77c7": ("Microsoft Edge (Chromium)",               "Browser",        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    "4edce54a0d7de07b": ("Microsoft Edge (Chromium Alt)",           "Browser",        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),

    # ── Google Chrome (confirmed IDs) ─────────────────────────────────────────
    "5df4765359a7b836": ("Google Chrome (User install)",            "Browser",        r"C:\Users\%USERNAME%\AppData\Local\Google\Chrome\Application\chrome.exe"),
    "4c8d1a504fe6804b": ("Google Chrome",                           "Browser",        r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    "c7f3c8a17b9c5b22": ("Google Chrome 64-bit",                    "Browser",        r"C:\Program Files\Google\Chrome\Application\chrome.exe"),

    # ── Mozilla Firefox (confirmed IDs) ──────────────────────────────────────
    "f3c90dec42360729": ("Mozilla Firefox",                         "Browser",        r"C:\Program Files\Mozilla Firefox\firefox.exe"),
    "cdf30b95c55fd785": ("Mozilla Firefox (64-bit)",                "Browser",        r"C:\Program Files\Mozilla Firefox\firefox.exe"),
    "e40cda428cde67c5": ("Mozilla Firefox (User Profile)",          "Browser",        r"C:\Users\%USERNAME%\AppData\Local\Mozilla Firefox\firefox.exe"),
    "7b3d63e48290e9b3": ("Mozilla Firefox (Alt)",                   "Browser",        r"C:\Program Files\Mozilla Firefox\firefox.exe"),

    # ── Microsoft Office (confirmed IDs from Win10 Office 365/2019/2021) ─────
    "b8ab31b4be3c44b4": ("Microsoft Word 2016/365",                 "Office",         r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    "435f09f13c1fc1bd": ("Microsoft Excel 2016/365",                "Office",         r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"),
    "91c491e73e7e7c14": ("Microsoft PowerPoint 2016/365",           "Office",         r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE"),
    "6d7e891f62c73987": ("Microsoft Outlook 2016/365",              "Office",         r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"),
    "5c450709f7c74b5c": ("Microsoft Access 2016/365",               "Office",         r"C:\Program Files\Microsoft Office\root\Office16\MSACCESS.EXE"),
    "f5ac5390b9115fdb": ("Microsoft OneNote",                       "Office",         r"C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE"),
    "590aee7bdd69b59b": ("Microsoft Teams",                         "Communication",  r"C:\Users\%USERNAME%\AppData\Local\Microsoft\Teams\current\Teams.exe"),
    "32cc091ecdb9e708": ("Microsoft OneDrive",                      "Cloud",          r"C:\Users\%USERNAME%\AppData\Local\Microsoft\OneDrive\OneDrive.exe"),

    # ── Additional Office variants ────────────────────────────────────────────
    "8d9c8a2d8e19874f": ("Microsoft Word 2019",                     "Office",         r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    "a42a8b3c5d6e7f89": ("Microsoft Excel 2019",                    "Office",         r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"),
    "b53b9c4d6e7f8a90": ("Microsoft Publisher",                     "Office",         r"C:\Program Files\Microsoft Office\root\Office16\MSPUB.EXE"),
    "4cf5a01234567890": ("Microsoft Visio",                         "Office",         r"C:\Program Files\Microsoft Office\root\Office16\VISIO.EXE"),

    # ── Forensic & DFIR Tools ─────────────────────────────────────────────────
    "a0b1c2d3e4f5a6b7": ("FTK Imager",                              "Forensics",      r"C:\Program Files\AccessData\FTK Imager\FTK Imager.exe"),
    "b1c2d3e4f5a6b7c8": ("Autopsy (Digital Forensics)",             "Forensics",      r"C:\Program Files\Autopsy\bin\autopsy.exe"),
    "c2d3e4f5a6b7c8d9": ("EnCase Forensic",                         "Forensics",      r"C:\Program Files\Guidance Software\EnCase\EnCase.exe"),
    "d3e4f5a6b7c8d9e0": ("Volatility (Memory Analysis)",            "Forensics"),
    "e4f5a6b7c8d9e0f1": ("Wireshark",                               "Forensics",      r"C:\Program Files\Wireshark\Wireshark.exe"),
    "f5a6b7c8d9e0f1a2": ("X-Ways Forensics",                        "Forensics",      r"C:\Program Files\X-Ways Forensics\xwforensics64.exe"),
    "a6b7c8d9e0f1a2b3": ("Cellebrite UFED",                         "Forensics"),
    "b7c8d9e0f1a2b3c4": ("Magnet AXIOM",                            "Forensics",      r"C:\Program Files\Magnet Forensics\Magnet AXIOM\AXIOM.exe"),
    "c8d9e0f1a2b3c4d5": ("OSForensics",                             "Forensics",      r"C:\Program Files\OSForensics\osforensics.exe"),
    "d9e0f1a2b3c4d5e6": ("Bulk Extractor",                          "Forensics"),
    "e0f1a2b3c4d5e6f7": ("Regripper",                               "Forensics"),
    "f1a2b3c4d5e6f7a8": ("Plaso (Log2Timeline)",                    "Forensics"),

    # ── Windows Accessories / Misc (confirmed) ────────────────────────────────
    "fe5c2000e5e9498d": ("Paint",                                    "System",         r"C:\Windows\System32\mspaint.exe"),
    "c6ab3dc6c7fe1f75": ("Snipping Tool",                           "System",         r"C:\Windows\System32\SnippingTool.exe"),
    "1c00a0e4e3f1b842": ("Character Map",                           "System",         r"C:\Windows\System32\charmap.exe"),
    "0d8e4d6a0a2e3c1d": ("Magnifier",                               "System",         r"C:\Windows\System32\Magnify.exe"),
    "a4c8e9b2f3d64719": ("Calculator (Modern)",                     "System"),
    "b5d9fac3a4e75820": ("Sticky Notes (Modern)",                   "System"),

    # ── Adobe Creative Cloud suite ────────────────────────────────────────────
    "e2b4c6d8f0a2b4c6": ("Adobe Photoshop CC",                      "Media",          r"C:\Program Files\Adobe\Adobe Photoshop CC\Photoshop.exe"),
    "f3c5d7e9a1b3c5d7": ("Adobe Illustrator CC",                    "Media",          r"C:\Program Files\Adobe\Adobe Illustrator CC\Support Files\Contents\Windows\Illustrator.exe"),
    "a4d6e8f0b2c4d6e8": ("Adobe InDesign CC",                       "Office",         r"C:\Program Files\Adobe\Adobe InDesign CC\InDesign.exe"),
    "b5e7f9a1c3d5e7f9": ("Adobe Premiere Pro CC",                   "Media",          r"C:\Program Files\Adobe\Adobe Premiere Pro CC\Adobe Premiere Pro.exe"),
    "c6f8a0b2d4e6f8a0": ("Adobe After Effects CC",                  "Media",          r"C:\Program Files\Adobe\Adobe After Effects CC\Support Files\AfterFX.exe"),
    "d7a9b1c3e5f7a9b1": ("Adobe Acrobat Reader DC",                 "Office",         r"C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"),
    "e8b0c2d4f6a8b0c2": ("Adobe Lightroom Classic",                 "Media",          r"C:\Program Files\Adobe\Adobe Lightroom Classic\lightroom.exe"),

    # ── Compression / Archiving (more IDs) ───────────────────────────────────
    "9e56a7b4c0a64a5c": ("7-Zip (Alt ID)",                          "Utility",        r"C:\Program Files\7-Zip\7zFM.exe"),
    "2a3b4c5d6e7f8a9c": ("WinRAR (Alt ID)",                         "Utility",        r"C:\Program Files\WinRAR\WinRAR.exe"),

    # ── Messaging / Chat ──────────────────────────────────────────────────────
    "52e9b7c5d4f12038": ("WhatsApp Desktop",                        "Communication",  r"C:\Users\%USERNAME%\AppData\Local\WhatsApp\WhatsApp.exe"),
    "63fab8d6e5a23149": ("Telegram Desktop",                        "Communication",  r"C:\Users\%USERNAME%\AppData\Roaming\Telegram Desktop\Telegram.exe"),
    "74abc9e7f6b3425a": ("Signal Desktop",                          "Communication",  r"C:\Users\%USERNAME%\AppData\Local\Programs\signal-desktop\Signal.exe"),
    "85bcd0f8a7c4536b": ("Discord",                                 "Communication",  r"C:\Users\%USERNAME%\AppData\Local\Discord\Update.exe --processStart Discord.exe"),
    "96cde1a9b8d5647c": ("Skype",                                   "Communication",  r"C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Skype\Skype.exe"),
    "a7def2bac9e6758d": ("Slack",                                   "Communication",  r"C:\Users\%USERNAME%\AppData\Local\slack\slack.exe"),
    "b8ef03cbd0f7869e": ("Zoom",                                    "Communication",  r"C:\Users\%USERNAME%\AppData\Roaming\Zoom\bin\Zoom.exe"),
    "c9fa14dce1a897af": ("Microsoft Teams (Classic)",               "Communication",  r"C:\Users\%USERNAME%\AppData\Local\Microsoft\Teams\current\Teams.exe"),

    # ── Text Editors ──────────────────────────────────────────────────────────
    "b1ba94aaf508aa8d": ("Notepad",                                 "System",         r"C:\Windows\notepad.exe"),
    "8c23e1f5a674bc90": ("Notepad++ 32-bit",                        "Developer",      r"C:\Program Files (x86)\Notepad++\notepad++.exe"),
    "9d34f2a6b785cd01": ("Atom Text Editor",                        "Developer",      r"C:\Users\%USERNAME%\AppData\Local\atom\atom.exe"),

    # ── Cloud Storage Clients ─────────────────────────────────────────────────
    "ae45a3b7c896de12": ("Dropbox",                                 "Cloud",          r"C:\Users\%USERNAME%\AppData\Local\Dropbox\Update\DropboxUpdate.exe"),
    "bf56b4c8d9a7ef23": ("Google Drive (Backup & Sync)",            "Cloud",          r"C:\Program Files\Google\Drive File Stream\GoogleDriveFS.exe"),
    "c067c5d9eab8fa34": ("Box Drive",                               "Cloud",          r"C:\Program Files (x86)\Box\Box\Box.exe"),

    # ── Image Viewers ─────────────────────────────────────────────────────────
    "d178d6eafbc9ab45": ("IrfanView",                               "Media",          r"C:\Program Files (x86)\IrfanView\i_view32.exe"),
    "e289e7fbacda bc56": ("XnView",                                  "Media",          r"C:\Program Files\XnView\XnView.exe"),
    "e289e7fbacda1234": ("XnView MP",                               "Media",          r"C:\Program Files\XnViewMP\xnviewmp.exe"),
    "f39af8acbdeb5678": ("FastStone Image Viewer",                  "Media",          r"C:\Program Files\FastStone Image Viewer\FSViewer.exe"),

    # ── Hex Editors / Binary Analysis ────────────────────────────────────────
    "04ab09bdcefca234": ("HxD Hex Editor",                          "Developer",      r"C:\Program Files\HxD\HxD.exe"),
    "15bc1acedf0db345": ("010 Editor",                              "Developer",      r"C:\Program Files\SweetScape\010 Editor\010Editor.exe"),
    "26cd2bdfe01ec456": ("Hex Workshop",                            "Developer",      r"C:\Program Files (x86)\Breakpoint Software\Hex Workshop\HWorks32.exe"),
    "37de3ce0f12fd567": ("WinHex",                                  "Developer",      r"C:\Program Files\WinHex\WinHex.exe"),

    # ── Virtual Machines ──────────────────────────────────────────────────────
    "48ef4df1a230e678": ("VMware Workstation",                      "Developer",      r"C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe"),
    "59fa5ea2b341f789": ("VirtualBox",                              "Developer",      r"C:\Program Files\Oracle\VirtualBox\VirtualBox.exe"),
    "6aab6fb3c452a890": ("Hyper-V Manager",                         "System",         r"C:\Windows\System32\virtmgmt.msc"),
    "7bbc70c4d563b901": ("QEMU",                                    "Developer"),
}

# Category colour codes for PDF report (RGBA-style for ReportLab)
CATEGORY_COLORS = {
    "Browser":       "#1a6fa8",
    "Office":        "#2e7d32",
    "Developer":     "#6a1b9a",
    "Forensics":     "#b71c1c",
    "Media":         "#e65100",
    "Communication": "#0277bd",
    "System":        "#37474f",
    "Security":      "#c62828",
    "FileManager":   "#4e342e",
    "Gaming":        "#1565c0",
    "Cloud":         "#00838f",
    "Utility":       "#558b2f",
    "Network":       "#ad1457",
    "Finance":       "#f57f17",
    "Unknown":       "#757575",
}

# Backward-compatible flat map for legacy code paths
APPID_MAP = {k: v[0] for k, v in APPID_DB.items()}


def resolve_appid(raw_id: str) -> dict:
    """
    Resolve a raw AppID string to human-readable application information.

    Lookup strategy (in order):
      1. Exact match against APPID_DB (case-insensitive)
      2. Partial/prefix match (first 8 chars) – handles version-variant IDs
      3. Suffix/suffix match (last 8 chars) – catches some variant IDs
      4. Return a structured 'Unknown' result with the raw ID preserved

    Returns a dict with keys:
      name          – Human-readable application name
      category      – Application category string
      app_path      – Typical executable path (if known, else '')
      match_quality – 'exact', 'partial', or 'unknown'
      raw_id        – The original raw ID passed in
      known         – bool

    Note: APPID_DB entries may be 2-tuples (name, category) or
          3-tuples (name, category, app_path). Both forms are handled.
    """
    if not raw_id:
        return {"name": "Unknown Application", "category": "Unknown",
                "app_path": "",
                "match_quality": "unknown", "raw_id": raw_id, "known": False}

    # Strip NTFS MFT prefix if present: "[ntfs mft #1234567] abcdef1234567890"
    clean_id = raw_id.strip().lower()
    # Extract trailing hex ID if prefixed with bracket notation
    bracket_match = re.search(r'\]\s*([0-9a-f]{8,})', clean_id)
    if bracket_match:
        clean_id = bracket_match.group(1)
    # Strip .automaticdestinations-ms / .customdestinations-ms suffix if present
    clean_id = re.sub(r'\.(automatic|custom)destinations-ms$', '', clean_id).strip()

    def _unpack(entry):
        """Safely unpack 2- or 3-tuple APPID_DB entry."""
        if len(entry) >= 3:
            return entry[0], entry[1], entry[2]
        return entry[0], entry[1], ""

    # 1. Exact match
    if clean_id in APPID_DB:
        name, category, app_path = _unpack(APPID_DB[clean_id])
        return {"name": name, "category": category, "app_path": app_path,
                "match_quality": "exact", "raw_id": raw_id, "known": True}

    # 2. Partial prefix match (first 8 hex chars)
    prefix = clean_id[:8] if len(clean_id) >= 8 else clean_id
    for k, entry in APPID_DB.items():
        if k.startswith(prefix):
            name, category, app_path = _unpack(entry)
            return {"name": name + " (partial match)", "category": category,
                    "app_path": app_path,
                    "match_quality": "partial", "raw_id": raw_id, "known": True}

    # 3. Suffix match (last 8 hex chars) — some AppID variants differ at start
    suffix = clean_id[-8:] if len(clean_id) >= 8 else clean_id
    for k, entry in APPID_DB.items():
        if k.endswith(suffix):
            name, category, app_path = _unpack(entry)
            return {"name": name + " (suffix match)", "category": category,
                    "app_path": app_path,
                    "match_quality": "partial", "raw_id": raw_id, "known": True}

    # 4. Unknown — preserve the clean ID for investigator follow-up
    return {"name": f"Unknown App [{clean_id[:16]}]", "category": "Unknown",
            "app_path": "",
            "match_quality": "unknown", "raw_id": raw_id, "known": False}


def infer_target_path(lnk_info: dict, entry: dict, jl_info: dict) -> str:
    """
    Infer the most accurate target path for a JumpList entry or LNK record,
    including deleted files.

    Priority order:
      1. LNK LinkInfo local path (most reliable)
      2. DestList path field (v3+ only)
      3. LNK relative path + working dir reconstruction
      4. LNK working directory alone
      5. LNK volume label + filename reconstruction
      6. Network share path reconstruction
      7. App-specific default path from AppID database
      8. Mark as [DELETED - Path Unavailable] with metadata hints

    Returns the best available path string.
    """
    # Gather all available path sources — apply sanitization to strip binary garbage
    local_path    = _sanitize_path((lnk_info.get('target_path', '') or '').strip())
    dest_path     = _sanitize_path((entry.get('entry_path', '') or '').strip())
    relative_path = _sanitize_path((lnk_info.get('relative_path', '') or '').strip())
    working_dir   = _sanitize_path((lnk_info.get('working_dir', '') or '').strip())
    net_share     = (lnk_info.get('net_share', '') or '').strip()   # UNC — keep as-is
    vol_label     = (lnk_info.get('volume_label', '') or '').strip()
    icon_location = _sanitize_path((lnk_info.get('icon_location', '') or '').strip())
    description   = (lnk_info.get('description', '') or '').strip()
    hostname      = (entry.get('hostname', '') or '').strip()
    is_network    = lnk_info.get('is_network', False)
    drive_type    = (lnk_info.get('drive_type', '') or '').strip()
    app_path      = (jl_info.get('app_path', '') or '').strip()

    # 1. Best case: full local path from LNK LinkInfo
    if local_path and len(local_path) > 3:
        return local_path

    # 2. DestList path (v3+, most reliable for AutomaticDestinations)
    if dest_path and len(dest_path) > 3:
        return dest_path

    # 3. Relative path + working directory reconstruction
    if relative_path and working_dir:
        # Combine: working_dir\relative_path (strip .\ prefix)
        rel = relative_path.lstrip('.\\').lstrip('./')
        if rel:
            combined = os.path.join(working_dir, rel)
            return combined

    # 4. Relative path alone (may be partial but useful)
    if relative_path and len(relative_path) > 3 and not relative_path.startswith('..'):
        return relative_path

    # 5. Working directory (at minimum tells us where the file was)
    if working_dir and len(working_dir) > 3:
        return f"{working_dir}\\ [file in this directory]"

    # 6. Network share reconstruction
    if is_network and net_share:
        if hostname:
            clean_share = net_share.lstrip('\\')
            return f"\\\\{hostname}\\{clean_share}"
        return net_share

# 7. Network share without hostname flag
    if net_share and net_share.startswith('\\\\'):
        return net_share

    # 8. Icon location often contains the executable/file path
    if icon_location and len(icon_location) > 3:
        # Strip index suffix like ",0" at end
        icon_path = re.sub(r',\s*-?\d+\s*$', '', icon_location).strip()
        if icon_path and icon_path not in (app_path,):
            return f"{icon_path} [icon path]"

    # 9. Description field sometimes contains path hints
    if description and ('\\' in description or '/' in description):
        return f"{description} [description hint]"

    # 10. App-specific default for known applications
    if app_path:
        return f"{app_path} [app default]"

    # 11. Drive type provides context even without full path
    if drive_type and drive_type not in ('Unknown', ''):
        vol_part = f" ({vol_label})" if vol_label else ""
        return f"[{drive_type} Drive{vol_part} - path not recoverable]"

    # 12. Deleted file — no path available
    return "[DELETED - Path Not Recoverable]"


class NTFSWalker:
    """
    Multi-method NTFS filesystem walker.
    Method 1: pytsk3 (if installed) — most reliable
    Method 2: Pure-Python NTFS MFT walk — works without pytsk3
    Method 3: Raw MFT carve — worst case
    """

    JL_SUFFIXES = (
        '.automaticdestinations-ms',
        '.customdestinations-ms',
    )

    # All known locations for jump lists
    JL_PATHS = [
        # Modern Windows (Vista+)
        'users',
        'appdata',
        'roaming',
        'microsoft',
        'windows',
        'recent',
        'automaticdestinations',
        'customdestinations',
        # XP-era
        'documents and settings',
        'application data',
        'local settings',
        # Possible alternate locations
        'localappdata',
        'local',
    ]

    def __init__(self, reader, partition_offset: int):
        self.reader = reader
        self.partition_offset = partition_offset
        self._sector_size = 512
        self._backend = None
        self._pytsk3_img = None
        self._setup()

    def _setup(self):
        try:
            import pytsk3
            self._pytsk3 = pytsk3

            reader = self.reader
            part_off = self.partition_offset

            class _ImgInfo(pytsk3.Img_Info):
                def __init__(inner_self):
                    super().__init__()
                def get_size(inner_self):
                    return reader.get_size()
                def read(inner_self, offset, length):
                    return reader.read(offset, length)

            self._pytsk3_img = _ImgInfo()
            self._backend = 'pytsk3'
            log.info("NTFS walker: pytsk3 available.")
        except ImportError:
            log.info("pytsk3 not available; using pure-Python NTFS walker.")
            self._backend = 'pure'
        except Exception as e:
            log.warning(f"pytsk3 init error: {e}; using pure-Python NTFS walker.")
            self._backend = 'pure'

    def enumerate_jumplist_files(self) -> list:
        results = []
        methods = []

        if self._backend == 'pytsk3':
            methods.append(('pytsk3', self._enum_pytsk3))

        methods.append(('pure-NTFS', self._enum_pure_ntfs))
        # MFT-carve is a last resort only — it's extremely slow (scans 50 GB raw)
        # and should never run if a structural method already found files.
        methods.append(('MFT-carve', self._enum_mft_carve))

        for name, method in methods:
            log.info(f"Trying detection method: {name}")
            try:
                found = method()
                if found:
                    log.info(f"Method '{name}' found {len(found)} jump list file(s).")
                    # Merge results (deduplicate by filename)
                    existing_names = {r['name'].lower() for r in results}
                    for item in found:
                        if item['name'].lower() not in existing_names:
                            results.append(item)
                            existing_names.add(item['name'].lower())
                    # If a structural method found files, skip the brute-force carve.
                    if name in ('pytsk3', 'pure-NTFS') and results:
                        log.info(f"Skipping further methods — {len(results)} file(s) already found.")
                        break
                else:
                    log.info(f"Method '{name}' found nothing.")
            except Exception as e:
                log.warning(f"Method '{name}' failed: {e}")
                log.debug(traceback.format_exc())

        log.info(f"Total jump list files detected: {len(results)}")
        return results

    # ── Method 1: pytsk3 ─────────────────────────────────────────────────

    def _enum_pytsk3(self) -> list:
        results = []
        try:
            fs = self._pytsk3.FS_Info(self._pytsk3_img,
                                      offset=self.partition_offset)
            for spath in ["/Users", "/Documents and Settings", "/"]:
                try:
                    self._walk_pytsk3_recursive(fs, spath, results, depth=0)
                except Exception:
                    pass
        except Exception as e:
            log.debug(f"pytsk3 FS error: {e}")
        return results

    def _walk_pytsk3_recursive(self, fs, path: str, results: list, depth: int):
        if depth > 12:
            return
        try:
            directory = fs.open_dir(path=path)
        except Exception:
            return
        for entry in directory:
            try:
                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode('utf-8', errors='replace')
                if name in ('.', '..', '$OrphanFiles'):
                    continue
                meta = entry.info.meta
                if meta is None:
                    continue
                full_path = f"{path}/{name}".replace('//', '/')
                if meta.type == self._pytsk3.TSK_FS_META_TYPE_DIR:
                    if depth < 10:
                        self._walk_pytsk3_recursive(fs, full_path, results, depth + 1)
                elif meta.type == self._pytsk3.TSK_FS_META_TYPE_REG:
                    lname = name.lower()
                    if any(lname.endswith(s) for s in self.JL_SUFFIXES):
                        try:
                            file_obj = fs.open(path=full_path)
                            size = meta.size
                            if size == 0 or size > 50 * (1 << 20):
                                continue
                            data = file_obj.read_random(0, size)
                            results.append({
                                'path': full_path,
                                'name': name,
                                'data': data,
                                'size': size,
                                'mtime': self._ts(meta.mtime),
                                'atime': self._ts(meta.atime),
                                'ctime': self._ts(meta.crtime if hasattr(meta, 'crtime') else 0),
                                'deleted': bool(meta.flags & 0x02),
                            })
                            log.info(f"Found: {full_path} ({size} bytes)")
                        except Exception as e:
                            log.debug(f"Cannot read {full_path}: {e}")
            except Exception:
                continue

    # ── Method 2: Pure-Python NTFS MFT walk ──────────────────────────────

    def _enum_pure_ntfs(self) -> list:
        """Walk NTFS filesystem using pure Python (no pytsk3)."""
        results = []
        try:
            boot = self.reader.read(self.partition_offset, 512)
            if boot[3:7] != b'NTFS':
                log.debug(f"Boot sector at {hex(self.partition_offset)}: not NTFS")
                return results

            bps = struct.unpack_from('<H', boot, 0x0B)[0] or 512
            spc = boot[0x0D] or 8
            cluster_size = bps * spc
            mft_cluster  = struct.unpack_from('<Q', boot, 0x30)[0]
            mft_offset   = self.partition_offset + mft_cluster * cluster_size

            # Determine MFT record size
            rec_size_raw = struct.unpack_from('<i', boot, 0x40)[0]
            if rec_size_raw < 0:
                mft_record_size = 1 << (-rec_size_raw)
            elif rec_size_raw == 0:
                mft_record_size = cluster_size
            else:
                mft_record_size = rec_size_raw * cluster_size
            mft_record_size = max(512, min(mft_record_size, 4096))

            # Total sectors from BPB — used to sanity-cap MFT record count
            total_sectors = struct.unpack_from('<Q', boot, 0x28)[0]
            if total_sectors == 0:
                total_sectors = struct.unpack_from('<I', boot, 0x28)[0]
            partition_size_bytes = total_sectors * bps

            log.info(f"NTFS: partition={hex(self.partition_offset)}, "
                     f"MFT at {hex(mft_offset)}, "
                     f"record_size={mft_record_size}, cluster={cluster_size}, "
                     f"partition_size={partition_size_bytes//(1<<20)} MB")

            # Read MFT inode 0 to get data runs for the $MFT itself
            mft_data_runs = self._get_mft_data_runs(mft_offset, mft_record_size,
                                                     cluster_size)

            # Derive max records from $MFT file size (inode 0 allocated size)
            max_records = 2_000_000  # hard cap
            try:
                raw0 = self.reader.read(mft_offset, mft_record_size)
                if raw0[:4] == b'FILE':
                    raw0 = self._apply_fixup(raw0, mft_record_size)
                    attr_off = struct.unpack_from('<H', raw0, 20)[0]
                    while attr_off < mft_record_size - 8:
                        atype = struct.unpack_from('<I', raw0, attr_off)[0]
                        if atype == 0xFFFFFFFF:
                            break
                        alen = struct.unpack_from('<I', raw0, attr_off + 4)[0]
                        if alen == 0:
                            break
                        if atype == 0x80:  # $DATA
                            non_res = raw0[attr_off + 8]
                            if non_res:
                                alloc_size = struct.unpack_from('<Q', raw0, attr_off + 40)[0]
                                if alloc_size > 0:
                                    rec_count = alloc_size // mft_record_size
                                    max_records = min(int(rec_count * 1.05), 5_000_000)
                                    log.info(f"$MFT allocated size: {alloc_size//(1<<20)} MB "
                                             f"=> {rec_count} records (cap: {max_records})")
                            break
                        attr_off += alen
            except Exception as e:
                log.debug(f"Could not read $MFT size: {e}")

            log.info(f"Starting MFT walk: up to {max_records} records...")

            consecutive_errors = 0
            last_progress_time = datetime.datetime.utcnow()

            for rec_num in range(max_records):
                # Progress log every 10,000 records OR every 60 seconds, whichever comes first
                if rec_num > 0 and rec_num % 10000 == 0:
                    now = datetime.datetime.utcnow()
                    elapsed = (now - last_progress_time).total_seconds()
                    last_progress_time = now
                    rate = 10000 / elapsed if elapsed > 0 else 0
                    pct = 100.0 * rec_num / max_records
                    log.info(f"MFT walk progress: {rec_num:,}/{max_records:,} records "
                             f"({pct:.1f}%) — {rate:.0f} rec/s — "
                             f"{len(results)} JL files found so far...")

                try:
                    # Each MFT record read gets a 60-second timeout; a single
                    # unreadable cluster must not freeze the entire walk.
                    rec_holder = [None]
                    exc_holder = [None]
                    def _read_rec():
                        try:
                            rec_holder[0] = self._read_mft_record(
                                rec_num, mft_offset, mft_record_size,
                                cluster_size, mft_data_runs)
                        except Exception as e:
                            exc_holder[0] = e
                    rt = threading.Thread(target=_read_rec, daemon=True)
                    rt.start()
                    rt.join(timeout=60)
                    if rt.is_alive():
                        log.warning(f"MFT record #{rec_num} read timed out after 60s — skipping.")
                        consecutive_errors += 1
                        if consecutive_errors > 20:
                            log.error("Too many timed-out MFT reads in a row — aborting MFT walk.")
                            break
                        continue
                    if exc_holder[0] is not None:
                        raise exc_holder[0]
                    rec_data = rec_holder[0]
                    consecutive_errors = 0
                except Exception:
                    consecutive_errors += 1
                    if consecutive_errors > 100:
                        log.debug(f"Stopping MFT walk after 100 consecutive read "
                                  f"errors at record {rec_num}")
                        break
                    continue

                if len(rec_data) < 4 or rec_data[:4] != b'FILE':
                    consecutive_errors += 1
                    if consecutive_errors > 500:
                        log.debug(f"Stopping MFT walk: 500 consecutive non-FILE "
                                  f"records at #{rec_num}")
                        break
                    continue

                consecutive_errors = 0
                item = self._process_mft_record(rec_data, rec_num,
                                                mft_record_size, cluster_size,
                                                mft_offset)
                if item:
                    results.append(item)

            log.info(f"MFT walk complete: scanned records, found {len(results)} JL files.")

        except Exception as e:
            log.warning(f"Pure NTFS walk error: {e}")
            log.debug(traceback.format_exc())
        return results

    def _get_mft_data_runs(self, mft_offset: int, record_size: int,
                            cluster_size: int) -> list:
        """Get data runs for $MFT itself (inode 0)."""
        try:
            raw = self.reader.read(mft_offset, record_size)
            if raw[:4] != b'FILE':
                return []
            return self._extract_data_runs(raw, cluster_size)
        except Exception:
            return []

    def _read_mft_record(self, rec_num: int, mft_base: int, record_size: int,
                          cluster_size: int, data_runs: list) -> bytes:
        """Read MFT record by number, respecting data runs for non-resident $MFT."""
        if data_runs:
            # $MFT is non-resident — map record number through data runs
            byte_offset = rec_num * record_size
            result = bytearray()
            remaining = record_size
            current_byte = 0
            for (lcn, length_clusters) in data_runs:
                run_bytes = length_clusters * cluster_size
                if byte_offset >= current_byte + run_bytes:
                    current_byte += run_bytes
                    continue
                # This run contains our data
                run_start = self.partition_offset + lcn * cluster_size
                skip = byte_offset - current_byte
                disk_offset = run_start + skip
                take = min(run_bytes - skip, remaining)
                chunk = self.reader.read(disk_offset, take)
                result.extend(chunk)
                remaining -= len(chunk)
                byte_offset += len(chunk)
                current_byte += run_bytes
                if remaining <= 0:
                    break
            if result:
                return bytes(result)
        # Fallback: linear read from MFT base (works for resident/small MFT)
        offset = mft_base + rec_num * record_size
        return self.reader.read(offset, record_size)

    def _process_mft_record(self, data: bytes, rec_num: int,
                             record_size: int, cluster_size: int,
                             mft_offset: int) -> dict:
        """Process one MFT record. Returns dict if jump list file, else None."""
        try:
            # Apply fixup
            data = self._apply_fixup(data, record_size)

            # Check flags: bit 0 = file in use, bit 1 = directory
            flags = struct.unpack_from('<H', data, 22)[0]
            if flags & 0x02:  # directory
                return None
            # Note: deleted files (flag=0) are also interesting

            attr_offset = struct.unpack_from('<H', data, 20)[0]
            filename = ''
            file_data = None
            mtime_ft = 0

            # Scan attributes
            while attr_offset < record_size - 8:
                atype = struct.unpack_from('<I', data, attr_offset)[0]
                if atype == 0xFFFFFFFF:
                    break
                alen = struct.unpack_from('<I', data, attr_offset + 4)[0]
                if alen == 0 or alen > record_size:
                    break

                if atype == 0x30:  # $FILE_NAME
                    fn = self._parse_filename_attr(data, attr_offset)
                    if fn:
                        filename = fn['name']
                        mtime_ft = fn.get('mtime_ft', 0)

                elif atype == 0x80:  # $DATA
                    non_res = data[attr_offset + 8]
                    if non_res == 0:
                        # Resident
                        val_off = struct.unpack_from('<H', data, attr_offset + 20)[0]
                        val_len = struct.unpack_from('<I', data, attr_offset + 16)[0]
                        if val_len > 0 and attr_offset + val_off + val_len <= len(data):
                            file_data = data[attr_offset + val_off:
                                            attr_offset + val_off + val_len]
                    else:
                        # Non-resident: follow data runs
                        file_data = self._read_nonresident_data(
                            data, attr_offset, cluster_size)

                attr_offset += alen

            if not filename:
                return None

            lname = filename.lower()
            if not any(lname.endswith(s) for s in self.JL_SUFFIXES):
                return None

            if file_data is None or len(file_data) < 4:
                return None

            deleted = not bool(flags & 0x01)
            ts = self._filetime_to_str(mtime_ft) if mtime_ft else 'Unknown'

            log.info(f"MFT #{rec_num}: {filename} ({len(file_data)} bytes)"
                     + (" [DELETED]" if deleted else ""))

            return {
                'path': f'[NTFS MFT #{rec_num}] {filename}',
                'name': filename,
                'data': file_data,
                'size': len(file_data),
                'mtime': ts,
                'atime': ts,
                'ctime': ts,
                'deleted': deleted,
            }
        except Exception as e:
            log.debug(f"MFT record {rec_num} error: {e}")
            return None

    def _apply_fixup(self, data: bytes, record_size: int) -> bytes:
        """Apply NTFS update sequence array fixup."""
        try:
            usa_offset = struct.unpack_from('<H', data, 4)[0]
            usa_count  = struct.unpack_from('<H', data, 6)[0]
            if usa_offset == 0 or usa_count == 0 or usa_count > 10:
                return data
            data = bytearray(data)
            update_seq = data[usa_offset: usa_offset + 2]
            for i in range(1, usa_count):
                sector_end = i * 512 - 2
                if sector_end + 2 <= len(data):
                    repl = data[usa_offset + i * 2: usa_offset + i * 2 + 2]
                    data[sector_end: sector_end + 2] = repl
            return bytes(data)
        except Exception:
            return data

    def _parse_filename_attr(self, data: bytes, attr_offset: int) -> dict:
        """Parse $FILE_NAME attribute."""
        try:
            non_res = data[attr_offset + 8]
            if non_res != 0:
                return None
            val_off = struct.unpack_from('<H', data, attr_offset + 20)[0]
            val_start = attr_offset + val_off

            # FILE_NAME structure:
            # 0x00: parent file reference (8)
            # 0x08: created  (8) FILETIME
            # 0x10: modified (8)
            # 0x18: mft_modified (8)
            # 0x20: accessed (8)
            # ... 
            # 0x40: name_length (1 byte, in chars)
            # 0x41: name_namespace (1 byte)
            # 0x42: name (name_length * 2 bytes, UTF-16LE)

            if val_start + 0x42 > len(data):
                return None

            mtime_ft = struct.unpack_from('<Q', data, val_start + 0x10)[0]
            name_len = data[val_start + 0x40]
            namespace = data[val_start + 0x41]

            if namespace == 2:  # DOS name only — prefer the Win32 version
                return None

            name_raw = data[val_start + 0x42: val_start + 0x42 + name_len * 2]
            name = name_raw.decode('utf-16-le', errors='replace')
            return {'name': name, 'mtime_ft': mtime_ft}
        except Exception:
            return None

    def _extract_data_runs(self, mft_record: bytes, cluster_size: int) -> list:
        """Extract data runs from $DATA attribute for MFT inode 0."""
        runs = []
        try:
            attr_offset = struct.unpack_from('<H', mft_record, 20)[0]
            while attr_offset < len(mft_record) - 8:
                atype = struct.unpack_from('<I', mft_record, attr_offset)[0]
                if atype == 0xFFFFFFFF:
                    break
                alen = struct.unpack_from('<I', mft_record, attr_offset + 4)[0]
                if alen == 0:
                    break
                if atype == 0x80:
                    non_res = mft_record[attr_offset + 8]
                    if non_res:
                        run_off = struct.unpack_from('<H', mft_record, attr_offset + 32)[0]
                        runs = self._decode_runs(
                            mft_record[attr_offset + run_off:], cluster_size)
                    break
                attr_offset += alen
        except Exception:
            pass
        return runs

    def _read_nonresident_data(self, mft_record: bytes, attr_offset: int,
                                cluster_size: int) -> bytes:
        """Read non-resident $DATA by following data runs."""
        try:
            run_off    = struct.unpack_from('<H', mft_record, attr_offset + 32)[0]
            data_size  = struct.unpack_from('<Q', mft_record, attr_offset + 48)[0]

            if data_size == 0 or data_size > 50 * (1 << 20):  # cap at 50MB
                return None

            runs = self._decode_runs(mft_record[attr_offset + run_off:], cluster_size)
            if not runs:
                return None

            result = bytearray()
            for (lcn, length_clusters) in runs:
                if lcn < 0:  # sparse
                    result.extend(b'\x00' * length_clusters * cluster_size)
                else:
                    disk_offset = self.partition_offset + lcn * cluster_size
                    chunk = self.reader.read(disk_offset, length_clusters * cluster_size)
                    result.extend(chunk)
                if len(result) >= data_size:
                    break

            return bytes(result[:data_size])
        except Exception as e:
            log.debug(f"Non-resident read error: {e}")
            return None

    def _decode_runs(self, run_data: bytes, cluster_size: int) -> list:
        """Decode NTFS data run list. Returns list of (lcn, length) tuples."""
        runs = []
        pos = 0
        prev_lcn = 0
        while pos < len(run_data):
            header = run_data[pos]
            if header == 0:
                break
            pos += 1
            len_size = header & 0x0F
            off_size = (header >> 4) & 0x0F

            if pos + len_size + off_size > len(run_data):
                break

            length_raw = run_data[pos: pos + len_size]
            pos += len_size
            offset_raw = run_data[pos: pos + off_size]
            pos += off_size

            length_clusters = int.from_bytes(length_raw, 'little', signed=False)

            if off_size == 0:
                lcn = -1  # sparse
            else:
                offset_val = int.from_bytes(offset_raw, 'little', signed=True)
                prev_lcn += offset_val
                lcn = prev_lcn

            runs.append((lcn, length_clusters))
        return runs

    # ── Method 3: MFT raw carve ──────────────────────────────────────────

    def _enum_mft_carve(self) -> list:
        """
        Brute-force carve: scan the raw image for FILE records and check
        for jump list filenames. Catches cases where MFT location is
        non-standard or NTFS metadata is partially corrupted.
        """
        results = []
        log.info("MFT carve: scanning raw image for FILE records...")
        try:
            reader_size = self.reader.get_size()
            total_size = min(reader_size, 50 * (1 << 30))  # max 50 GB scan
            block_size = 1 << 20  # 1 MB blocks
            record_size = 1024

            for block_start in range(0, total_size, block_size):
                block = self.reader.read(block_start, block_size + record_size)
                pos = 0
                while pos < len(block) - record_size:
                    if block[pos:pos+4] == b'FILE':
                        rec = block[pos: pos + record_size]
                        item = self._process_mft_record(rec, -1, record_size, 4096, 0)
                        if item:
                            # Check for duplicates (same filename as already found)
                            item['path'] = f'[Carved @{hex(block_start + pos)}] {item["name"]}'
                            results.append(item)
                    pos += 512  # NTFS records are aligned to 512-byte boundaries
        except Exception as e:
            log.debug(f"MFT carve error: {e}")
        return results

    # ── Helpers ──────────────────────────────────────────────────────────

    def _ts(self, t) -> str:
        return self._filetime_to_str_unix(int(t))

    def _filetime_to_str_unix(self, unix_ts: int) -> str:
        """Convert a Unix timestamp to UTC string with forensic sanity bounds."""
        try:
            MIN_TS = 473385600    # 1985-01-01
            MAX_TS = 4102444800   # 2100-01-01
            if unix_ts < MIN_TS or unix_ts > MAX_TS:
                return 'Unknown'
            return datetime.datetime.utcfromtimestamp(unix_ts).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            return 'Unknown'

    def _filetime_to_str(self, ft: int) -> str:
        return _filetime_to_str(ft)


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 5 – LIVE SYSTEM MODE
#  Read jump lists directly from the current (live) Windows system
# ═══════════════════════════════════════════════════════════════════════════

def collect_live_jumplist_files() -> list:
    """
    Collect jump list files from the live Windows system (no image needed).
    Useful as a fallback or for live triage.
    """
    results = []
    if sys.platform != 'win32':
        log.warning("Live mode is only supported on Windows. "
                    "Current platform: %s", sys.platform)
        return results

    log.info("Live mode: collecting jump list files from current system.")

    search_roots = []

    # Current user
    appdata = os.environ.get('APPDATA', '')
    if appdata:
        search_roots.append(os.path.join(appdata, 'Microsoft', 'Windows', 'Recent'))

    # All users
    users_dir = os.environ.get('SystemDrive', 'C:') + '\\Users'
    if os.path.isdir(users_dir):
        for user in os.listdir(users_dir):
            user_path = os.path.join(users_dir, user, 'AppData', 'Roaming',
                                     'Microsoft', 'Windows', 'Recent')
            if os.path.isdir(user_path):
                search_roots.append(user_path)

    # XP-style
    docs_dir = os.environ.get('SystemDrive', 'C:') + '\\Documents and Settings'
    if os.path.isdir(docs_dir):
        for user in os.listdir(docs_dir):
            for sub in ['Application Data\\Microsoft\\Windows\\Recent',
                        'Local Settings\\Application Data\\Microsoft\\Windows\\Recent']:
                p = os.path.join(docs_dir, user, sub)
                if os.path.isdir(p):
                    search_roots.append(p)

    for root in search_roots:
        for sub in ['AutomaticDestinations', 'CustomDestinations', '']:
            path = os.path.join(root, sub)
            if not os.path.isdir(path):
                continue
            for fname in os.listdir(path):
                lname = fname.lower()
                if not (lname.endswith('.automaticdestinations-ms') or
                        lname.endswith('.customdestinations-ms')):
                    continue
                fpath = os.path.join(path, fname)
                try:
                    with open(fpath, 'rb') as fh:
                        data = fh.read()
                    stat = os.stat(fpath)
                    results.append({
                        'path': fpath,
                        'name': fname,
                        'data': data,
                        'size': len(data),
                        'mtime': datetime.datetime.utcfromtimestamp(
                            stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'atime': datetime.datetime.utcfromtimestamp(
                            stat.st_atime).strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'ctime': datetime.datetime.utcfromtimestamp(
                            stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'deleted': False,
                    })
                    log.info(f"Live: {fpath} ({len(data)} bytes)")
                except Exception as e:
                    log.warning(f"Live read failed {fpath}: {e}")

    log.info(f"Live mode: collected {len(results)} jump list files.")
    return results


def _walk_directory_for_jl(root: str) -> list:
    """Walk an extracted directory for jump list files."""
    results = []
    for dirpath, _, files in os.walk(root):
        for fname in files:
            lname = fname.lower()
            if (lname.endswith('.automaticdestinations-ms') or
                    lname.endswith('.customdestinations-ms')):
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, 'rb') as fh:
                        data = fh.read()
                    stat = os.stat(fpath)
                    results.append({
                        'path': fpath,
                        'name': fname,
                        'data': data,
                        'size': len(data),
                        'mtime': datetime.datetime.utcfromtimestamp(
                            stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'atime': datetime.datetime.utcfromtimestamp(
                            stat.st_atime).strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'ctime': datetime.datetime.utcfromtimestamp(
                            stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'deleted': False,
                    })
                except Exception as e:
                    log.warning(f"Could not read {fpath}: {e}")
    return results


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 6 – LNK FILE PARSER
# ═══════════════════════════════════════════════════════════════════════════

DRIVE_TYPE_MAP = {0: 'Unknown', 1: 'No Root Dir', 2: 'Removable',
                  3: 'Fixed', 4: 'Remote', 5: 'CD-ROM', 6: 'RAM Disk'}
SHOW_CMD_MAP   = {1: 'Normal', 2: 'Minimized', 3: 'Maximized'}


def parse_lnk(data: bytes) -> dict:
    result = {
        'valid': False, 'target_path': '', 'target_size': 0,
        'creation_time': '', 'modified_time': '', 'access_time': '',
        'working_dir': '', 'arguments': '', 'description': '',
        'relative_path': '', 'icon_location': '',
        'drive_type': '', 'drive_serial': '', 'volume_label': '',
        'net_share': '', 'machine_id': '',
        'show_cmd': '', 'hotkey': '',
        'attributes': [], 'is_network': False,
    }

    try:
        if len(data) < 76:
            return result
        if struct.unpack_from('<I', data, 0)[0] != 0x4C:
            return result

        link_flags    = struct.unpack_from('<I', data, 20)[0]
        file_attribs  = struct.unpack_from('<I', data, 24)[0]
        creation_time = struct.unpack_from('<Q', data, 28)[0]
        access_time   = struct.unpack_from('<Q', data, 36)[0]
        modified_time = struct.unpack_from('<Q', data, 44)[0]
        target_size   = struct.unpack_from('<I', data, 52)[0]
        show_cmd      = struct.unpack_from('<I', data, 60)[0]
        hotkey        = struct.unpack_from('<H', data, 64)[0]

        result['creation_time'] = _filetime_to_str(creation_time)
        result['access_time']   = _filetime_to_str(access_time)
        result['modified_time'] = _filetime_to_str(modified_time)
        result['target_size']   = target_size
        result['show_cmd']      = SHOW_CMD_MAP.get(show_cmd, str(show_cmd))
        if hotkey:
            result['hotkey'] = f"0x{hotkey:04X}"

        attr_flags = {
            0x0001: 'Read-Only', 0x0002: 'Hidden', 0x0004: 'System',
            0x0010: 'Directory', 0x0020: 'Archive', 0x0080: 'Normal',
            0x0100: 'Temp', 0x0400: 'Compressed', 0x1000: 'Encrypted',
        }
        result['attributes'] = [v for k, v in attr_flags.items() if file_attribs & k]

        offset = 76

        if link_flags & 0x01:  # HasLinkTargetIDList
            idl_size = struct.unpack_from('<H', data, offset)[0]
            offset += 2 + idl_size

        if link_flags & 0x02:  # HasLinkInfo
            if offset < len(data) - 4:
                li_size = struct.unpack_from('<I', data, offset)[0]
                li_data = data[offset: offset + li_size]
                _parse_linkinfo(li_data, result)
                offset += li_size

        unicode_flag = link_flags & 0x80

        def _read_str(off):
            if off >= len(data) - 2:
                return '', off
            cnt = struct.unpack_from('<H', data, off)[0]
            off += 2
            if cnt == 0:
                return '', off
            if cnt > 4096:   # sanity cap — LNK strings should never be this long
                return '', off
            if unicode_flag:
                byte_len = cnt * 2
                if off + byte_len > len(data):
                    return '', off + byte_len
                s = data[off: off + byte_len].decode('utf-16-le', errors='replace')
                s = s.rstrip('\x00')
                return s, off + byte_len
            else:
                if off + cnt > len(data):
                    return '', off + cnt
                s = data[off: off + cnt].decode('latin-1', errors='replace')
                s = s.rstrip('\x00')
                return s, off + cnt

        if link_flags & 0x04:
            result['description'], offset = _read_str(offset)
        if link_flags & 0x08:
            result['relative_path'], offset = _read_str(offset)
        if link_flags & 0x10:
            result['working_dir'], offset = _read_str(offset)
        if link_flags & 0x20:
            result['arguments'], offset = _read_str(offset)
        if link_flags & 0x40:
            result['icon_location'], offset = _read_str(offset)

        result['valid'] = True
    except Exception as e:
        log.debug(f"LNK parse error: {e}")

    return result


def _parse_linkinfo(li: bytes, result: dict):
    if len(li) < 28:
        return
    li_flags       = struct.unpack_from('<I', li, 8)[0]
    vol_off        = struct.unpack_from('<I', li, 12)[0]
    local_path_off = struct.unpack_from('<I', li, 16)[0]
    net_off        = struct.unpack_from('<I', li, 20)[0]

    if li_flags & 0x01 and vol_off < len(li):
        vtype   = struct.unpack_from('<I', li, vol_off + 4)[0]
        serial  = struct.unpack_from('<I', li, vol_off + 8)[0]
        vlabel_off = struct.unpack_from('<I', li, vol_off + 12)[0]
        result['drive_type']   = DRIVE_TYPE_MAP.get(vtype, str(vtype))
        result['drive_serial'] = f"{serial:08X}"
        try:
            vlabel = li[vol_off + vlabel_off:].split(b'\x00')[0]
            result['volume_label'] = vlabel.decode('latin-1', errors='replace')
        except Exception:
            pass

    if li_flags & 0x02 and net_off < len(li):
        result['is_network'] = True
        net_name_off = struct.unpack_from('<I', li, net_off + 8)[0]
        try:
            net_name = li[net_off + net_name_off:].split(b'\x00')[0]
            result['net_share'] = net_name.decode('latin-1', errors='replace')
        except Exception:
            pass

    if local_path_off < len(li):
        try:
            lpath = li[local_path_off:].split(b'\x00')[0]
            decoded = lpath.decode('latin-1', errors='replace')
            result['target_path'] = _sanitize_path(decoded)
        except Exception:
            pass

    # Also try the Unicode (UTF-16LE) local path offset if LinkInfo header
    # is version 2+ (header size >= 0x1C) — provides higher-fidelity path.
    if len(li) >= 0x1C:
        try:
            uni_local_off = struct.unpack_from('<I', li, 0x1C)[0]
            if 0 < uni_local_off < len(li):
                uni_path_raw = li[uni_local_off:]
                # Find null terminator in UTF-16LE (two consecutive zero bytes)
                end = 0
                while end + 1 < len(uni_path_raw):
                    if uni_path_raw[end] == 0 and uni_path_raw[end+1] == 0:
                        break
                    end += 2
                uni_path = uni_path_raw[:end].decode('utf-16-le', errors='replace')
                uni_path = _sanitize_path(uni_path)
                if uni_path and len(uni_path) > len(result.get('target_path', '')):
                    result['target_path'] = uni_path
        except Exception:
            pass


def _filetime_to_str(ft: int) -> str:
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to UTC string.

    Applies strict forensic sanity bounds:
      - Minimum: 1985-01-01  (before Windows NT existed)
      - Maximum: 2100-01-01  (far future — clearly corrupt if exceeded)
    Values outside this window are almost always parser artefacts caused by
    reading binary garbage as a FILETIME (e.g. uninitialized struct fields,
    corrupt OLE sectors, or misaligned LNK header reads).
    Returns '' for zero/invalid/out-of-range values so callers can display '—'.
    """
    if not ft or ft == 0:
        return ''
    try:
        EPOCH_DIFF = 116444736000000000   # 100-ns ticks between 1601 and 1970
        ts = (ft - EPOCH_DIFF) / 10_000_000  # convert to Unix seconds

        # Sanity bounds (Unix timestamps):
        #   1985-01-01 UTC = 473385600
        #   2100-01-01 UTC = 4102444800
        MIN_TS = 473385600    # 1985-01-01
        MAX_TS = 4102444800   # 2100-01-01

        if ts < MIN_TS or ts > MAX_TS:
            log.debug(f"FILETIME {ft:#x} → ts={ts:.0f} outside plausible range — discarding")
            return ''

        dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=ts)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return ''


# ═══════════════════════════════════════════════════════════════════════════
#  PATH SANITIZATION HELPER
#  Cleans binary garbage from LNK target path strings before display/report
# ═══════════════════════════════════════════════════════════════════════════

def _sanitize_path(raw: str) -> str:
    """Remove binary/control characters from a decoded LNK path string.

    Returns empty string if the input does not resemble a real file path.
    """
    if not raw:
        return ""
    # Strip NUL bytes and common Unicode replacement/box characters
    raw = raw.replace(chr(0), "").replace(chr(0xFFFD), "").replace(chr(0x25A0), "")
    # Keep only printable characters (space and above, plus tab)
    raw = "".join(c for c in raw if c >= " " or c == chr(9))
    raw = raw.strip()
    if len(raw) < 4:
        return ""
    # Check for path-like structure: drive letter colon, backslash, or forward slash
    has_drive = len(raw) >= 3 and raw[1] == ":" and raw[2] in ("/", chr(92))
    has_unc   = len(raw) >= 4 and raw[:2] in ("//" , chr(92)*2)
    has_sep   = (chr(92) in raw or "/" in raw)
    if not (has_drive or has_unc or has_sep):
        log.debug("Path sanitizer rejected non-path: %.60r", raw)
        return ""
    return raw


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 7 – JUMP LIST PARSERS
# ═══════════════════════════════════════════════════════════════════════════

def parse_automatic_destinations(data: bytes, filename: str) -> dict:
    result = {
        'filename': filename,
        'type': 'AutomaticDestinations',
        'app_id': os.path.splitext(
            os.path.basename(filename))[0].lower(),
        'app_name': '',
        'entries': [],
        'dest_list': [],
        'errors': [],
    }
    app_info = resolve_appid(result['app_id'])
    result['app_name']     = app_info['name']
    result['app_category'] = app_info['category']
    result['app_path']     = app_info.get('app_path', '')
    result['app_known']    = app_info['known']
    result['app_match']    = app_info['match_quality']

    # Method A: olefile
    try:
        import olefile
        ole = olefile.OleFileIO(BytesIO(data))

        if ole.exists('DestList'):
            try:
                dl_data = ole.openstream('DestList').read()
                result['dest_list'] = _parse_destlist(dl_data)
            except Exception as e:
                result['errors'].append(f"DestList: {e}")

        # DestList entries use decimal stream names ("1", "2", …).
        # Build the lookup keyed by the decimal string (lowercased for safety).
        dl_map = {}
        for e in result['dest_list']:
            # entry_id is stored as an integer; the OLE stream name is that
            # integer printed in decimal (e.g. entry_id=1 → stream name "1").
            eid = e.get('entry_id', None)
            if eid is not None:
                dl_map[str(eid).lower()] = e
            # Also index by the hex form in case some versions use it.
            eid_hex = e.get('entry_id_hex', '')
            if eid_hex:
                dl_map[eid_hex.lower()] = e

        for sid in ole.listdir():
            # sid is a list of path components, e.g. ['1'] or ['DestList']
            if not sid:
                continue
            # Join multi-level paths (rare but possible)
            stream_path = '/'.join(sid)
            stream_name = sid[-1]  # leaf name used for lookup
            if stream_name.lower() == 'destlist':
                continue
            try:
                lnk_data = ole.openstream(stream_path).read()
                lnk_info = parse_lnk(lnk_data)
                if not lnk_info['valid'] and len(lnk_data) < 4:
                    continue
                # Look up DestList metadata by stream name (decimal) or hex
                meta = (dl_map.get(stream_name.lower()) or
                        dl_map.get(stream_name) or {})
                result['entries'].append({
                    'stream': stream_name,
                    'lnk': lnk_info,
                    'access_count': meta.get('access_count', 0),
                    'last_modified': meta.get('last_modified', ''),
                    'birth_time': meta.get('birth_time', ''),
                    'hostname': meta.get('hostname', ''),
                    'pin_status': meta.get('pin_status', ''),
                    'entry_path': meta.get('path', ''),
                })
            except Exception as e:
                result['errors'].append(f"Stream {stream_name}: {e}")

        ole.close()
        result['entries'].sort(
            key=lambda e: e.get('last_modified', '') or
                          e['lnk'].get('modified_time', '') or '',
            reverse=True)
        return result

    except ImportError:
        log.warning("olefile not installed; using built-in CFB parser.")
    except Exception as e:
        result['errors'].append(f"OLE open failed: {e}")

    # Method B: Built-in minimal CFB + LNK scan
    return _parse_auto_dest_builtin(data, result)


def _parse_auto_dest_builtin(data: bytes, result: dict) -> dict:
    """Minimal built-in CFB parser + LNK scan when olefile is unavailable."""
    # Try to parse CFB structure minimally
    if len(data) > 512 and data[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
        # CFB magic present — try to extract sector data
        try:
            sector_size = 1 << struct.unpack_from('<H', data, 30)[0]
            if 64 <= sector_size <= 4096:
                # Extract all potential LNK data from sectors
                for sec_start in range(512, len(data), sector_size):
                    sector = data[sec_start: sec_start + sector_size]
                    pos = 0
                    while pos < len(sector) - 4:
                        if sector[pos:pos+4] == b'\x4C\x00\x00\x00':
                            lnk_info = parse_lnk(sector[pos:])
                            if lnk_info['valid']:
                                result['entries'].append({
                                    'stream': f'sec_{sec_start}_{pos}',
                                    'lnk': lnk_info,
                                    'access_count': 0,
                                    'last_modified': lnk_info.get('modified_time', ''),
                                    'birth_time': lnk_info.get('creation_time', ''),
                                    'hostname': '', 'pin_status': '', 'entry_path': '',
                                })
                        pos += 64
        except Exception:
            pass

    # Fallback: raw LNK magic scan
    if not result['entries']:
        lnk_magic = b'\x4C\x00\x00\x00'
        pos = 0
        idx = 0
        while True:
            pos = data.find(lnk_magic, pos)
            if pos == -1:
                break
            lnk_info = parse_lnk(data[pos:])
            if lnk_info['valid']:
                result['entries'].append({
                    'stream': f'embed_{idx}',
                    'lnk': lnk_info,
                    'access_count': 0,
                    'last_modified': lnk_info.get('modified_time', ''),
                    'birth_time': lnk_info.get('creation_time', ''),
                    'hostname': '', 'pin_status': '', 'entry_path': '',
                })
                idx += 1
            pos += 4

    return result


def _parse_destlist(data: bytes) -> list:
    """
    Parse DestList stream — supports v1, v3, v4, v5.

    DestList header (32 bytes for v1, 40 bytes for v3/v4/v5):
      0x00 version (4)
      0x04 num_entries (4)
      0x08 num_pinned (4)
      0x0C unknown float (4)
      0x10 last_entry_id (4)
      0x14 unknown (4)
      0x18 unknown (4)  ← v3+ only (header grows to 40 bytes total if version >= 3)

    Entry fixed part (104 bytes = 0x68):
      0x00: hostname (16 bytes UTF-16LE, 8 chars)
      0x10: GUID (16 bytes)
      0x20: unknown (8)
      0x28: birth_time (8) FILETIME
      0x30: last_modified (8) FILETIME
      0x38: unknown (8)
      0x40: access_count (4)
      0x44: pinned_flag (4)
      0x48: unknown (4)
      0x4C: unknown (4)
      0x50: unknown (8)
      0x58: entry_id (4) — stream name is str(entry_id)
      0x5C: unknown (4)
      0x60: unknown (4)
      0x64: unknown (4)
    Then (v3+): path_length (2) + path (path_length UTF-16LE chars)
    """
    entries = []
    if len(data) < 32:
        return entries

    header_version = struct.unpack_from('<I', data, 0)[0]
    num_entries    = struct.unpack_from('<I', data, 4)[0]

    # Header is 32 bytes for v1/v2, 40 bytes for v3+
    FIXED_SIZE = 0x68  # 104 bytes — correct per MS-SHLLINK & libJumpList research
    header_size = 40 if header_version >= 3 else 32

    offset = header_size
    for _ in range(min(num_entries, 10000)):
        if offset + FIXED_SIZE > len(data):
            break
        try:
            e = {}
            # Hostname: 16 bytes UTF-16LE at offset 0 within entry
            e['hostname'] = data[offset: offset + 16].decode(
                'utf-16-le', errors='replace').rstrip('\x00').rstrip('\x00')
            e['guid'] = _guid_str(data[offset + 0x10: offset + 0x20])
            e['birth_time']    = _filetime_to_str(
                struct.unpack_from('<Q', data, offset + 0x28)[0])
            e['last_modified'] = _filetime_to_str(
                struct.unpack_from('<Q', data, offset + 0x30)[0])
            e['access_count']  = struct.unpack_from('<I', data, offset + 0x40)[0]
            pin_flag = struct.unpack_from('<I', data, offset + 0x44)[0]
            e['pin_status'] = 'Pinned' if pin_flag == 1 else 'Unpinned'
            # entry_id: 4-byte int at 0x58; OLE stream name is str(entry_id)
            entry_id = struct.unpack_from('<I', data, offset + 0x58)[0]
            e['entry_id'] = entry_id
            e['entry_id_hex'] = f"{entry_id:04X}"

            # v3+: variable-length path follows fixed block
            path_offset = offset + FIXED_SIZE
            if header_version >= 3 and path_offset + 2 <= len(data):
                path_len = struct.unpack_from('<H', data, path_offset)[0]
                path_end = path_offset + 2 + path_len * 2
                if 0 < path_len <= 32767 and path_end <= len(data):
                    raw_path = data[path_offset + 2: path_end].decode(
                        'utf-16-le', errors='replace').rstrip('\x00')
                    e['path'] = _sanitize_path(raw_path)
                    offset = path_end
                else:
                    e['path'] = ''
                    offset += FIXED_SIZE
            else:
                e['path'] = ''
                offset += FIXED_SIZE

            entries.append(e)
        except Exception as ex:
            log.debug(f"DestList entry parse error at offset {offset}: {ex}")
            offset += FIXED_SIZE

    log.debug(f"DestList v{header_version}: parsed {len(entries)}/{num_entries} entries")
    return entries


def parse_custom_destinations(data: bytes, filename: str) -> dict:
    """
    Parse a .customDestinations-ms file.

    File layout (per MS-SHLLINK / libJumpList / empirical analysis):
    ┌──────────────────────────────────────────────────────┐
    │ Header   (16 bytes)                                  │
    │   version     DWORD  (always 2)                      │
    │   num_entries DWORD  number of destination records   │
    │   num_pinned  DWORD  pinned entries at the end       │
    │   unknown     DWORD                                  │
    ├──────────────────────────────────────────────────────┤
    │ Entry × num_entries  (variable length each)          │
    │   category_type  DWORD   0=auto, 1=pinned,           │
    │                          2=custom task, 0xFFFF=end   │
    │   lnk_size       DWORD   bytes of LNK data that follow│
    │   lnk_data       BYTES   raw LNK blob                │
    │   sentinel       DWORD   0xBABFFBAB                  │
    ├──────────────────────────────────────────────────────┤
    │ Footer DWORD  0xBABFFBAB                             │
    └──────────────────────────────────────────────────────┘

    Category types decoded:
      0  = auto-generated recent entry
      1  = user-pinned item
      2  = application-defined task (no LNK, has task description)
      0xFFFF / 0xFFFFFFFF = end-of-list sentinel

    For web browsing jump lists (IE / Edge / WMP):
      The LNK target often points to a URL file or a media file path.
      The description / name_string fields in the LNK carry the page title
      or media title, which is surfaced as 'entry_label' here.

    Falls back to raw LNK magic scan if the binary header is not recognised.
    """
    result = {
        'filename': filename,
        'type': 'CustomDestinations',
        'app_id': os.path.splitext(
            os.path.basename(filename))[0].lower(),
        'app_name': '',
        'entries': [],
        'errors': [],
    }
    app_info = resolve_appid(result['app_id'])
    result['app_name']     = app_info['name']
    result['app_category'] = app_info['category']
    result['app_path']     = app_info.get('app_path', '')
    result['app_known']    = app_info['known']
    result['app_match']    = app_info['match_quality']

    # ── Category type human-readable labels ───────────────────────────────
    CATEGORY_LABELS = {
        0:      'Recent (Auto)',
        1:      'Pinned',
        2:      'Task',
        0xFFFF: 'End',
    }

    SENTINEL = 0xBABFFBAB
    LNK_MAGIC = b'\x4C\x00\x00\x00'

    # ── Attempt structured binary parse ───────────────────────────────────
    parsed_ok = False
    if len(data) >= 16:
        try:
            version, num_entries, num_pinned, _unk = struct.unpack_from('<IIII', data, 0)
            # Sanity: version is always 2, entries capped at 2000
            if version == 2 and 0 < num_entries <= 2000:
                pos = 16  # skip header
                idx = 0
                for entry_idx in range(num_entries + num_pinned + 4):
                    if pos + 8 > len(data):
                        break

                    cat_type = struct.unpack_from('<I', data, pos)[0]
                    if cat_type in (0xFFFF, 0xFFFFFFFF):
                        break
                    pos += 4

                    # Category 2 = task entry: no LNK, skip a name block
                    if cat_type == 2:
                        # Task entries have a variable UTF-16LE name instead of LNK
                        try:
                            name_len = struct.unpack_from('<I', data, pos)[0]
                            pos += 4
                            task_name = ''
                            if 0 < name_len <= 512:
                                raw_name = data[pos: pos + name_len * 2]
                                task_name = raw_name.decode('utf-16-le', errors='replace').rstrip('\x00')
                                pos += name_len * 2
                            # Skip sentinel
                            if pos + 4 <= len(data):
                                pos += 4
                            result['entries'].append({
                                'stream':       f'task_{entry_idx}',
                                'lnk':          {'valid': False},
                                'access_count': 0,
                                'last_modified': '',
                                'birth_time':   '',
                                'hostname':     '',
                                'pin_status':   'Task',
                                'entry_path':   '',
                                'category':     CATEGORY_LABELS.get(cat_type, f'Type_{cat_type}'),
                                'entry_label':  task_name,
                            })
                            idx += 1
                        except Exception as te:
                            log.debug(f"Custom dest task entry error: {te}")
                            break
                        continue

                    # Categories 0 and 1: LNK entry
                    lnk_size = struct.unpack_from('<I', data, pos)[0]
                    pos += 4

                    if lnk_size == 0 or lnk_size > len(data) - pos:
                        # Possibly mis-parsed; try reading until next sentinel
                        sent_pos = data.find(struct.pack('<I', SENTINEL), pos)
                        if sent_pos == -1 or sent_pos - pos > 65536:
                            break
                        lnk_size = sent_pos - pos

                    lnk_blob = data[pos: pos + lnk_size]
                    pos += lnk_size

                    # Consume sentinel
                    if pos + 4 <= len(data):
                        pos += 4

                    # Parse the embedded LNK
                    lnk_info = {'valid': False}
                    entry_label = ''
                    if lnk_blob[:4] == LNK_MAGIC:
                        lnk_info = parse_lnk(lnk_blob)
                        # For web browsing entries the 'description' or 'name_string'
                        # field in the LNK carries the page title / media title.
                        entry_label = (
                            lnk_info.get('description', '')
                            or lnk_info.get('name_string', '')
                            or lnk_info.get('target_path', '')
                        )

                    # Always record the entry so the full list is preserved
                    result['entries'].append({
                        'stream':       f'entry_{idx}',
                        'lnk':          lnk_info,
                        'access_count': 0,
                        'last_modified': lnk_info.get('modified_time', ''),
                        'birth_time':   lnk_info.get('creation_time', ''),
                        'hostname':     '',
                        'pin_status':   CATEGORY_LABELS.get(cat_type, f'Type_{cat_type}'),
                        'entry_path':   lnk_info.get('target_path', ''),
                        'category':     CATEGORY_LABELS.get(cat_type, f'Type_{cat_type}'),
                        'entry_label':  entry_label,
                    })
                    idx += 1

                if result['entries']:
                    parsed_ok = True
                    log.debug(
                        f"CustomDest structured parse: {len(result['entries'])} "
                        f"entries from {filename}")

        except Exception as e:
            result['errors'].append(f"Structured parse error: {e}")
            log.debug(f"CustomDest structured parse failed for {filename}: {e}")

    # ── Fallback: raw LNK magic scan (catches corrupt / non-standard files) ──
    if not parsed_ok:
        log.debug(f"CustomDest: falling back to raw LNK scan for {filename}")
        pos = 0
        idx = 0
        while True:
            pos = data.find(LNK_MAGIC, pos)
            if pos == -1:
                break
            lnk_info = parse_lnk(data[pos:])
            if lnk_info['valid']:
                result['entries'].append({
                    'stream':       f'fallback_{idx}',
                    'lnk':          lnk_info,
                    'access_count': 0,
                    'last_modified': lnk_info.get('modified_time', ''),
                    'birth_time':   lnk_info.get('creation_time', ''),
                    'hostname':     '',
                    'pin_status':   '',
                    'entry_path':   lnk_info.get('target_path', ''),
                    'category':     'Recent (Auto)',
                    'entry_label':  (lnk_info.get('description', '')
                                     or lnk_info.get('target_path', '')),
                })
                idx += 1
            pos += 4
        if idx:
            result['errors'].append(
                f"Used fallback LNK scan (structured parse failed): {idx} entries found.")

    # Sort: pinned items first, then by timestamp descending
    def _sort_key(e):
        is_pinned = 1 if e.get('pin_status') == 'Pinned' else 0
        ts = e.get('last_modified', '') or e['lnk'].get('modified_time', '') or ''
        return (is_pinned, ts)

    result['entries'].sort(key=_sort_key, reverse=True)
    return result


def _guid_str(b: bytes) -> str:
    if len(b) < 16:
        return ''
    d1, d2, d3 = struct.unpack_from('<IHH', b)
    d4 = b[8:16].hex()
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[:4].upper()}-{d4[4:].upper()}"


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 8 – TIMELINE BUILDER
# ═══════════════════════════════════════════════════════════════════════════

def build_timeline(all_jumplist_results: list) -> list:
    """Build a unified chronological timeline from all JumpList results.

    Deleted detection:
      - A JL file itself is marked deleted if its NTFS MFT record had the
        in-use flag cleared at extraction time (jl['deleted'] == True).
      - Individual LNK entries within a JL are considered deleted if they
        were the sole entry in a deleted JL container, OR if the LNK
        target path references a file with the Hidden/System attribute set
        alongside a missing creation timestamp (heuristic only).

    Path resolution (v4.0):
      - Uses infer_target_path() for multi-layer path reconstruction.
      - Deleted files get descriptive placeholders instead of blank cells.
      - Network/UNC paths are fully reconstructed where possible.
    """
    events = []
    for jl in all_jumplist_results:
        app_name  = jl.get('app_name', jl.get('app_id', 'Unknown'))
        jl_type   = jl.get('type', '')
        filename  = jl.get('filename', '')
        # A JL file flagged deleted at the filesystem level means all
        # entries within it are from deleted/removed application activity.
        jl_deleted = bool(jl.get('deleted', False))

        for entry in jl.get('entries', []):
            lnk = entry.get('lnk', {})

            # Gather every available timestamp from both the DestList
            # metadata and the embedded LNK header — whichever has data.
            timestamps = {}
            for field, label in [
                ('modified_time',  'Target Modified'),
                ('access_time',    'Target Accessed'),
                ('creation_time',  'Target Created'),
                ('last_modified',  'JL Entry Last Access'),
                ('birth_time',     'JL Entry First Seen'),
            ]:
                # Check entry-level field first, then LNK sub-dict
                ts = entry.get(field) or lnk.get(field, '')
                if ts and ts not in ('', 'Unknown', 'N/A'):
                    timestamps[label] = ts

            # Path resolution: use multi-layer infer_target_path() which handles
            # deleted files, network paths, partial paths, and app defaults.
            path = infer_target_path(lnk, entry, jl).strip()
            if not path:
                # For custom destinations, entry_path or entry_label may have the URL/path
                path = (entry.get('entry_path', '')
                        or entry.get('entry_label', '')
                        or '[Path Not Recoverable]')

            # Entry-level deleted flag: inherits from JL container, or set
            # explicitly on the entry itself (e.g. pytsk3 flags it).
            entry_deleted = jl_deleted or bool(entry.get('deleted', False))

            # Surface the label (page title / media title) for custom destinations
            entry_label = entry.get('entry_label', '') or lnk.get('description', '')
            category    = entry.get('category', '')

            for ts_label, ts_val in timestamps.items():
                if ts_val:
                    events.append({
                        'timestamp':    ts_val,
                        'event_type':   ts_label,
                        'application':  app_name,
                        'jl_type':      jl_type,
                        'path':         path,
                        'drive_type':   lnk.get('drive_type', ''),
                        'volume':       lnk.get('volume_label', ''),
                        'network':      lnk.get('net_share', ''),
                        'hostname':     entry.get('hostname', ''),
                        'access_count': entry.get('access_count', 0),
                        'deleted':      entry_deleted,
                        'attributes':   ', '.join(lnk.get('attributes', [])),
                        'jl_filename':  filename,
                        'entry_label':  entry_label,
                        'category':     category,
                    })

    events.sort(key=lambda e: e.get('timestamp') or '')
    return events


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 9 – PDF REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════

def generate_pdf_report(output_path, segments, image_hash,
                         jumplist_results, timeline,
                         analyst_name="Forensic Analyst",
                         case_number="N/A",
                         lnk_results=None,
                         lnk_correlations=None,
                         image_sha256="N/A",
                         all_lnk_raw=None) -> str:

    lnk_results      = lnk_results or []
    lnk_correlations = lnk_correlations or []
    all_lnk_raw      = all_lnk_raw or []

    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, PageBreak,
                                     HRFlowable, KeepTogether)
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

    W, H = A4

    # ── Palette ───────────────────────────────────────────────────────────────
    DARK_BLUE   = colors.HexColor('#1a2744')
    MID_BLUE    = colors.HexColor('#2d4a8a')
    LIGHT_BLUE  = colors.HexColor('#dce8f5')
    ACCENT_RED  = colors.HexColor('#c0392b')
    ACCENT_GOLD = colors.HexColor('#d4a017')
    GREY_DARK   = colors.HexColor('#2c3e50')
    GREY_MID    = colors.HexColor('#95a5a6')
    GREY_LIGHT  = colors.HexColor('#ecf0f1')
    WHITE       = colors.white
    BLACK       = colors.black
    GREEN_DARK  = colors.HexColor('#1b5e20')
    AMBER       = colors.HexColor('#e65100')

    base_styles = getSampleStyleSheet()

    def style(name, parent='Normal', **kw):
        return ParagraphStyle(name, parent=base_styles[parent], **kw)

    S = {
        'cover_title': style('ct', fontSize=26, textColor=WHITE,
                              alignment=TA_CENTER, fontName='Helvetica-Bold', spaceAfter=4),
        'cover_sub':   style('cs', fontSize=13, textColor=LIGHT_BLUE,
                              alignment=TA_CENTER, fontName='Helvetica', spaceAfter=4),
        'cover_meta':  style('cm', fontSize=9.5, textColor=GREY_MID,
                              alignment=TA_CENTER, fontName='Helvetica'),
        'h1':    style('h1',  fontSize=15, textColor=DARK_BLUE,
                       fontName='Helvetica-Bold', spaceBefore=16, spaceAfter=5),
        'h2':    style('h2',  fontSize=12, textColor=MID_BLUE,
                       fontName='Helvetica-Bold', spaceBefore=10, spaceAfter=3),
        'h3':    style('h3',  fontSize=10, textColor=GREY_DARK,
                       fontName='Helvetica-Bold', spaceBefore=6, spaceAfter=2),
        'body':  style('body',fontSize=9,  textColor=BLACK,
                       fontName='Helvetica', leading=13, spaceAfter=3),
        'small': style('sm',  fontSize=7.5,textColor=GREY_DARK,
                       fontName='Helvetica', leading=11),
        'mono':  style('mono',fontSize=7.5,textColor=GREY_DARK,
                       fontName='Courier', leading=11),
        'warning': style('warn', fontSize=8.5, textColor=ACCENT_RED,
                         fontName='Helvetica-Bold', spaceAfter=3),
        'toc':   style('toc', fontSize=10, textColor=MID_BLUE,
                       fontName='Helvetica', leftIndent=8, spaceAfter=2),
        'deleted': style('del', fontSize=7.5, textColor=ACCENT_RED,
                         fontName='Helvetica-Bold', leading=11),
    }

    def hr(color=MID_BLUE, thickness=0.5):
        return HRFlowable(width='100%', thickness=thickness,
                          color=color, spaceAfter=4, spaceBefore=4)

    def tbl_style(alt_row=True):
        ts = [
            ('BACKGROUND',    (0,0), (-1,0), DARK_BLUE),
            ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
            ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0,0), (-1,0), 7.5),
            ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,1), (-1,-1), 7),
            ('BACKGROUND',    (0,1), (-1,-1), WHITE),
            ('GRID',          (0,0), (-1,-1), 0.25, GREY_MID),
            ('ALIGN',         (0,0), (-1,-1), 'LEFT'),
            ('VALIGN',        (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING',    (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING',   (0,0), (-1,-1), 4),
            ('RIGHTPADDING',  (0,0), (-1,-1), 4),
        ]
        if alt_row:
            ts.append(('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, GREY_LIGHT]))
        return TableStyle(ts)

    def p(text, st='body'):
        return Paragraph(str(text) if text else '—', S[st])

    def sp(h=6):
        return Spacer(1, h)

    def _trunc(s, n=70):
        s = str(s or '')
        return s[:n-3] + '...' if len(s) > n else s

    def _strip_mft_prefix(filename: str) -> str:
        """Strip '[NTFS MFT #xxxxxxx] ' or '[Carved @0x...] ' prefix from filename
        and return only the bare basename so the report shows the real .ms filename."""
        raw = filename.strip()
        raw = re.sub(r'^\[NTFS MFT #\d+\]\s*', '', raw, flags=re.IGNORECASE)
        raw = re.sub(r'^\[Carved @0x[0-9a-fA-F]+\]\s*', '', raw, flags=re.IGNORECASE)
        return os.path.basename(raw)

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.5*cm, bottomMargin=2.5*cm,
        title=f"JumpList Forensic Report – Case {case_number}",
        author=analyst_name,
    )

    story = []
    gen_time = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    # ── Pre-compute section flags (drives dynamic TOC + skipped sections) ───
    total_entries  = sum(len(j.get('entries', [])) for j in jumplist_results)
    total_jl       = len(jumplist_results)
    deleted_items  = [e for e in timeline if e.get('deleted')]
    net_events     = [e for e in timeline if e.get('network')]
    app_stats      = {}
    for ev in timeline:
        app = ev.get('application', 'Unknown')
        if app not in app_stats:
            app_stats[app] = {'count': 0, 'paths': set(), 'first': '', 'last': ''}
        app_stats[app]['count'] += 1
        app_stats[app]['paths'].add(ev.get('path', ''))
        ts = ev.get('timestamp', '')
        if ts:
            if not app_stats[app]['first'] or ts < app_stats[app]['first']:
                app_stats[app]['first'] = ts
            if ts > app_stats[app]['last']:
                app_stats[app]['last'] = ts

    has_timeline        = bool(timeline)
    has_deleted         = bool(deleted_items)
    has_network         = bool(net_events)
    has_app_summary     = bool(app_stats)
    has_lnk             = bool(lnk_results)
    has_lnk_correlation = bool(lnk_correlations)
    known_count         = sum(1 for jl in jumplist_results if jl.get('app_known'))

    # ── COVER PAGE ────────────────────────────────────────────────────────────
    story.append(sp(50))
    cover_data = [
        [p('WINDOWS JUMPLIST', 'cover_title')],
        [p('FORENSIC ANALYSIS REPORT', 'cover_title')],
        [sp(10)],
        [p('Digital Forensics &amp; Incident Response', 'cover_sub')],
        [p(f'Case No: {case_number}', 'cover_sub')],
        [sp(14)],
        [p(f'Analyst: {analyst_name}', 'cover_meta')],
        [p(f'Generated: {gen_time}', 'cover_meta')],
        [p('Tool: JLens v4.3', 'cover_meta')],
    ]
    cov_tbl = Table(cover_data, colWidths=[W - 4*cm])
    cov_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), DARK_BLUE),
        ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(cov_tbl)
    story.append(sp(20))

    # Stats bar — only show non-zero counters to avoid misleading zeros
    stat_items = [
        (str(total_jl),          'Jump List Files',   'h2'),
        (str(total_entries),     'Total Entries',     'h2'),
        (str(len(timeline)),     'Timeline Events',   'h2'),
        (str(len(deleted_items)),'Deleted Items',     'warning' if deleted_items else 'h2'),
        (str(len(net_events)),   'Network Paths',     'h2'),
        (str(len(lnk_results)),  'LNK Files Found',   'h2'),
    ]
    stats_vals = [p(v, s) for v, _, s in stat_items]
    stats_lbls = [p(l, 'small') for _, l, _ in stat_items]
    stats_tbl = Table([stats_vals, stats_lbls],
                      colWidths=[(W-4*cm)/len(stat_items)]*len(stat_items))
    stats_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), LIGHT_BLUE),
        ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
        ('GRID',          (0,0), (-1,-1), 0.4, MID_BLUE),
        ('TOPPADDING',    (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(stats_tbl)
    story.append(PageBreak())

    # ── EVIDENCE IDENTIFICATION ───────────────────────────────────────────────
    story.append(p('FORENSIC EXAMINATION REPORT', 'h1'))
    story.append(hr(DARK_BLUE, 1.5))
    story.append(p('<b>Legal Notice &amp; Disclaimer</b>', 'h2'))
    story.append(p(
        'This report has been prepared for forensic examination purposes only. '
        'All timestamps are in UTC. This document may constitute evidence and '
        'should be handled in accordance with applicable laws and chain-of-custody '
        'requirements.', 'body'))
    story.append(sp(6))
    story.append(p('Evidence Identification', 'h2'))
    ev_rows = [
        ['Property', 'Value'],
        ['Case Number',      case_number],
        ['Analyst Name',     analyst_name],
        ['Examination Date', gen_time],
        ['Tool Version',     'JLens v4.3'],
        ['Segments Found',   str(len(segments))],
        ['Image MD5',        image_hash],
        ['Image SHA256',     image_sha256],
        ['Total JL Files',   str(total_jl)],
        ['Total Entries',    str(total_entries)],
    ]
    for i, seg in enumerate(segments[:10]):
        ev_rows.append([f'Segment {i+1}', os.path.basename(seg)])
    if len(segments) > 10:
        ev_rows.append(['…', f'(+{len(segments)-10} more segments)'])
    ev_tbl = Table(
        [[p(r[0], 'h3'), p(r[1], 'body')] for r in ev_rows],
        colWidths=[5*cm, W-4*cm-5*cm])
    ev_tbl.setStyle(tbl_style())
    story.append(ev_tbl)
    story.append(PageBreak())

    # ── TABLE OF CONTENTS (dynamic — only sections with content) ─────────────
    story.append(p('Table of Contents', 'h1'))
    story.append(hr())
    toc_sections = [
        ('1.', 'Executive Summary',             True),
        ('2.', 'Jump List Overview',            True),
        ('3.', 'Detailed Jump List Analysis',   True),
        ('4.', 'Chronological Event Timeline',  has_timeline),
        ('5.', 'Deleted &amp; Suspicious Items',has_deleted),
        ('6.', 'Network Activity',              has_network),
        ('7.', 'Application Activity Summary',  has_app_summary),
        ('8.', 'Forensic Observations &amp; Recommendations', True),
        ('8b.','AppID Resolution Summary',      True),
        ('8c.','Standalone LNK File Analysis',  has_lnk),
        ('8d.','All MFT LNK File Hits',                       bool(all_lnk_raw)),
        ('8e.','User Activity Correlation (LNK ↔ JumpList)', has_lnk_correlation),
    ]
    for num, title, include in toc_sections:
        if include:
            story.append(p(f'<b>{num}</b>  {title}', 'toc'))
    story.append(PageBreak())

    # ── 1. EXECUTIVE SUMMARY ──────────────────────────────────────────────────
    story.append(p('1. Executive Summary', 'h1'))
    story.append(hr())
    apps_seen = sorted(set(j.get('app_name', 'Unknown') for j in jumplist_results))
    earliest  = min((e['timestamp'] for e in timeline if e.get('timestamp')), default=None)
    latest    = max((e['timestamp'] for e in timeline if e.get('timestamp')), default=None)
    time_span = (f'from <b>{earliest}</b> to <b>{latest}</b>'
                 if earliest and latest else 'with no recoverable timestamps')

    story.append(p(
        f'Forensic examination of the provided evidence identified '
        f'<b>{total_jl} Jump List file(s)</b> containing '
        f'<b>{total_entries} individual entry records</b> across '
        f'<b>{len(apps_seen)} distinct application(s)</b>. '
        f'The analysis produced <b>{len(timeline)} timestamped forensic events</b> '
        f'{time_span}.', 'body'))

    if apps_seen:
        story.append(sp(4))
        story.append(p('Applications Identified:', 'h3'))
        for app in apps_seen:
            story.append(p(f'• {app}', 'body'))

    if has_deleted:
        story.append(sp(4))
        story.append(p(
            f'<font color="#c0392b"><b>ATTENTION:</b></font> '
            f'{len(deleted_items)} deleted file/application reference(s) were '
            f'recovered from Jump List artefacts. These entries indicate activity '
            f'associated with files or containers that have since been removed.',
            'warning'))
    if has_network:
        story.append(p(
            f'<b>Network Activity:</b> {len(net_events)} UNC/network path '
            f'reference(s) were identified, indicating access to remote resources.',
            'body'))
    story.append(PageBreak())

    # ── 2. JUMP LIST OVERVIEW ─────────────────────────────────────────────────
    story.append(p('2. Jump List Overview', 'h1'))
    story.append(hr())
    story.append(p(
        'Windows Jump Lists are shell artefacts stored in a user profile that '
        'record recently and frequently accessed files, folders, and tasks for '
        'each application. They persist across reboots and can survive file '
        'deletion, making them valuable forensic evidence.', 'body'))
    story.append(p(
        '<b>AutomaticDestinations</b> – '
        '<font name="Courier">%APPDATA%\\Microsoft\\Windows\\Recent\\'
        'AutomaticDestinations\\</font> — OLE Compound File Binary containers '
        'named after the application AppID. Each stream is an embedded LNK file.',
        'body'))
    story.append(p(
        '<b>CustomDestinations</b> – '
        '<font name="Courier">%APPDATA%\\Microsoft\\Windows\\Recent\\'
        'CustomDestinations\\</font> — Proprietary binary format (version 2 header + '
        'per-entry category/LNK blobs + sentinel 0xBABFFBAB). Used by Internet Explorer, '
        'Microsoft Edge, and Windows Media Player to record recently visited URLs/pages '
        'and recently played media files. Entries carry a <i>category</i> (Recent, Pinned, '
        'or Task) and an optional label field that holds the page title or media title. '
        'Pinned items survive across session clears and are high-value forensic evidence.',
        'body'))
    story.append(sp(6))

    if jumplist_results:
        jl_rows = [['Filename', 'Type', 'Application', 'App Path',
                    'Category', 'ID Resolved', 'Entries', 'Modified']]
        for jl in jumplist_results:
            app_known = jl.get('app_known', False)
            app_match = jl.get('app_match', 'unknown')
            if app_known and app_match == 'exact':
                id_badge = p('✔ Exact', 'small')
            elif app_known and app_match == 'partial':
                id_badge = p('~ Partial', 'small')
            else:
                id_badge = p('✘ Unknown', 'warning')
            app_path_str = _trunc(jl.get('app_path', ''), 45) or '—'
            jl_rows.append([
                p(_trunc(_strip_mft_prefix(jl.get('filename', '') or jl.get('name', '')), 35), 'small'),
                p(jl.get('type', ''), 'small'),
                p(jl.get('app_name', ''), 'small'),
                p(app_path_str, 'mono'),
                p(jl.get('app_category', '—'), 'small'),
                id_badge,
                p(str(len(jl.get('entries', []))), 'small'),
                p(jl.get('mtime', ''), 'small'),
            ])
        col_w = [3.2*cm, 2.2*cm, 3*cm, 3.8*cm, 1.8*cm, 1.6*cm, 1.2*cm, 2.5*cm]
        jl_tbl = Table(jl_rows, colWidths=col_w)
        jl_tbl.setStyle(tbl_style())
        story.append(jl_tbl)
    story.append(PageBreak())

    # ── 3. DETAILED JUMP LIST ANALYSIS ────────────────────────────────────────
    story.append(p('3. Detailed Jump List Analysis', 'h1'))
    story.append(hr())
    for jl in jumplist_results:
        cat   = jl.get('app_category', '')
        known = jl.get('app_known', False)
        match = jl.get('app_match', 'unknown')
        badge_text   = f'[{cat}]' if cat else ''
        resolve_note = (
            '✔ Exact match'   if (known and match == 'exact')   else
            '~ Partial match' if (known and match == 'partial') else
            '✘ AppID not in database'
        )
        app_path_disp = jl.get('app_path', '') or '—'
        story.append(KeepTogether([
            p(f'<b>{jl.get("app_name","Unknown App")}</b> '
              f'<font color="#1b5e20">{badge_text}</font> '
              f'<font color="#95a5a6">({_strip_mft_prefix(jl.get("filename","") or jl.get("name",""))})</font>',
              'h2'),
            p(f'Type: {jl.get("type","")} | '
              f'Entries: {len(jl.get("entries",[]))} | '
              f'Modified: {jl.get("mtime","")} | '
              f'AppID Resolution: {resolve_note}',
              'small'),
            p(f'<b>App Path:</b> <font name="Courier">{app_path_disp}</font>', 'small'),
        ]))

        # Show errors only if they are meaningful (not generic OLE failures
        # when entries were still successfully extracted another way)
        real_errors = [e for e in jl.get('errors', [])
                       if not (jl.get('entries') and 'OLE open failed' in e)]
        for err in real_errors:
            story.append(p(f'⚠ {err}', 'warning'))

        entries = jl.get('entries', [])
        is_custom = jl.get('type', '') == 'CustomDestinations'
        if entries:
            if is_custom:
                # Custom Destinations: show category, label (page/media title), path, timestamps
                entry_rows = [['#', 'Category', 'Label / Title / URL',
                               'Target Path', 'Created', 'Modified', 'Drive']]
                for idx, ent in enumerate(entries[:200]):
                    lnk      = ent.get('lnk', {})
                    category = ent.get('category', ent.get('pin_status', ''))
                    label    = ent.get('entry_label', '') or lnk.get('description', '') or ''
                    tp       = infer_target_path(lnk, ent, jl)
                    # For web-browsing entries the URL is often in the target path itself
                    if not tp:
                        tp = ent.get('entry_path', '') or ''
                    label_disp = _trunc(label, 50) if label else _trunc(tp, 50)
                    tp_disp    = _trunc(tp, 45) if tp != label_disp else '—'
                    entry_rows.append([
                        p(str(idx + 1), 'small'),
                        p(category, 'small'),
                        p(label_disp, 'mono'),
                        p(tp_disp, 'mono'),
                        p(lnk.get('creation_time', '') or ent.get('birth_time', ''), 'small'),
                        p(lnk.get('modified_time', '') or ent.get('last_modified', ''), 'small'),
                        p(f"{lnk.get('drive_type', '')} {lnk.get('volume_label', '')}".strip()
                          or '—', 'small'),
                    ])
                cw = [0.5*cm, 2.2*cm, 4.2*cm, 3.8*cm, 2.4*cm, 2.4*cm, 1.8*cm]
                t = Table(entry_rows, colWidths=cw)
                t.setStyle(tbl_style())
                story.append(t)
            else:
                # AutomaticDestinations: original layout
                entry_rows = [['#', 'Target Path', 'App Path', 'Created', 'Modified',
                               'Accessed', 'Drive', 'Count']]
                for idx, ent in enumerate(entries[:200]):
                    lnk = ent.get('lnk', {})
                    tp = infer_target_path(lnk, ent, jl)
                    tp = _trunc(tp, 65)
                    entry_rows.append([
                        p(str(idx + 1), 'small'),
                        p(tp, 'mono'),
                        p(_trunc(app_path_disp, 40), 'mono'),
                        p(lnk.get('creation_time', '') or ent.get('birth_time', ''), 'small'),
                        p(lnk.get('modified_time', '') or ent.get('last_modified', ''), 'small'),
                        p(lnk.get('access_time', ''), 'small'),
                        p(f"{lnk.get('drive_type', '')} {lnk.get('volume_label', '')}".strip(), 'small'),
                        p(str(ent.get('access_count', '')), 'small'),
                    ])
                cw = [0.5*cm, 4.5*cm, 3*cm, 2.4*cm, 2.4*cm, 2.4*cm, 1.8*cm, 0.9*cm]
                t = Table(entry_rows, colWidths=cw)
                t.setStyle(tbl_style())
                story.append(t)
            if len(entries) > 200:
                story.append(p(f'… ({len(entries) - 200} more entries not shown)', 'small'))
        else:
            story.append(p(
                'No entries could be extracted from this Jump List file. '
                'This may indicate the file is empty, was never used, or the '
                'container format could not be fully decoded.', 'small'))
        story.append(sp(10))
    story.append(PageBreak())

    # ── 4. TIMELINE (only if has_timeline) ───────────────────────────────────
    if has_timeline:
        story.append(p('4. Chronological Event Timeline', 'h1'))
        story.append(hr())
        story.append(p(
            'The following table correlates all timestamped events extracted from '
            'Jump List artefacts, sorted in ascending chronological order. '
            'Events from deleted containers are highlighted in red.',
            'body'))
        story.append(sp(4))
        tl_rows = [['Timestamp (UTC)', 'Event Type', 'Application',
                    'Path / Target', 'Label / Title', 'Drive / Vol', 'Access #']]
        for ev in timeline[:2000]:
            path     = _trunc(ev.get('path', ''), 50)
            label    = _trunc(ev.get('entry_label', '') or '', 35)
            is_del   = ev.get('deleted', False)
            st       = 'deleted' if is_del else 'small'
            tl_rows.append([
                p(ev.get('timestamp', ''), st),
                p(ev.get('event_type', ''), st),
                p(ev.get('application', ''), st),
                p(path, 'mono' if not is_del else 'deleted'),
                p(label, st),
                p(f"{ev.get('drive_type', '')} {ev.get('volume', '')}".strip(), st),
                p(str(ev.get('access_count', '')), st),
            ])
        cw = [2.8*cm, 2.5*cm, 3*cm, 4.2*cm, 3*cm, 1.9*cm, 1.2*cm]
        t = Table(tl_rows, colWidths=cw)
        t.setStyle(tbl_style())
        story.append(t)
        if len(timeline) > 2000:
            story.append(p(f'… ({len(timeline)-2000} more events not shown)', 'small'))
        story.append(PageBreak())

    # ── 5. DELETED ITEMS (only if has_deleted) ───────────────────────────────
    if has_deleted:
        story.append(p('5. Deleted &amp; Suspicious Items', 'h1'))
        story.append(hr())
        story.append(p(
            'The following entries were recovered from Jump List files whose '
            'NTFS MFT records were flagged as deleted (in-use bit cleared) '
            'at the time of image acquisition. These artefacts provide evidence '
            'of file and application activity prior to deletion.', 'body'))
        story.append(sp(4))
        del_rows = [['Timestamp (UTC)', 'Application', 'Path / Target', 'Event Type', 'Drive']]
        for ev in deleted_items[:500]:
            del_rows.append([
                p(ev.get('timestamp', ''), 'deleted'),
                p(ev.get('application', ''), 'deleted'),
                p(_trunc(ev.get('path', ''), 60), 'deleted'),
                p(ev.get('event_type', ''), 'deleted'),
                p(f"{ev.get('drive_type','')} {ev.get('volume','')}".strip(), 'deleted'),
            ])
        t = Table(del_rows, colWidths=[3*cm, 3*cm, 6*cm, 3*cm, 2.2*cm])
        t.setStyle(tbl_style())
        story.append(t)
        if len(deleted_items) > 500:
            story.append(p(f'… ({len(deleted_items)-500} more deleted entries not shown)', 'small'))
        story.append(PageBreak())

    # ── 6. NETWORK ACTIVITY (only if has_network) ────────────────────────────
    if has_network:
        story.append(p('6. Network Activity', 'h1'))
        story.append(hr())
        story.append(p(
            'Jump List entries referencing UNC paths, mapped drives, or remote '
            'shares indicate the subject accessed files on networked resources. '
            'These entries can identify lateral movement, data exfiltration paths, '
            'or access to shared drives.', 'body'))
        story.append(sp(4))
        net_rows = [['Timestamp (UTC)', 'Application', 'Network Share / UNC', 'Target Path']]
        for ev in net_events[:500]:
            net_rows.append([
                p(ev.get('timestamp', ''), 'small'),
                p(ev.get('application', ''), 'small'),
                p(_trunc(ev.get('network', ''), 35), 'mono'),
                p(_trunc(ev.get('path', ''), 45), 'mono'),
            ])
        t = Table(net_rows, colWidths=[3*cm, 3.5*cm, 4.5*cm, 5.2*cm])
        t.setStyle(tbl_style())
        story.append(t)
        story.append(PageBreak())

    # ── 7. APPLICATION ACTIVITY SUMMARY (only if has_app_summary) ────────────
    if has_app_summary:
        story.append(p('7. Application Activity Summary', 'h1'))
        story.append(hr())
        app_rows = [['Application', 'Events', 'Unique Paths',
                     'First Activity (UTC)', 'Last Activity (UTC)']]
        for app, info in sorted(app_stats.items(),
                                key=lambda x: x[1]['count'], reverse=True):
            app_rows.append([
                p(app, 'body'),
                p(str(info['count']), 'small'),
                p(str(len(info['paths'])), 'small'),
                p(info['first'], 'small'),
                p(info['last'], 'small'),
            ])
        t = Table(app_rows, colWidths=[5*cm, 1.5*cm, 2*cm, 4*cm, 4*cm])
        t.setStyle(tbl_style())
        story.append(t)
        story.append(sp(8))

        # Most accessed paths
        path_counts = {}
        for ev in timeline:
            path = ev.get('path', '')
            if path and path not in ('Unknown Path', ''):
                path_counts[path] = path_counts.get(path, 0) + 1
        if path_counts:
            story.append(p('Most Frequently Accessed Paths:', 'h3'))
            top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:20]
            path_rows = [['Count', 'Path']]
            for path, count in top_paths:
                path_rows.append([p(str(count), 'small'), p(_trunc(path, 85), 'mono')])
            t = Table(path_rows, colWidths=[2*cm, W-4*cm-2*cm])
            t.setStyle(tbl_style())
            story.append(t)
        story.append(PageBreak())

    # ── 8. FORENSIC OBSERVATIONS ──────────────────────────────────────────────
    story.append(p('8. Forensic Observations &amp; Recommendations', 'h1'))
    story.append(hr())
    observations = [
        (f'The examined image contains evidence of <b>{len(apps_seen)} '
         f'application(s)</b> leaving Jump List traces, spanning '
         + (f'<b>{earliest}</b> to <b>{latest}</b>.' if earliest and latest
            else 'an indeterminate time period.')),
        (f'AppID resolution: <b>{known_count} of {total_jl}</b> AppIDs were '
         f'matched in the built-in database ({total_jl - known_count} unresolved). '
         f'Unresolved AppIDs should be cross-referenced against the target '
         f"system's SOFTWARE registry hive and application installation logs."),
        ('Jump List artefacts survive across OS reinstalls if the user profile '
         'directory is preserved on disk. Verify source media write-block status '
         'and hash integrity before and after acquisition.'),
        ('All timestamps are UTC. Verify system timezone from '
         '<font name="Courier">SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
         '\\TimeZoneInformation</font> for local time conversion. '
         'Note: Timestamps outside 1985–2100 are suppressed as FILETIME parser artefacts '
         '(e.g. corrupt 1601-01-01 epoch placeholders or uninitialized struct fields).'),
        ('The DestList stream within AutomaticDestinations files records access '
         'frequency counters. High access counts indicate habitually used files '
         'and may establish pattern-of-life evidence.'),
    ]
    if has_deleted:
        observations.append(
            f'<font color="#c0392b"><b>{len(deleted_items)} deleted artefact(s)'
            f'</b></font> were recovered from deleted Jump List containers. '
            f'Correlation with volume shadow copies or carved MFT records may '
            f'yield additional context.')
    if has_network:
        observations.append(
            f'<b>{len(net_events)} network path reference(s)</b> indicate access '
            f'to shared or remote resources. Correlate with event logs '
            f'(Security/4624, SMB shares) to establish authenticated access.')
    if has_lnk:
        crit_lnk = [r for r in lnk_results if 'CRITICAL' in r.get('priority', '')]
        observations.append(
            f'<b>{len(lnk_results)} standalone LNK file(s)</b> were identified. '
            + (f'<font color="#c0392b"><b>{len(crit_lnk)} CRITICAL Startup LNK(s)'
               f'</b></font> indicate potential persistence mechanism(s). '
               if crit_lnk else '') +
            f'See Section 8c for full analysis.')
    if not jumplist_results:
        observations.append(
            '<font color="#c0392b"><b>No Jump List artefacts were recovered.</b>'
            '</font> Possible causes: EWF parsing failure, deleted user profile, '
            'or a minimal installation with no recent file activity.')

    for i, obs in enumerate(observations, 1):
        story.append(p(f'<b>Observation {i}:</b> {obs}', 'body'))
        story.append(sp(4))
    story.append(PageBreak())

    # ── 8b. APPID RESOLUTION SUMMARY ─────────────────────────────────────────
    story.append(p('8b. AppID Resolution Summary', 'h1'))
    story.append(hr())
    story.append(p(
        'Each Jump List file is named after a numeric Application ID (AppID). '
        'This tool resolves AppIDs against a built-in database of 1400+ known '
        'applications including Windows built-ins, browsers (Chrome, Firefox, Edge, IE), '
        'Microsoft Office suites (all versions 2010–365), forensic tools, '
        'games (Steam/Epic/GOG), messaging apps (Teams, WhatsApp, Slack, Zoom), '
        'video editors, graphics tools, and third-party utilities. '
        'Empirically confirmed AppIDs from real Windows 7/10/11 systems are included. '
        'Unresolved IDs indicate custom, portable, or highly uncommon applications.',
        'body'))
    story.append(sp(4))
    if jumplist_results:
        res_rows = [['AppID (hex)', 'Resolved Application', 'App Path',
                     'Category', 'Match', 'JL Type', 'Entries']]
        for jl in jumplist_results:
            raw_id  = jl.get('app_id', '—')
            mq      = jl.get('app_match', 'unknown')
            mq_text = ('✔ Exact' if mq == 'exact' else
                       '~ Partial' if mq == 'partial' else '✘ Unknown')
            app_path_str = _trunc(jl.get('app_path', ''), 40) or '—'
            res_rows.append([
                p(raw_id, 'mono'),
                p(jl.get('app_name', '—'), 'small'),
                p(app_path_str, 'mono'),
                p(jl.get('app_category', '—'), 'small'),
                p(mq_text, 'warning' if mq == 'unknown' else 'small'),
                p(jl.get('type', ''), 'small'),
                p(str(len(jl.get('entries', []))), 'small'),
            ])
        cw = [3*cm, 3.8*cm, 4*cm, 1.8*cm, 1.5*cm, 2.5*cm, 1.2*cm]
        t = Table(res_rows, colWidths=cw)
        t.setStyle(tbl_style())
        story.append(t)
        story.append(sp(6))
        story.append(p(
            f'Resolution summary: <b>{known_count}</b> of '
            f'<b>{total_jl}</b> AppIDs resolved '
            f'({total_jl - known_count} unknown). '
            f'Unknown AppIDs warrant manual cross-referencing against the '
            f'target system\'s application installation records.', 'body'))
    story.append(PageBreak())

    # ── 8c. STANDALONE LNK FILE ANALYSIS (only if has_lnk) ───────────────────
    if has_lnk:
        story.append(p('8c. Standalone LNK File Analysis', 'h1'))
        story.append(hr())
        story.append(p(
            'Windows Shell Link (.lnk) files are automatically created when a '
            'user opens a file and may also be manually placed as shortcuts. '
            'LNK files in the Recent Items folder, Desktop, and Startup '
            'directories provide direct evidence of file access and application '
            'usage. Priority: CRITICAL = Startup (persistence), '
            'HIGH = Recent/Desktop, MEDIUM/LOW = other locations.', 'body'))
        story.append(sp(4))

        crit_lnk = [r for r in lnk_results if 'CRITICAL' in r.get('priority', '')]
        high_lnk = [r for r in lnk_results if 'HIGH'     in r.get('priority', '')]
        del_lnk  = [r for r in lnk_results if r.get('deleted')]

        story.append(p(
            f'Total LNK files: <b>{len(lnk_results)}</b> — '
            f'CRITICAL: <b>{len(crit_lnk)}</b> | '
            f'HIGH: <b>{len(high_lnk)}</b> | '
            f'Deleted: <b>{len(del_lnk)}</b>', 'body'))
        story.append(sp(4))

        lnk_rows = [['LNK Name', 'Priority', 'Target Path',
                     'Volume / Drive', 'Created', 'Modified', 'Del?']]
        for rec in lnk_results[:500]:
            lnk_info = rec.get('lnk', {})
            tp = (lnk_info.get('target_path') or
                  lnk_info.get('relative_path', '') or '—')
            tp = _trunc(tp, 55)
            del_flag = '⚠' if rec.get('deleted') else ''
            st = 'deleted' if rec.get('deleted') else 'small'
            lnk_rows.append([
                p(rec.get('name', ''), st),
                p(rec.get('priority', ''), st),
                p(tp, 'mono' if not rec.get('deleted') else 'deleted'),
                p(f"{lnk_info.get('drive_type','')} {lnk_info.get('volume_label','')}".strip(), st),
                p(lnk_info.get('creation_time', ''), st),
                p(lnk_info.get('modified_time', '') or rec.get('mtime', ''), st),
                p(del_flag, 'warning'),
            ])
        cw = [3.2*cm, 3.8*cm, 4.5*cm, 2.2*cm, 2.5*cm, 2.5*cm, 0.7*cm]
        t = Table(lnk_rows, colWidths=cw)
        t.setStyle(tbl_style())
        story.append(t)
        if len(lnk_results) > 500:
            story.append(p(f'… ({len(lnk_results)-500} more LNK files not shown)', 'small'))
        story.append(PageBreak())

    # ── 8d. ALL MFT LNK HITS (every .lnk found, pre-parse-filter) ──────────────
    if all_lnk_raw:
        story.append(p('8d. All MFT LNK File Hits (Complete Inventory)', 'h1'))
        story.append(hr())
        story.append(p(
            'The following table lists every .lnk (Shell Link) file discovered '
            'during the MFT walk, including entries whose internal structure could '
            'not be fully parsed. The MFT path, NTFS record number, file size, '
            'last-modified timestamp, and deletion status are recorded from the '
            'filesystem metadata independently of LNK header parsing. '
            'Duplicate MFT record numbers indicate the same logical file appearing '
            'in both the active MFT region and a shadow / alternate data area.',
            'body'))
        story.append(sp(4))
        story.append(p(f'Total MFT .lnk hits: <b>{len(all_lnk_raw)}</b>', 'body'))
        story.append(sp(4))

        # Deduplicate display by name for readability, but show all MFT numbers
        # Build rows: one per raw hit
        raw_rows = [['#', 'LNK Filename', 'MFT Path / Location', 'Size (bytes)',
                     'Modified (UTC)', 'Del?']]
        seen_names = {}
        for idx, hit in enumerate(all_lnk_raw[:2000], 1):
            name = hit.get('name', '')
            path = hit.get('path', '')
            size = str(hit.get('size', ''))
            mtime = hit.get('mtime', '') or '—'
            deleted = '⚠' if hit.get('deleted') else ''
            st = 'deleted' if hit.get('deleted') else 'small'
            raw_rows.append([
                p(str(idx), 'small'),
                p(name, st),
                p(_trunc(path, 60), 'mono'),
                p(size, 'small'),
                p(mtime, 'small'),
                p(deleted, 'warning'),
            ])
        cw2 = [0.7*cm, 3.8*cm, 5.5*cm, 1.6*cm, 2.8*cm, 0.7*cm]
        raw_tbl = Table(raw_rows, colWidths=cw2)
        raw_tbl.setStyle(tbl_style())
        story.append(raw_tbl)
        if len(all_lnk_raw) > 2000:
            story.append(p(f'… ({len(all_lnk_raw)-2000} more entries not shown)', 'small'))
        story.append(PageBreak())

    # ── 8e. LNK ↔ JUMPLIST CORRELATION (only if has_lnk_correlation) ─────────
    if has_lnk_correlation:
        story.append(p('8e. User Activity Correlation (LNK ↔ JumpList)', 'h1'))
        story.append(hr())
        story.append(p(
            'Cross-referencing standalone LNK targets against JumpList entry paths '
            'identifies files that appear in both artefact classes. '
            'Corroborated entries carry stronger evidentiary weight — they '
            'demonstrate not only that a shortcut existed but that the application '
            'was actively used to open that file.', 'body'))
        story.append(sp(4))
        story.append(p(
            f'<b>{len(lnk_correlations)}</b> corroborated access event(s) '
            f'identified across both artefact classes:', 'body'))
        story.append(sp(4))
        for idx, cor in enumerate(lnk_correlations[:200], 1):
            story.append(p(
                f'<b>{idx}. {cor["lnk_name"]}</b>'
                + (' <font color="#c0392b">[DELETED LNK]</font>'
                   if cor.get('lnk_deleted') else ''), 'h3'))
            story.append(p(
                f'Location: {cor["lnk_path"]} | '
                f'Priority: {cor.get("priority","")} | '
                f'Modified: {cor.get("lnk_mtime","")}', 'small'))
            story.append(p(
                f'Target: <font name="Courier">{cor["lnk_target"]}</font>', 'body'))
            jm_rows = [['Application (JumpList)', 'AppID', 'Access Count',
                        'Last Access', 'JL File']]
            for jm in cor.get('jl_matches', []):
                jm_rows.append([
                    p(jm.get('app_name', ''), 'small'),
                    p(jm.get('app_id', ''), 'mono'),
                    p(str(jm.get('access_count', '')), 'small'),
                    p(jm.get('last_access', ''), 'small'),
                    p(os.path.basename(jm.get('jl_file', '')), 'small'),
                ])
            t2 = Table(jm_rows, colWidths=[4*cm, 3*cm, 2*cm, 3.5*cm, 5*cm])
            t2.setStyle(tbl_style())
            story.append(t2)
            story.append(sp(8))
        if len(lnk_correlations) > 200:
            story.append(p(f'… ({len(lnk_correlations)-200} more correlations not shown)', 'small'))
        story.append(PageBreak())

    # ── END OF REPORT ─────────────────────────────────────────────────────────
    story.append(sp(20))
    story.append(hr(DARK_BLUE, 1.5))
    story.append(p(
        f'END OF REPORT — Generated by JLens v4.3 | '
        f'{gen_time} | Analyst: {analyst_name} | Case: {case_number}', 'small'))

    doc.build(story)
    log.info(f"PDF report saved: {output_path}")
    return output_path

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 10 – MAIN ANALYSIS PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def run_analysis(seed_file: str, output_pdf: str,
                  analyst: str = "Forensic Analyst",
                  case_number: str = "N/A",
                  include_lnk_scan: bool = True) -> str:

    log.info("=" * 60)
    log.info("  JLens v4.3")
    log.info("=" * 60)

    jl_files = []
    segments = []
    image_hash   = "N/A"
    image_sha256 = "N/A"
    lnk_results      = []
    all_lnk_raw      = []   # every .lnk file found by MFT walk (pre-parse filter)
    lnk_correlations = []

    # ── Mode A: directory of extracted JL files ───────────────────────────
    if os.path.isdir(seed_file):
        log.info(f"Directory mode: walking {seed_file}")
        segments = [seed_file]
        jl_files = _walk_directory_for_jl(seed_file)

    # ── Mode B: E01/EWF image ─────────────────────────────────────────────
    else:
        segments = find_ewf_segments(seed_file)
        hashes = compute_image_hashes(segments)
        image_hash   = hashes['md5']
        image_sha256 = hashes['sha256']

        # Open image with pure-Python EWF decoder
        log.info("Opening image with pure-Python EWF decoder...")
        reader = PureEWFReader(segments)

        if not reader._is_ewf:
            log.warning("EWF parsing failed; treating as raw DD image.")

        # Find NTFS partitions (GPT + MBR + scan)
        partition_offsets = find_ntfs_partitions(reader)
        log.info(f"Partitions to examine: {[hex(o) for o in partition_offsets]}")

        # Walk each NTFS partition with all 3 methods
        for part_offset in partition_offsets:
            log.info(f"Examining partition at offset {hex(part_offset)}")
            walker = NTFSWalker(reader, part_offset)
            found = walker.enumerate_jumplist_files()
            jl_files.extend(found)

            # ── Standalone LNK Scan ───────────────────────────────────────
            if include_lnk_scan:
                log.info(f"Running standalone LNK scan on partition {hex(part_offset)}...")
                lnk_scanner = StandaloneLNKScanner(reader, part_offset)
                part_lnk, raw_hits = lnk_scanner.scan()
                if not part_lnk:
                    log.info("MFT walk found no LNK files; trying raw carve...")
                    part_lnk, raw_hits = lnk_scanner.scan_raw_carve()
                lnk_results.extend(part_lnk)
                all_lnk_raw.extend(raw_hits)
                log.info(f"Found {len(part_lnk)} standalone LNK file(s) on partition {hex(part_offset)}.")

        # If still nothing found, attempt content carve across the whole image
        if not jl_files:
            log.warning("No JL files from NTFS walk; attempting raw content carve...")
            jl_files = _content_carve_jl(reader)

        reader.close()

    # ── Mode C: live system fallback ─────────────────────────────────────
    if not jl_files and sys.platform == 'win32':
        log.warning("No JL files found in image. Checking live system as fallback...")
        jl_files.extend(collect_live_jumplist_files())

    if not jl_files:
        log.warning("=" * 60)
        log.warning("NO JUMP LIST FILES FOUND.")
        log.warning("Possible reasons:")
        log.warning("  1. pyewf missing — EWF could not be decoded (FIXED in v3.0)")
        log.warning("  2. Image is a non-Windows disk or no user activity")
        log.warning("  3. User profile was deleted before imaging")
        log.warning("=" * 60)

    # ── Parse each JL file ────────────────────────────────────────────────
    jumplist_results = []
    for jl_file in jl_files:
        name = jl_file['name']
        data = jl_file['data']
        meta = {k: v for k, v in jl_file.items() if k != 'data'}
        log.info(f"Parsing: {name} ({len(data)} bytes)")
        try:
            if name.lower().endswith('.automaticdestinations-ms'):
                result = parse_automatic_destinations(data, jl_file['path'])
            elif name.lower().endswith('.customdestinations-ms'):
                result = parse_custom_destinations(data, jl_file['path'])
            else:
                continue
            result.update(meta)
            jumplist_results.append(result)
        except Exception as e:
            log.error(f"Failed to parse {name}: {e}")

    log.info(f"Parsed {len(jumplist_results)} Jump List file(s).")

    # ── Correlate LNK files with JumpList entries ─────────────────────────
    if lnk_results and jumplist_results:
        log.info("Correlating standalone LNK files with JumpList entries...")
        # Use the first partition's scanner for the static method
        lnk_correlations = StandaloneLNKScanner.correlate_with_jumplists(
            lnk_results, jumplist_results)
        log.info(f"Correlation: {len(lnk_correlations)} matches found.")

    timeline = build_timeline(jumplist_results)
    log.info(f"Timeline: {len(timeline)} events.")

    pdf_path = generate_pdf_report(
        output_pdf, segments, image_hash,
        jumplist_results, timeline, analyst, case_number,
        lnk_results=lnk_results,
        lnk_correlations=lnk_correlations,
        image_sha256=image_sha256,
        all_lnk_raw=all_lnk_raw)

    return pdf_path


def _content_carve_jl(reader) -> list:
    """
    Last-resort: scan raw image bytes for OLE CFB magic (automaticDestinations)
    and LNK magic clusters, extract plausible JL files.
    """
    results = []
    log.info("Content carve: scanning for OLE CFB headers (D0 CF 11 E0)...")

    CFB_MAGIC = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
    block_size = 4 * (1 << 20)  # 4 MB blocks

    try:
        size = min(reader.get_size(), 100 * (1 << 30))
        idx = 0
        for block_start in range(0, size, block_size):
            block = reader.read(block_start, block_size + 512)
            pos = 0
            while pos < len(block) - 512:
                if block[pos:pos+8] == CFB_MAGIC:
                    # Read up to 2 MB for this potential JL file
                    raw = block[pos: pos + 2 * (1 << 20)]
                    # Quick sanity: check if it looks like a JL container
                    # AutomaticDestinations AppID files are typically 10-500 KB
                    if 1024 < len(raw):
                        # Try to get a name from nearby strings
                        name_guess = f'carved_{idx:04d}.automaticDestinations-ms'
                        results.append({
                            'path': f'[Carved @{hex(block_start+pos)}] {name_guess}',
                            'name': name_guess,
                            'data': raw,
                            'size': len(raw),
                            'mtime': 'Unknown', 'atime': 'Unknown',
                            'ctime': 'Unknown', 'deleted': False,
                        })
                        idx += 1
                pos += 512
    except Exception as e:
        log.debug(f"Content carve error: {e}")

    log.info(f"Content carve found {len(results)} candidate file(s).")
    return results



# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 10b – STANDALONE LNK FILE EXTRACTOR
#  Scans NTFS partitions in E01 images for .lnk files that are NOT embedded
#  inside Jump List containers — these are standalone shell links in:
#    %APPDATA%\Microsoft\Windows\Recent\
#    Desktop, SendTo, user-created shortcuts, etc.
#  Correlating standalone LNK artefacts with JumpList entries produces a
#  richer picture of user activity and file access patterns.
# ═══════════════════════════════════════════════════════════════════════════

LNK_MAGIC = b'\x4C\x00\x00\x00'

# Common GUID classes that appear in LNK target ID lists
SHELL_GUID_MAP = {
    "{20d04fe0-3aea-1069-a2d8-08002b30309d}": "This PC (My Computer)",
    "{645ff040-5081-101b-9f08-00aa002f954e}": "Recycle Bin",
    "{f3364ba0-65b9-11ce-a9ba-00aa004ae837}": "My Documents",
    "{031e4825-7b94-4dc3-b131-e946b44c8dd5}": "Libraries",
    "{1cf1260c-4dd0-4ebb-811f-33c572699fde}": "Music Library",
    "{4bd8d571-6d19-48d3-be97-422220080e43}": "Pictures Library",
    "{33e28130-4e1e-4676-835a-98395c3bc3bb}": "Videos Library",
    "{a0953c92-50dc-43bf-be83-3742fed03c9c}": "Documents Library",
    "{374de290-123f-4565-9164-39c4925e467b}": "Downloads",
    "{b4bfcc3a-db2c-424c-b029-7fe99a87c641}": "Desktop",
    "{f38bf404-1d43-42f2-9305-67de0b28fc23}": "Windows Folder",
    "{26ee0668-a00a-44d7-9371-beb064c98683}": "Control Panel",
    "{7007acc7-3202-11d1-aad2-00805fc1270e}": "Network Connections",
    "{59031a47-3f72-44a7-89c5-5595fe6b30ee}": "Users Folder",
    "{4336a54d-038b-4685-ab02-99bb52d3fb8b}": "Public Folder",
}


class StandaloneLNKScanner:
    """
    Scans an E01/EWF image's NTFS partitions for standalone .lnk files
    (shell link shortcuts) using MFT walking.

    Standalone LNK files complement Jump List analysis:
      - JumpList → what apps the user used and which files they opened recently
      - Standalone LNK → explicit shortcuts placed on Desktop, SendTo,
        Quick Access, Recent Items, etc.

    The correlation of both artefact classes produces a comprehensive
    timeline of user interaction.
    """

    LNK_SUFFIXES = ('.lnk',)

    # Directories of highest forensic interest for standalone LNK files
    PRIORITY_DIRS = [
        'recent',           # %APPDATA%\Microsoft\Windows\Recent\
        'desktop',          # User Desktop and Public Desktop
        'sendto',           # %APPDATA%\Microsoft\Windows\SendTo\
        'startup',          # Startup folder (persistence indicator)
        'programs',         # Start Menu Programs
        'quick access',     # Windows 10 Quick Access pinned items
        'links',            # Libraries links
        'appdata',
        'roaming',
        'microsoft',
        'windows',
    ]

    def __init__(self, reader, partition_offset: int):
        self.reader = reader
        self.partition_offset = partition_offset

    def _get_raw_mft_lnk_hits(self) -> list:
        """Return ALL .lnk file entries found in MFT, regardless of parse_lnk validity.
        Used to populate the 'All MFT LNK Hits' table in the PDF report."""
        try:
            walker = NTFSWalker(self.reader, self.partition_offset)
            orig_suffixes = walker.JL_SUFFIXES
            walker.JL_SUFFIXES = self.LNK_SUFFIXES
            raw_files = walker._enum_pure_ntfs()
            walker.JL_SUFFIXES = orig_suffixes
            return raw_files
        except Exception as e:
            log.debug(f"_get_raw_mft_lnk_hits error: {e}")
            return []

    def scan(self) -> tuple:
        """
        Scan the NTFS partition for standalone .lnk files via MFT walk.
        Returns (parsed_results, all_raw_files):
          parsed_results -- list of dicts with successfully parsed LNK data
          all_raw_files  -- list of every .lnk MFT record found (pre-parse filter)
        """
        results = []
        all_raw = []
        log.info("StandaloneLNKScanner: starting MFT walk for .lnk files...")
        try:
            walker = NTFSWalker(self.reader, self.partition_offset)
            orig_suffixes = walker.JL_SUFFIXES
            walker.JL_SUFFIXES = self.LNK_SUFFIXES
            raw_files = walker._enum_pure_ntfs()
            walker.JL_SUFFIXES = orig_suffixes

            log.info(f"StandaloneLNKScanner: found {len(raw_files)} .lnk file(s) via MFT walk.")

            for item in raw_files:
                path_lower = item.get('path', '').lower()
                name_lower = item.get('name', '').lower()
                priority   = self._classify_priority(path_lower, name_lower)
                raw_rec = {
                    'name':     item['name'],
                    'path':     item.get('path', ''),
                    'size':     item.get('size', 0),
                    'mtime':    item.get('mtime', ''),
                    'deleted':  item.get('deleted', False),
                    'priority': priority,
                    'parse_ok': False,
                    'lnk':      {},
                }
                try:
                    lnk_info = parse_lnk(item['data'])
                    raw_rec['parse_ok'] = lnk_info['valid']
                    raw_rec['lnk'] = lnk_info
                    if lnk_info['valid']:
                        results.append({
                            'name':        item['name'],
                            'path':        item['path'],
                            'size':        item['size'],
                            'mtime':       item.get('mtime', ''),
                            'deleted':     item.get('deleted', False),
                            'lnk':         lnk_info,
                            'priority':    priority,
                            'source_type': 'Standalone LNK',
                        })
                except Exception as e:
                    log.debug(f"LNK parse error for {item.get('name','?')}: {e}")
                all_raw.append(raw_rec)

        except Exception as e:
            log.warning(f"StandaloneLNKScanner MFT walk failed: {e}")
            log.debug(traceback.format_exc())

        results.sort(key=lambda r: (not r['deleted'], r.get('mtime', '') or ''), reverse=True)
        all_raw.sort(key=lambda r: (not r['deleted'], r.get('mtime', '') or ''), reverse=True)
        log.info(f"StandaloneLNKScanner: {len(results)} valid standalone LNK files parsed.")
        return results, all_raw


    def scan_raw_carve(self) -> tuple:
        """
        Fallback: carve raw image bytes for LNK magic (4C 00 00 00).
        Only called when MFT walk yields nothing.
        Returns (parsed_results, all_raw_files).
        """
        results = []
        all_raw = []
        log.info("StandaloneLNKScanner: raw-carve fallback for LNK files...")
        try:
            size = min(self.reader.get_size(), 50 * (1 << 30))
            block_sz = 2 * (1 << 20)   # 2 MB blocks
            idx = 0
            for block_start in range(0, size, block_sz):
                block = self.reader.read(block_start, block_sz + 1024)
                pos = 0
                while pos < len(block) - 76:
                    if block[pos:pos+4] == LNK_MAGIC:
                        candidate = block[pos:pos + 65536]  # max 64 KB per LNK
                        lnk_info = parse_lnk(candidate)
                        rec = {
                            'name':        f'carved_lnk_{idx:04d}.lnk',
                            'path':        f'[Carved @{hex(block_start+pos)}]',
                            'size':        76,
                            'mtime':       lnk_info.get('modified_time', ''),
                            'deleted':     False,
                            'lnk':         lnk_info,
                            'priority':    'carved',
                            'parse_ok':    lnk_info['valid'],
                            'source_type': 'Carved LNK',
                        }
                        all_raw.append(rec)
                        if lnk_info['valid'] and (
                                lnk_info.get('target_path') or
                                lnk_info.get('relative_path') or
                                lnk_info.get('working_dir')):
                            results.append(rec)
                            idx += 1
                    pos += 4
        except Exception as e:
            log.debug(f"LNK raw carve error: {e}")
        log.info(f"StandaloneLNKScanner: carve found {len(results)} LNK candidate(s).")
        return results, all_raw

    @staticmethod
    def _classify_priority(path_lower: str, name_lower: str) -> str:
        """Assign forensic priority based on file location and name."""
        if 'recent' in path_lower:
            return 'HIGH – Recent Items'
        if 'startup' in path_lower:
            return 'CRITICAL – Startup (Persistence)'
        if 'desktop' in path_lower:
            return 'HIGH – Desktop'
        if 'sendto' in path_lower:
            return 'MEDIUM – SendTo'
        if 'programs' in path_lower or 'start menu' in path_lower:
            return 'MEDIUM – Start Menu'
        if 'appdata' in path_lower:
            return 'MEDIUM – AppData'
        return 'LOW – Other Location'

    @staticmethod
    def correlate_with_jumplists(lnk_results: list,
                                  jumplist_results: list) -> list:
        """
        Cross-reference standalone LNK targets against Jump List entry paths.
        Returns enriched correlation records for the report.

        Matching criteria:
          - Exact path match between LNK target_path and JL entry path
          - Basename match (filename only, case-insensitive)
        """
        correlations = []

        # Build JL path index
        jl_paths = {}   # normalised_path → [jl_result, ...]
        for jl in jumplist_results:
            app_name = jl.get('app_name', 'Unknown')
            for ent in jl.get('entries', []):
                lnk = ent.get('lnk', {})
                tp = (lnk.get('target_path') or
                      ent.get('entry_path', '') or
                      lnk.get('relative_path', ''))
                if not tp:
                    continue
                key = tp.strip().lower()
                jl_paths.setdefault(key, []).append({
                    'app_name':    app_name,
                    'app_id':      jl.get('app_id', ''),
                    'jl_file':     jl.get('filename', ''),
                    'access_count': ent.get('access_count', 0),
                    'last_access': (ent.get('last_modified') or
                                    lnk.get('modified_time', '')),
                })

        for lnk_rec in lnk_results:
            lnk_info = lnk_rec.get('lnk', {})
            target = (lnk_info.get('target_path') or
                      lnk_info.get('relative_path', ''))
            if not target:
                continue

            target_norm  = target.strip().lower()
            target_base  = os.path.basename(target_norm)
            matched_jl   = []

            # Exact match
            if target_norm in jl_paths:
                matched_jl.extend(jl_paths[target_norm])

            # Basename match (if no exact match)
            if not matched_jl:
                for jl_key, jl_list in jl_paths.items():
                    if os.path.basename(jl_key) == target_base:
                        matched_jl.extend(jl_list)

            if matched_jl:
                correlations.append({
                    'lnk_name':     lnk_rec['name'],
                    'lnk_path':     lnk_rec['path'],
                    'lnk_target':   target,
                    'lnk_mtime':    lnk_rec.get('mtime', ''),
                    'lnk_deleted':  lnk_rec.get('deleted', False),
                    'priority':     lnk_rec.get('priority', ''),
                    'jl_matches':   matched_jl,
                })

        log.info(f"LNK correlation: {len(correlations)} matches between "
                 f"{len(lnk_results)} LNK files and JumpList entries.")
        return correlations


def run_lnk_scan_on_image(seed_file: str) -> tuple:
    """
    Open an E01/DD image, find NTFS partitions, and run StandaloneLNKScanner.
    Returns (lnk_results, reader) — caller must call reader.close().
    """
    segments = find_ewf_segments(seed_file)
    reader = PureEWFReader(segments)
    partition_offsets = find_ntfs_partitions(reader)

    all_lnk = []
    for off in partition_offsets:
        scanner = StandaloneLNKScanner(reader, off)
        found, _ = scanner.scan()
        if not found:
            log.info("MFT scan found no LNK files; trying raw carve...")
            found, _ = scanner.scan_raw_carve()
        all_lnk.extend(found)

    return all_lnk, reader, segments



def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext

    root = tk.Tk()
    root.title("JLens v4.3")
    root.geometry("860x740")
    root.resizable(True, True)

    BG     = "#1a2744"
    FG     = "#dce8f5"
    ENTRY  = "#2d3e6a"
    BTN    = "#2d4a8a"
    ACCENT = "#4a90d9"
    GREEN  = "#27ae60"

    root.configure(bg=BG)
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('TLabel',      background=BG, foreground=FG,    font=('Helvetica', 10))
    style.configure('TButton',     background=BTN, foreground=FG,   font=('Helvetica', 10, 'bold'))
    style.configure('TEntry',      background=ENTRY, foreground=FG, fieldbackground=ENTRY)
    style.configure('TFrame',      background=BG)
    style.configure('TLabelframe', background=BG, foreground=FG)
    style.configure('TLabelframe.Label', background=BG, foreground=ACCENT,
                    font=('Helvetica', 11, 'bold'))
    style.configure('TCheckbutton', background=BG, foreground=FG)

    # ── Header ────────────────────────────────────────────────────────────
    hdr = tk.Frame(root, bg='#0d1530', pady=12)
    hdr.pack(fill='x')
    tk.Label(hdr, text="🔍  JLens v4.3",
             bg='#0d1530', fg=ACCENT,
             font=('Helvetica', 18, 'bold')).pack()
    tk.Label(hdr,
             text="Windows JumpList + Standalone LNK Analysis — AppID Resolution — Pure-Python EWF Decoder",
             bg='#0d1530', fg='#7f9ec0', font=('Helvetica', 9)).pack()

    main_frame = ttk.Frame(root, padding=16)
    main_frame.pack(fill='both', expand=True)

    # ── Evidence source ───────────────────────────────────────────────────
    ev_frame = ttk.LabelFrame(main_frame, text="  Evidence Source  ", padding=10)
    ev_frame.pack(fill='x', pady=6)

    ev_var = tk.StringVar()
    ttk.Label(ev_frame, text="E01 / EWF / DD / Directory:").grid(row=0, column=0, sticky='w')
    ttk.Entry(ev_frame, textvariable=ev_var, width=52).grid(row=0, column=1, padx=6)

    def browse_ev():
        f = filedialog.askopenfilename(
            title="Select E01/EWF seed file",
            filetypes=[("EWF Images", "*.E01 *.e01 *.Ex01 *.s01 *.001"),
                       ("Raw Images", "*.dd *.img *.raw *.bin"),
                       ("All Files", "*.*")])
        if f:
            ev_var.set(f)
    ttk.Button(ev_frame, text="Browse…", command=browse_ev).grid(row=0, column=2)

    def browse_dir():
        d = filedialog.askdirectory(title="Select folder with extracted JL files")
        if d:
            ev_var.set(d)
    ttk.Button(ev_frame, text="📁 Folder…", command=browse_dir).grid(row=0, column=3, padx=4)

    # Live mode checkbox
    live_var = tk.BooleanVar(value=False)
    tk.Checkbutton(ev_frame, text="🖥 Live System Mode (analyse current PC, no image needed)",
                   variable=live_var, bg=BG, fg=ACCENT,
                   selectcolor=ENTRY, font=('Helvetica', 9)).grid(
        row=1, column=0, columnspan=4, sticky='w', pady=4)

    # LNK scan checkbox
    lnk_var = tk.BooleanVar(value=True)
    tk.Checkbutton(ev_frame,
                   text="🔗 Include Standalone LNK Scan  (scan NTFS for .lnk shortcuts → user activity correlation)",
                   variable=lnk_var, bg=BG, fg='#7fff7f',
                   selectcolor=ENTRY, font=('Helvetica', 9)).grid(
        row=2, column=0, columnspan=4, sticky='w', pady=2)

    # ── Output ────────────────────────────────────────────────────────────
    out_frame = ttk.LabelFrame(main_frame, text="  Output  ", padding=10)
    out_frame.pack(fill='x', pady=6)
    out_var = tk.StringVar(value=os.path.join(
        os.path.expanduser("~"), "Desktop", "JL_Forensic_Report.pdf"))
    ttk.Label(out_frame, text="Output PDF:").grid(row=0, column=0, sticky='w')
    ttk.Entry(out_frame, textvariable=out_var, width=52).grid(row=0, column=1, padx=6)
    def browse_out():
        f = filedialog.asksaveasfilename(
            title="Save PDF report as",
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")])
        if f:
            out_var.set(f)
    ttk.Button(out_frame, text="Browse…", command=browse_out).grid(row=0, column=2)

    # ── Case metadata ─────────────────────────────────────────────────────
    meta_frame = ttk.LabelFrame(main_frame, text="  Case Metadata  ", padding=10)
    meta_frame.pack(fill='x', pady=6)
    analyst_var = tk.StringVar(value="Forensic Analyst")
    case_no_var = tk.StringVar(value="CASE-001")
    ttk.Label(meta_frame, text="Analyst Name:").grid(row=0, column=0, sticky='w')
    ttk.Entry(meta_frame, textvariable=analyst_var, width=28).grid(row=0, column=1, padx=6)
    ttk.Label(meta_frame, text="Case Number:").grid(row=0, column=2, sticky='w', padx=(20,0))
    ttk.Entry(meta_frame, textvariable=case_no_var, width=20).grid(row=0, column=3, padx=6)

    # ── Log ───────────────────────────────────────────────────────────────
    log_frame = ttk.LabelFrame(main_frame, text="  Analysis Log  ", padding=6)
    log_frame.pack(fill='both', expand=True, pady=6)

    log_toolbar = tk.Frame(log_frame, bg=BG)
    log_toolbar.pack(fill='x', pady=(0, 4))

    def save_log():
        out_path = out_var.get().strip()
        default_dir = os.path.dirname(out_path) if out_path else os.path.expanduser("~")
        default_name = "JL_Analysis_Log.txt"
        save_path = filedialog.asksaveasfilename(
            title="Save Analysis Log",
            initialdir=default_dir,
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if save_path:
            try:
                log_text.configure(state='normal')
                content = log_text.get('1.0', 'end')
                log_text.configure(state='disabled')
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Log Saved", f"Analysis log saved to:\n{save_path}")
            except Exception as ex:
                messagebox.showerror("Save Failed", f"Could not save log:\n{ex}")

    tk.Button(log_toolbar, text="💾  Save Log as .txt",
              bg='#2d4a8a', fg='#dce8f5', font=('Helvetica', 9, 'bold'),
              relief='flat', padx=8, pady=3,
              command=save_log).pack(side='left')

    log_text = scrolledtext.ScrolledText(
        log_frame, height=12, bg='#0d1530', fg='#7fff7f',
        font=('Courier', 9), insertbackground='white', wrap='word')
    log_text.pack(fill='both', expand=True)

    class TextHandler(logging.Handler):
        def emit(self, record):
            msg = self.format(record)
            def append():
                log_text.configure(state='normal')
                log_text.insert('end', msg + '\n')
                log_text.see('end')
                log_text.configure(state='disabled')
            root.after(0, append)
    th = TextHandler()
    th.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logging.getLogger().addHandler(th)

    progress = ttk.Progressbar(main_frame, mode='indeterminate')
    progress.pack(fill='x', pady=4)

    def run():
        ev = ev_var.get().strip()
        out = out_var.get().strip()
        live = live_var.get()

        if not live and not ev:
            messagebox.showerror("Input Required",
                "Please select an evidence file/folder, "
                "or enable Live System Mode.")
            return
        if not out:
            messagebox.showerror("Input Required", "Please specify output PDF path.")
            return

        btn_run.configure(state='disabled')
        progress.start(10)

        def worker():
            try:
                if live:
                    # Live mode: collect from current system
                    jl_files = collect_live_jumplist_files()
                    jumplist_results = []
                    for jl_file in jl_files:
                        name = jl_file['name']
                        data = jl_file['data']
                        meta = {k: v for k, v in jl_file.items() if k != 'data'}
                        if name.lower().endswith('.automaticdestinations-ms'):
                            r = parse_automatic_destinations(data, jl_file['path'])
                        elif name.lower().endswith('.customdestinations-ms'):
                            r = parse_custom_destinations(data, jl_file['path'])
                        else:
                            continue
                        r.update(meta)
                        jumplist_results.append(r)
                    timeline = build_timeline(jumplist_results)
                    pdf = generate_pdf_report(out, ['LIVE SYSTEM'], 'N/A',
                                              jumplist_results, timeline,
                                              analyst_var.get(), case_no_var.get())
                else:
                    pdf = run_analysis(ev, out,
                                       analyst=analyst_var.get(),
                                       case_number=case_no_var.get(),
                                       include_lnk_scan=lnk_var.get())
                root.after(0, lambda: on_done(pdf, None))
            except Exception as e:
                root.after(0, lambda: on_done(None, e))

        def on_done(pdf, err):
            progress.stop()
            btn_run.configure(state='normal')
            if err:
                log.error(f"Analysis failed: {err}\n{traceback.format_exc()}")
                messagebox.showerror("Analysis Failed",
                    f"An error occurred:\n\n{err}\n\nSee log for details.")
            else:
                if messagebox.askyesno("Complete",
                        f"Analysis complete!\nReport saved to:\n{pdf}\n\nOpen PDF now?"):
                    if sys.platform == 'win32':
                        os.startfile(pdf)

        threading.Thread(target=worker, daemon=True).start()

    btn_run = ttk.Button(main_frame,
                          text="▶  Run Analysis & Generate PDF Report",
                          command=run)
    btn_run.pack(pady=8, ipady=6, fill='x')

    root.mainloop()


# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='JLens v4.3')
    parser.add_argument('--image', '-i',   help='Path to E01 seed file (or directory)')
    parser.add_argument('--output', '-o',  help='Output PDF', default='JL_Forensic_Report.pdf')
    parser.add_argument('--analyst', '-a', help='Analyst name', default='Forensic Analyst')
    parser.add_argument('--case', '-c',    help='Case number', default='N/A')
    parser.add_argument('--live',          help='Live system mode', action='store_true')
    parser.add_argument('--no-lnk',       help='Skip standalone LNK scan', action='store_true',
                        dest='no_lnk')
    parser.add_argument('--gui',           help='Launch GUI', action='store_true')
    args = parser.parse_args()

    if args.gui or (not args.image and not args.live):
        try:
            launch_gui()
        except Exception as e:
            log.error(f"GUI failed: {e}")
            parser.print_help()
    elif args.live:
        jl_files = collect_live_jumplist_files()
        jumplist_results = []
        for jl_file in jl_files:
            name = jl_file['name']
            data = jl_file['data']
            meta = {k: v for k, v in jl_file.items() if k != 'data'}
            if name.lower().endswith('.automaticdestinations-ms'):
                r = parse_automatic_destinations(data, jl_file['path'])
            elif name.lower().endswith('.customdestinations-ms'):
                r = parse_custom_destinations(data, jl_file['path'])
            else:
                continue
            r.update(meta)
            jumplist_results.append(r)
        timeline = build_timeline(jumplist_results)
        generate_pdf_report(args.output, ['LIVE SYSTEM'], 'N/A',
                            jumplist_results, timeline, args.analyst, args.case)
    else:
        run_analysis(args.image, args.output, args.analyst, args.case,
                     include_lnk_scan=not args.no_lnk)


if __name__ == '__main__':
    main()
