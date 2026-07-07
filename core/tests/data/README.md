# tests/data — DMG Corpus

Real DMG images produced by macOS `hdiutil`, independent from the Rust parser,
satisfying the doer-checker principle.

## Files

| File | Size | Format | Tool / Command |
|------|------|--------|----------------|
| `hfsplus_udro.dmg` | 818 KB | UDIF/UDRO (raw blocks, GPT-wrapped HFS+) | `hdiutil convert -format UDRO` |
| `hfsplus_compressed.dmg` | 13 KB | UDIF/UDZO (zlib-compressed, same disk) | `hdiutil convert -format UDZO` |
| `synthetic.sparseimage` | 6 KB | Apple `.sparseimage` (`sprs`) | hand-built (see below) |
| `synthetic.sparsebundle/` | 2 KB | Apple `.sparsebundle` (bundle dir) | hand-built (see below) |

## Disk Layout (both images)

Both images virtualise the same 4 MiB HFS+ disk (8192 × 512-byte sectors):

| Sectors | Content |
|---------|---------|
| 0 | Protective MBR |
| 1 | GPT primary header |
| 2–33 | GPT primary partition table |
| 40–8151 | Apple_HFS partition |
| 8152–8158 | Free |
| 8159–8190 | GPT backup partition table |
| 8191 | GPT backup header |

HFS+ volume header magic `0x482B` is at byte offset `40×512 + 1024 = 21504`.

## Provenance

### `hfsplus_udro.dmg`
- **Origin**: generated locally on macOS with `hdiutil`
- **Commands**:
  ```bash
  hdiutil create -size 4m -fs HFS+ -volname TestVol /tmp/hfsplus.dmg
  hdiutil convert /tmp/hfsplus.dmg.dmg -format UDRO -o hfsplus_udro.dmg
  ```
- **Format**: UDIF version 4, koly trailer at `file_size − 512`, raw (type 0x01) BLKXRun entries

### `hfsplus_compressed.dmg`
- **Origin**: UDZO conversion of the same source disk
- **Commands**:
  ```bash
  hdiutil convert /tmp/hfsplus.dmg.dmg -format UDZO -o hfsplus_compressed.dmg
  ```
- **Format**: UDIF version 4, koly trailer at `file_size − 512`, zlib (type 0x80000005) BLKXRun entries

### `synthetic.sparseimage`  (SYNTHETIC)

Minimal hand-built `.sparseimage` specifying the `sprs` parse/read behaviour on
CI (the real-`hdiutil` oracle in `core/tests/sparse_images.rs` is env-gated and
skips on Linux). Layout: `sectors_per_band = 2` (band 1024 bytes),
`total_sectors = 6` (3 virtual bands, 3072-byte disk). Virtual band 0 starts
with the HFS+ `H+` magic, band 1 is an unallocated hole, band 2 is `0xCC`.

The `sprs` band table is **indexed by physical slot**, value `= virtual_band + 1`
(0 = unused) — this inverse-map layout was confirmed byte-identical to
`hdiutil convert … -format UDTO` on real 4 MiB/8 MiB images. So the two stored
slots are `slot0 → v0` (table entry `1`) and `slot1 → v2` (table entry `3`).

- **md5**: `ba6c599117d20fad9ad965c4cbd1a362`
- **Consumed by**: `core/tests/sparse_images.rs` (`synthetic_sparseimage_*`)
- **Builder** (verbatim):
  ```python
  import struct
  hdr = bytearray(4096)
  hdr[0:4] = b'sprs'
  struct.pack_into('>I', hdr, 0x04, 3)   # version
  struct.pack_into('>I', hdr, 0x08, 2)   # sectors_per_band -> band_size 1024
  struct.pack_into('>I', hdr, 0x10, 6)   # total_sectors -> 3 bands, 3072-byte disk
  struct.pack_into('>I', hdr, 0x40, 1)   # slot0 -> virtual band 0 (+1)
  struct.pack_into('>I', hdr, 0x44, 3)   # slot1 -> virtual band 2 (+1)
  slot0 = bytes([0x48,0x2b,0x00,0x04]) + b'\xAA'*1020
  slot1 = b'\xCC'*1024
  open('synthetic.sparseimage','wb').write(bytes(hdr)+slot0+slot1)
  ```

### `synthetic.sparsebundle/`  (SYNTHETIC)

Minimal hand-built `.sparsebundle` directory: `Info.plist` (band-size 1024,
size 3072, `diskimage-bundle-type = com.apple.diskimage.sparsebundle`) plus a
`bands/` dir. Band files are named by lowercase-hex virtual band index:
`bands/0` (present, `H+` magic), band 1 **absent** (a hole → zeros), `bands/2`
(present but 512 bytes, so its 512-byte tail reads as zeros).

- **md5**: `Info.plist 0cfa542f39f545e2c8143a35d0d3eb8e`, `bands/0 15759725b11ff649a05109de124fd4be`, `bands/2 1ecbf5127f93699e74276538a785ce1f`
- **Consumed by**: `core/tests/sparse_images.rs` (`synthetic_sparsebundle_*`)
- **Builder** (verbatim):
  ```python
  import os
  os.makedirs('synthetic.sparsebundle/bands', exist_ok=True)
  plist = ('<?xml version="1.0" encoding="UTF-8"?>\n'
   '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
   '<plist version="1.0">\n<dict>\n'
   '\t<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>\n'
   '\t<key>band-size</key><integer>1024</integer>\n'
   '\t<key>bundle-backingstore-version</key><integer>1</integer>\n'
   '\t<key>diskimage-bundle-type</key><string>com.apple.diskimage.sparsebundle</string>\n'
   '\t<key>size</key><integer>3072</integer>\n'
   '</dict>\n</plist>\n')
  open('synthetic.sparsebundle/Info.plist','w').write(plist)
  open('synthetic.sparsebundle/bands/0','wb').write(bytes([0x48,0x2b,0x00,0x04]) + b'\xAA'*1020)
  # band 1 intentionally absent (hole)
  open('synthetic.sparsebundle/bands/2','wb').write(b'\xCC'*512)
  ```

The env-gated `hdiutil_*_matches_flat_oracle` tests additionally mint **real**
sparse images (`hdiutil create -type SPARSE|SPARSEBUNDLE`), flatten them with
`hdiutil convert … -format UDTO`, and assert a full-image SHA-256 match — **tier-2**
validation: the image is self-minted (we chose the scenario) and the oracle
(`hdiutil convert`) shares hdiutil's codebase with the minter, so it cross-checks
our reader against hdiutil but cannot vouch for the real-world quirks a captured
image might carry. Those artifacts live in `/tmp` and are never committed.

## Regenerating

```bash
hdiutil create -size 4m -fs HFS+ -volname TestVol /tmp/raw
hdiutil convert /tmp/raw.dmg -format UDRO -o hfsplus_udro.dmg
hdiutil convert /tmp/raw.dmg -format UDZO -o hfsplus_compressed.dmg
```
