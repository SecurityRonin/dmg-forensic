# tests/data — DMG Corpus

Real DMG images produced by macOS `hdiutil`, independent from the Rust parser,
satisfying the doer-checker principle.

## Files

| File | Size | Format | Tool / Command |
|------|------|--------|----------------|
| `hfsplus_udro.dmg` | 818 KB | UDIF/UDRO (raw blocks, GPT-wrapped HFS+) | `hdiutil convert -format UDRO` |
| `hfsplus_compressed.dmg` | 13 KB | UDIF/UDZO (zlib-compressed, same disk) | `hdiutil convert -format UDZO` |

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

## Regenerating

```bash
hdiutil create -size 4m -fs HFS+ -volname TestVol /tmp/raw
hdiutil convert /tmp/raw.dmg -format UDRO -o hfsplus_udro.dmg
hdiutil convert /tmp/raw.dmg -format UDZO -o hfsplus_compressed.dmg
```
