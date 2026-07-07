//! Integration tests for the Apple sparse-image readers.
//!
//! Two tiers:
//!  * **Committed synthetic fixtures** (`synthetic.sparseimage`,
//!    `synthetic.sparsebundle/`) — small, deterministic, run on every CI. They
//!    specify the parse/read behaviour; provenance is in `tests/data/README.md`.
//!  * **Real `hdiutil` oracle** (tier-1/2, env-gated) — mints real sparse images
//!    with Apple's `hdiutil`, builds a flat raw oracle with
//!    `hdiutil convert … -format UDTO`, and asserts the reader materialises a
//!    byte-identical image (full SHA-256 match). Skips cleanly when `hdiutil`
//!    is unavailable (Linux/CI), exactly like an oracle-binary gate.

use dmg::{SparseBundleReader, SparseImageReader};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

const HFS_MAGIC: [u8; 4] = [0x48, 0x2b, 0x00, 0x04]; // 'H+' volume header signature

fn data(name: &str) -> PathBuf {
    Path::new(DATA_DIR).join(name)
}

// ── Committed synthetic .sparseimage ───────────────────────────────────────

fn open_image() -> SparseImageReader<BufReader<File>> {
    let f = File::open(data("synthetic.sparseimage")).expect("open synthetic.sparseimage");
    SparseImageReader::open(BufReader::new(f)).expect("parse synthetic.sparseimage")
}

#[test]
fn synthetic_sparseimage_virtual_disk_size() {
    assert_eq!(open_image().virtual_disk_size(), 3072);
}

#[test]
fn synthetic_sparseimage_first_band_has_hfs_magic() {
    let mut r = open_image();
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).unwrap();
    assert_eq!(buf, HFS_MAGIC);
}

#[test]
fn synthetic_sparseimage_hole_band_is_zeros() {
    let mut r = open_image();
    r.seek(SeekFrom::Start(1024)).unwrap(); // virtual band 1 = hole
    let mut buf = [0xFFu8; 1024];
    r.read_exact(&mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn synthetic_sparseimage_second_band_content() {
    let mut r = open_image();
    r.seek(SeekFrom::Start(2048)).unwrap(); // virtual band 2 → phys 2 (0xCC)
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [0xCC; 4]);
}

// ── Committed synthetic .sparsebundle ──────────────────────────────────────

fn open_bundle() -> SparseBundleReader {
    SparseBundleReader::open(&data("synthetic.sparsebundle")).expect("parse synthetic.sparsebundle")
}

#[test]
fn synthetic_sparsebundle_virtual_disk_size() {
    assert_eq!(open_bundle().virtual_disk_size(), 3072);
}

#[test]
fn synthetic_sparsebundle_first_band_has_hfs_magic() {
    let mut r = open_bundle();
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).unwrap();
    assert_eq!(buf, HFS_MAGIC);
}

#[test]
fn synthetic_sparsebundle_missing_band_is_zeros() {
    let mut r = open_bundle();
    r.seek(SeekFrom::Start(1024)).unwrap(); // band 1 file absent = hole
    let mut buf = [0xFFu8; 1024];
    r.read_exact(&mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn synthetic_sparsebundle_partial_band_tail_is_zeros() {
    let mut r = open_bundle();
    r.seek(SeekFrom::Start(2048)).unwrap(); // band 2 = 512 bytes 0xCC + 512 zeros
    let mut buf = [0u8; 1024];
    r.read_exact(&mut buf).unwrap();
    assert!(buf[..512].iter().all(|&b| b == 0xCC));
    assert!(buf[512..].iter().all(|&b| b == 0));
}

// ── Real hdiutil oracle (tier-1/2, env-gated) ──────────────────────────────

fn hdiutil_ok() -> bool {
    Command::new("hdiutil")
        .arg("help")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn run(cmd: &mut Command) -> bool {
    cmd.output().is_ok_and(|o| o.status.success())
}

fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("read oracle");
    sha256(&bytes)
}

/// Minimal SHA-256 (test-only; avoids adding a crypto dependency to the crate).
#[allow(clippy::too_many_lines)]
fn sha256(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, wi) in w.iter_mut().enumerate().take(16) {
            let o = i * 4;
            *wi = u32::from_be_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for (hi, vi) in h.iter_mut().zip(v.iter()) {
            *hi = hi.wrapping_add(*vi);
        }
    }
    h.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:08x}");
        s
    })
}

fn read_all<R: Read + Seek>(reader: &mut R, size: u64) -> Vec<u8> {
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut out = Vec::with_capacity(size as usize);
    let mut buf = vec![0u8; 64 * 1024];
    let mut remaining = size;
    while remaining > 0 {
        let n = reader.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        let take = (n as u64).min(remaining) as usize;
        out.extend_from_slice(&buf[..take]);
        remaining -= take as u64;
    }
    out
}

/// Locate the HFS+ volume-header magic in the flat oracle, so both readers can
/// be checked at the *same* virtual offset the real disk carries it.
fn find_hfs_magic(flat: &[u8]) -> Option<usize> {
    flat.windows(4).position(|w| w == HFS_MAGIC)
}

#[test]
fn hdiutil_sparseimage_matches_flat_oracle() {
    if !hdiutil_ok() {
        eprintln!("skip: hdiutil unavailable");
        return;
    }
    let tmp = std::env::temp_dir().join("dmg_sparse_oracle_img");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let img = tmp.join("sp"); // hdiutil appends .sparseimage
    let sparse = tmp.join("sp.sparseimage");
    let oracle = tmp.join("flat"); // hdiutil appends .cdr

    assert!(run(Command::new("hdiutil").args([
        "create",
        "-type",
        "SPARSE",
        "-size",
        "8m",
        "-fs",
        "HFS+",
        "-volname",
        "SP",
        img.to_str().unwrap(),
    ])));
    assert!(run(Command::new("hdiutil").args([
        "convert",
        sparse.to_str().unwrap(),
        "-format",
        "UDTO",
        "-o",
        oracle.to_str().unwrap(),
    ])));
    let cdr = tmp.join("flat.cdr");

    let f = File::open(&sparse).unwrap();
    let mut reader = SparseImageReader::open(BufReader::new(f)).unwrap();
    let flat = std::fs::read(&cdr).unwrap();

    assert_eq!(
        reader.virtual_disk_size(),
        flat.len() as u64,
        "virtual_disk_size must equal flat oracle length"
    );
    let vsize = reader.virtual_disk_size();
    let ours = read_all(&mut reader, vsize);
    assert_eq!(
        sha256(&ours),
        sha256_file(&cdr),
        "full-image SHA-256 must match the hdiutil raw oracle"
    );
    let magic_off = find_hfs_magic(&flat).expect("HFS+ magic in oracle");
    assert_eq!(&ours[magic_off..magic_off + 4], &HFS_MAGIC);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn hdiutil_sparsebundle_matches_flat_oracle() {
    if !hdiutil_ok() {
        eprintln!("skip: hdiutil unavailable");
        return;
    }
    let tmp = std::env::temp_dir().join("dmg_sparse_oracle_bundle");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let img = tmp.join("sb"); // hdiutil appends .sparsebundle
    let bundle = tmp.join("sb.sparsebundle");
    let oracle = tmp.join("flat");

    assert!(run(Command::new("hdiutil").args([
        "create",
        "-type",
        "SPARSEBUNDLE",
        "-size",
        "8m",
        "-fs",
        "HFS+",
        "-volname",
        "SB",
        img.to_str().unwrap(),
    ])));
    assert!(run(Command::new("hdiutil").args([
        "convert",
        bundle.to_str().unwrap(),
        "-format",
        "UDTO",
        "-o",
        oracle.to_str().unwrap(),
    ])));
    let cdr = tmp.join("flat.cdr");

    let mut reader = SparseBundleReader::open(&bundle).unwrap();
    let flat = std::fs::read(&cdr).unwrap();

    assert_eq!(reader.virtual_disk_size(), flat.len() as u64);
    let vsize = reader.virtual_disk_size();
    let ours = read_all(&mut reader, vsize);
    assert_eq!(
        sha256(&ours),
        sha256_file(&cdr),
        "full-image SHA-256 must match the hdiutil raw oracle"
    );
    let magic_off = find_hfs_magic(&flat).expect("HFS+ magic in oracle");
    assert_eq!(&ours[magic_off..magic_off + 4], &HFS_MAGIC);
    let _ = std::fs::remove_dir_all(&tmp);
}
