//! Pure-Rust detools **sequential** patch encoder (no Python, no detools at runtime).
//!
//! Produces a byte stream the on-device detools **C decoder** applies to the running image to reconstruct
//! the target — the ESP32 A/B delta path (`codec_id = detools-sequential`). The nRF52 in-place path still
//! goes through the detools shim (see [`crate::delta`]); porting it is future work.
//!
//! ## Correctness contract
//! A patch is correct iff the real detools decoder rebuilds the target **byte-for-byte** — NOT iff our
//! bytes equal detools'. We therefore implement the *canonical* bsdiff algorithm (Colin Percival's, which
//! detools' C mirrors): it is correct by construction — the control triples carry the exact `to - from`
//! byte deltas and literal runs, so reconstruction is exact regardless of match quality. `tests/encode.rs`
//! pins this by decoding every produced patch with the real detools decoder and comparing hashes.
//!
//! ## Wire format (matches `apply_patch_sequential` in detools 0.53.0)
//! ```text
//! header(1) = (PATCH_TYPE_SEQUENTIAL<<4) | COMPRESSION_CRLE
//! size(to_len)                                  ; signed varint, UNCOMPRESSED
//! crle( size(0)                                 ; data-format = none
//!       repeat: size(diff_len) diff[diff_len]   ; to = from + diff (mod 256), from advances diff_len
//!               size(extra_len) extra[extra_len]; literal to-bytes, from unchanged
//!               size(seek) )                    ; signed; from cursor += seek
//! ```
//!
//! Pure and stateless — no shared mutable state, so it is inherently free of data races.

const PATCH_TYPE_SEQUENTIAL: u8 = 0;
const COMPRESSION_CRLE: u8 = 2;
const CRLE_SCATTERED: u8 = 0;
const CRLE_REPEATED: u8 = 1;
const CRLE_MIN_REPEAT: usize = 6;

/// Encode a detools `sequential` + `crle` patch that turns `from` into `to`.
pub fn encode_sequential(from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut patch = Vec::new();
    patch.push((PATCH_TYPE_SEQUENTIAL << 4) | COMPRESSION_CRLE);
    patch.extend(pack_size(to.len() as i64)); // to_size, uncompressed

    // The compressed body: data-format marker (none = 0) followed by the bsdiff control/diff/extra stream.
    let mut body = pack_size(0);
    if !to.is_empty() {
        bsdiff(from, to, &mut body);
    }
    patch.extend(crle_compress(&body));
    patch
}

// ---- bsdiff (canonical) --------------------------------------------------------------------------

/// Append the bsdiff control/diff/extra stream for `from -> to` to `body`.
fn bsdiff(from: &[u8], to: &[u8], body: &mut Vec<u8>) {
    let oldsize = from.len() as i64;
    let newsize = to.len() as i64;
    let sa = suffix_array_with_sentinel(from); // I[0..=oldsize], I[0] = oldsize (empty suffix)

    let get = |v: &[u8], i: i64| -> u8 { v[i as usize] };

    let mut scan: i64 = 0;
    let mut len: i64 = 0;
    let mut pos: i64 = 0;
    let mut lastscan: i64 = 0;
    let mut lastpos: i64 = 0;
    let mut lastoffset: i64 = 0;

    while scan < newsize {
        let mut oldscore: i64 = 0;
        scan += len;
        let mut scsc = scan;
        while scan < newsize {
            let (l, p) = search(&sa, from, &to[scan as usize..], 0, oldsize);
            len = l;
            pos = p;
            while scsc < scan + len {
                if scsc + lastoffset < oldsize && get(from, scsc + lastoffset) == get(to, scsc) {
                    oldscore += 1;
                }
                scsc += 1;
            }
            if (len == oldscore && len != 0) || len > oldscore + 8 {
                break;
            }
            if scan + lastoffset < oldsize && get(from, scan + lastoffset) == get(to, scan) {
                oldscore -= 1;
            }
            scan += 1;
        }

        if len != oldscore || scan == newsize {
            // Forward extend: how far the match at (lastscan, lastpos) is worth keeping as "diff".
            let mut s = 0i64;
            let mut sf = 0i64;
            let mut lenf = 0i64;
            {
                let mut i = 0i64;
                while lastscan + i < scan && lastpos + i < oldsize {
                    if get(from, lastpos + i) == get(to, lastscan + i) {
                        s += 1;
                    }
                    i += 1;
                    if s * 2 - i > sf * 2 - lenf {
                        sf = s;
                        lenf = i;
                    }
                }
            }
            // Backward extend from the next match at (scan, pos).
            let mut lenb = 0i64;
            if scan < newsize {
                let mut s = 0i64;
                let mut sb = 0i64;
                let mut i = 1i64;
                while scan >= lastscan + i && pos >= i {
                    if get(from, pos - i) == get(to, scan - i) {
                        s += 1;
                    }
                    if s * 2 - i > sb * 2 - lenb {
                        sb = s;
                        lenb = i;
                    }
                    i += 1;
                }
            }
            // Resolve overlap between the forward and backward regions.
            if lastscan + lenf > scan - lenb {
                let overlap = (lastscan + lenf) - (scan - lenb);
                let mut s = 0i64;
                let mut ss = 0i64;
                let mut lens = 0i64;
                let mut i = 0i64;
                while i < overlap {
                    if get(to, lastscan + lenf - overlap + i)
                        == get(from, lastpos + lenf - overlap + i)
                    {
                        s += 1;
                    }
                    if get(to, scan - lenb + i) == get(from, pos - lenb + i) {
                        s -= 1;
                    }
                    if s > ss {
                        ss = s;
                        lens = i + 1;
                    }
                    i += 1;
                }
                lenf += lens - overlap;
                lenb -= lens;
            }

            // diff span: to[lastscan .. lastscan+lenf] - from[lastpos .. lastpos+lenf]
            let diff_len = lenf;
            let mut diff = Vec::with_capacity(diff_len as usize);
            for i in 0..diff_len {
                diff.push(get(to, lastscan + i).wrapping_sub(get(from, lastpos + i)));
            }
            // extra span: literal to-bytes between the two matched regions.
            let extra_len = (scan - lenb) - (lastscan + lenf);
            let extra = &to[(lastscan + lenf) as usize..(scan - lenb) as usize];
            // seek: reposition the from cursor to the next matched region.
            let seek = (pos - lenb) - (lastpos + lenf);

            body.extend(pack_size(diff_len));
            body.extend(&diff);
            body.extend(pack_size(extra_len));
            body.extend_from_slice(extra);
            body.extend(pack_size(seek));

            lastscan = scan - lenb;
            lastpos = pos - lenb;
            lastoffset = pos - scan;
        }
    }
}

/// Length of the common prefix of `a` and `b`.
fn matchlen(a: &[u8], b: &[u8]) -> i64 {
    let mut i = 0usize;
    let n = a.len().min(b.len());
    while i < n && a[i] == b[i] {
        i += 1;
    }
    i as i64
}

/// Longest prefix of `new` occurring in `from`, via binary search on the suffix array `sa`
/// (`sa[st..=en]`). Returns `(match_len, from_pos)`. Correctness of the patch does not depend on this
/// being the global maximum — a shorter match just yields a larger (still exact) patch.
fn search(sa: &[i64], from: &[u8], new: &[u8], st: i64, en: i64) -> (i64, i64) {
    if en - st < 2 {
        let x = matchlen(&from[sa[st as usize] as usize..], new);
        let y = matchlen(&from[sa[en as usize] as usize..], new);
        if x > y {
            (x, sa[st as usize])
        } else {
            (y, sa[en as usize])
        }
    } else {
        let x = st + (en - st) / 2;
        let oi = sa[x as usize] as usize;
        // memcmp(from+sa[x], new, min(len)) < 0  ->  go right, else go left.
        let n = (from.len() - oi).min(new.len());
        if from[oi..oi + n] < new[..n] {
            search(sa, from, new, x, en)
        } else {
            search(sa, from, new, st, x)
        }
    }
}

/// Suffix array of `s` with the empty suffix prepended at index 0 (so `I` has length `s.len()+1` and
/// `I[0] == s.len()`), matching the indexing bsdiff's `search` expects.
fn suffix_array_with_sentinel(s: &[u8]) -> Vec<i64> {
    let mut sa = suffix_array(s);
    let mut i = Vec::with_capacity(sa.len() + 1);
    i.push(s.len() as i64); // empty suffix sorts first
    i.append(&mut sa);
    i
}

/// Plain suffix array of `s` (positions `0..s.len()` sorted by suffix), prefix-doubling, O(n log^2 n).
fn suffix_array(s: &[u8]) -> Vec<i64> {
    let n = s.len();
    if n == 0 {
        return Vec::new();
    }
    let mut sa: Vec<usize> = (0..n).collect();
    let mut rank: Vec<i64> = s.iter().map(|&b| b as i64).collect();
    let mut tmp = vec![0i64; n];
    let key = |rank: &[i64], i: usize, k: usize| -> (i64, i64) {
        (rank[i], if i + k < rank.len() { rank[i + k] } else { -1 })
    };
    let mut k = 1;
    loop {
        sa.sort_by_key(|&a| key(&rank, a, k));
        tmp[sa[0]] = 0;
        for w in 1..n {
            let prev = key(&rank, sa[w - 1], k);
            let cur = key(&rank, sa[w], k);
            tmp[sa[w]] = tmp[sa[w - 1]] + if cur != prev { 1 } else { 0 };
        }
        rank.copy_from_slice(&tmp);
        if rank[sa[n - 1]] as usize == n - 1 {
            break; // all ranks distinct: fully sorted
        }
        k <<= 1;
        if k >= n {
            break;
        }
    }
    sa.into_iter().map(|x| x as i64).collect()
}

// ---- varints -------------------------------------------------------------------------------------

/// detools' signed size varint (patch structure): first byte = sign(0x40) | low-6 | cont(0x80),
/// then 7 bits per continuation byte. Inverse of `unpack_size` in detools `common.py`.
fn pack_size(value: i64) -> Vec<u8> {
    let (sign, mut v) = if value < 0 {
        (0x40u8, -value)
    } else {
        (0u8, value)
    };
    let mut out = Vec::new();
    let mut byte = sign | (v as u8 & 0x3f);
    v >>= 6;
    while v > 0 {
        out.push(byte | 0x80);
        byte = v as u8 & 0x7f;
        v >>= 7;
    }
    out.push(byte);
    out
}

/// crle's own unsigned 7-bit varint (segment lengths). Inverse of `unpack_size` in `compression/crle.py`.
fn crle_pack_size(mut value: u64) -> Vec<u8> {
    let mut out = vec![0x80 | (value as u8 & 0x7f)];
    value >>= 7;
    while value > 0 {
        out.push(0x80 | (value as u8 & 0x7f));
        value >>= 7;
    }
    let last = out.len() - 1;
    out[last] &= 0x7f;
    out
}

// ---- crle compression ----------------------------------------------------------------------------

/// Conditional RLE (detools `crle`): runs of >= 6 identical bytes become REPEATED segments, everything
/// else stays SCATTERED. Batch equivalent of detools' streaming compressor (segmentation depends only on
/// content, so the flushed output is identical). Public so tests can round-trip it through the real
/// detools decompressor in isolation.
pub fn crle_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if data.is_empty() {
        out.push(CRLE_SCATTERED);
        out.extend(crle_pack_size(0));
        return out;
    }
    let n = data.len();
    let mut i = 0;
    while i < n {
        match first_run(data, i) {
            None => {
                emit_scattered(&mut out, &data[i..]);
                i = n;
            }
            Some((j, _)) if j > i => {
                emit_scattered(&mut out, &data[i..j]);
                i = j;
            }
            Some((_, rlen)) => {
                out.push(CRLE_REPEATED);
                out.extend(crle_pack_size(rlen as u64));
                out.push(data[i]);
                i += rlen;
            }
        }
    }
    out
}

fn emit_scattered(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(CRLE_SCATTERED);
    out.extend(crle_pack_size(bytes.len() as u64));
    out.extend_from_slice(bytes);
}

/// The first byte offset `>= start` at which a run of `>= CRLE_MIN_REPEAT` identical bytes begins, and its
/// full length. `None` if there is no such run in `data[start..]`.
fn first_run(data: &[u8], start: usize) -> Option<(usize, usize)> {
    let n = data.len();
    let mut o = start;
    while o < n {
        let b = data[o];
        let mut l = 0;
        while o + l < n && data[o + l] == b {
            l += 1;
        }
        if l >= CRLE_MIN_REPEAT {
            return Some((o, l));
        }
        o += l;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_size_matches_examples() {
        assert_eq!(pack_size(0), vec![0x00]);
        assert_eq!(pack_size(1), vec![0x01]);
        assert_eq!(pack_size(-1), vec![0x41]); // sign bit
        assert_eq!(pack_size(0x3f), vec![0x3f]);
        assert_eq!(pack_size(0x40), vec![0x80, 0x01]); // needs a continuation byte
    }

    #[test]
    fn crle_pack_size_examples() {
        assert_eq!(crle_pack_size(0), vec![0x00]);
        assert_eq!(crle_pack_size(1), vec![0x01]);
        assert_eq!(crle_pack_size(0x7f), vec![0x7f]);
        assert_eq!(crle_pack_size(0x80), vec![0x80, 0x01]);
    }

    #[test]
    fn crle_runs_and_scatter() {
        // < 6 repeats stay scattered; >= 6 become one repeated segment.
        let out = crle_compress(&[1, 2, 3]);
        assert_eq!(out, vec![CRLE_SCATTERED, 3, 1, 2, 3]);
        let out = crle_compress(&[7u8; 6]);
        assert_eq!(out, vec![CRLE_REPEATED, 6, 7]);
    }
}
