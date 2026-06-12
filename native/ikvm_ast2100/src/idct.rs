// AAN fast IDCT, ported verbatim from ast2100.js IDCT_transform.
// Integer arithmetic with MULTIPLY = (v*c) >> 8, row descale >> 3.

const FIX_1_082392200: i32 = 277;
const FIX_1_414213562: i32 = 362;
const FIX_1_847759065: i32 = 473;
const FIX_2_613125930: i32 = 669;

#[inline(always)]
fn multiply(v: i32, c: i32) -> i32 {
    (v * c) >> 8
}

// Build the range-limit table (mRlimitTable) as described in the spec.
// Indexed from 0..=1535+:
//   [0..256)         -> 0
//   [256..512)       -> identity (0..255)
//   [512..896)       -> 255  (saturate high, 384 entries)
//   [896..1280)      -> 0    (zeros, 384 entries)
//   [1280..1408)     -> identity (0..127)
pub fn build_range_limit_table() -> Vec<u16> {
    // mRlimitTable_index = 256, total size = 256 + 256 + 384 + 384 + 128 = 1408
    let size = 1408usize;
    let mut tbl = vec![0u16; size];
    // [0..256] = 0 (already zero)
    // [256..512) = identity 0..255
    for j in 0usize..256 {
        tbl[256 + j] = j as u16;
    }
    // [512..896) = 255
    for j in 256usize..640 {
        tbl[256 + j] = 255;
    }
    // [896..1280) = 0 (already zero)
    // [1280..1408) = 0..127
    for j in 0usize..128 {
        tbl[256 + 640 + 384 + j] = j as u16;
    }
    tbl
}

// IDCT transform for one 8x8 block.
// Input: dct_coeff[idx..idx+64] (dequantized coefficients, i32)
//        quant[0..64] (pre-scaled quant table, i64)
// Output: tile_yuv[idx..idx+64] (u8 level-shifted and clamped via range-limit table)
pub fn idct_transform(
    dct_coeff: &[i32],
    idx: usize,
    quant: &[i64; 64],
    tile_yuv: &mut [u8],
    out_idx: usize,
    rlimit: &[u16],
) {
    let mut ws = [0i32; 64];

    // Column pass: dequantize and butterfly into ws
    for ctr in 0usize..8 {
        // Check if all 7 non-DC column values are zero (DC-only fast path)
        let dc_only = dct_coeff[idx + ctr + 8] == 0
            && dct_coeff[idx + ctr + 16] == 0
            && dct_coeff[idx + ctr + 24] == 0
            && dct_coeff[idx + ctr + 32] == 0
            && dct_coeff[idx + ctr + 40] == 0
            && dct_coeff[idx + ctr + 48] == 0
            && dct_coeff[idx + ctr + 56] == 0;

        if dc_only {
            let dcval = ((dct_coeff[idx + ctr] as i64 * quant[ctr]) >> 16) as i32;
            for r in 0usize..8 {
                ws[ctr + r * 8] = dcval;
            }
            continue;
        }

        let t0 = ((dct_coeff[idx + ctr] as i64 * quant[ctr]) >> 16) as i32;
        let t1 = ((dct_coeff[idx + ctr + 16] as i64 * quant[ctr + 16]) >> 16) as i32;
        let t2 = ((dct_coeff[idx + ctr + 32] as i64 * quant[ctr + 32]) >> 16) as i32;
        let t3 = ((dct_coeff[idx + ctr + 48] as i64 * quant[ctr + 48]) >> 16) as i32;

        let t10 = t0 + t2;
        let t11 = t0 - t2;
        let t13 = t1 + t3;
        let t12 = multiply(t1 - t3, FIX_1_414213562) - t13;

        let a0 = t10 + t13;
        let a3 = t10 - t13;
        let a1 = t11 + t12;
        let a2 = t11 - t12;

        let t4 = ((dct_coeff[idx + ctr + 8] as i64 * quant[ctr + 8]) >> 16) as i32;
        let t5 = ((dct_coeff[idx + ctr + 24] as i64 * quant[ctr + 24]) >> 16) as i32;
        let t6 = ((dct_coeff[idx + ctr + 40] as i64 * quant[ctr + 40]) >> 16) as i32;
        let t7 = ((dct_coeff[idx + ctr + 56] as i64 * quant[ctr + 56]) >> 16) as i32;

        let z13 = t6 + t5;
        let z10 = t6 - t5;
        let z11 = t4 + t7;
        let z12 = t4 - t7;

        let b7 = z11 + z13;
        let t11b = multiply(z11 - z13, FIX_1_414213562);
        let z5 = multiply(z10 + z12, FIX_1_847759065);
        let b10 = multiply(z12, FIX_1_082392200) - z5;
        let b12 = multiply(z10, -FIX_2_613125930) + z5;

        let b6 = b12 - b7;
        let b5 = t11b - b6;
        let b4 = b10 + b5;

        ws[ctr + 0] = a0 + b7;
        ws[ctr + 56] = a0 - b7;
        ws[ctr + 8] = a1 + b6;
        ws[ctr + 48] = a1 - b6;
        ws[ctr + 16] = a2 + b5;
        ws[ctr + 40] = a2 - b5;
        ws[ctr + 32] = a3 + b4;
        ws[ctr + 24] = a3 - b4;
    }

    // Row pass: butterfly, descale >>3, level-shift+clamp via rlimit[384 + (x & 1023)]
    for ctr in 0usize..8 {
        let o = ctr * 8;

        let t10 = ws[o] + ws[o + 4];
        let t11 = ws[o] - ws[o + 4];
        let t13 = ws[o + 2] + ws[o + 6];
        let t12 = multiply(ws[o + 2] - ws[o + 6], FIX_1_414213562) - t13;

        let a0 = t10 + t13;
        let a3 = t10 - t13;
        let a1 = t11 + t12;
        let a2 = t11 - t12;

        let z13 = ws[o + 5] + ws[o + 3];
        let z10 = ws[o + 5] - ws[o + 3];
        let z11 = ws[o + 1] + ws[o + 7];
        let z12 = ws[o + 1] - ws[o + 7];

        let b7 = z11 + z13;
        let t11b = multiply(z11 - z13, FIX_1_414213562);
        let z5 = multiply(z10 + z12, FIX_1_847759065);
        let b10 = multiply(z12, FIX_1_082392200) - z5;
        let b12 = multiply(z10, -FIX_2_613125930) + z5;

        let b6 = b12 - b7;
        let b5 = t11b - b6;
        let b4 = b10 + b5;

        let rlim = |v: i32| -> u8 {
            let idx = 384usize + ((v >> 3) as usize & 1023);
            rlimit[idx] as u8
        };

        tile_yuv[out_idx + o + 0] = rlim(a0 + b7);
        tile_yuv[out_idx + o + 7] = rlim(a0 - b7);
        tile_yuv[out_idx + o + 1] = rlim(a1 + b6);
        tile_yuv[out_idx + o + 6] = rlim(a1 - b6);
        tile_yuv[out_idx + o + 2] = rlim(a2 + b5);
        tile_yuv[out_idx + o + 5] = rlim(a2 - b5);
        tile_yuv[out_idx + o + 4] = rlim(a3 + b4);
        tile_yuv[out_idx + o + 3] = rlim(a3 - b4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quant::build_quant_table;
    use crate::tables::TBL_057Y;

    #[test]
    fn test_idct_dc_only_block() {
        // A block with only DC = 128 (after dequant) should produce a flat output of 128+128=256->255?
        // Actually: after IDCT of DC-only block with DC coeff = N,
        // the column pass: dcval = (coeff * quant_dc) >> 16
        // After column pass all 8 rows get dcval; row pass: a0 = dcval*8 (times accumulation), descale>>3 -> dcval
        // Level shift adds 128 -> dcval + 128; if dcval=0 -> 128 in output
        let rlimit = build_range_limit_table();
        let quant = build_quant_table(&TBL_057Y, 16);

        let mut dct_coeff = vec![0i32; 64];
        // Set DC = value such that after dequant we get 0 -> output = 128
        // dcval = (coeff * quant[0]) >> 16
        // To get dcval = 0: coeff = 0
        dct_coeff[0] = 0;

        let mut tile_yuv = vec![0u8; 64];
        idct_transform(&dct_coeff, 0, &quant, &mut tile_yuv, 0, &rlimit);

        // All outputs should be 128 (level shift of 0)
        for &v in &tile_yuv {
            assert_eq!(v, 128, "DC-only block with coeff=0 should yield 128 everywhere");
        }
    }

    #[test]
    fn test_range_limit_table_structure() {
        let rlimit = build_range_limit_table();
        // Identity region at [256..512): tbl[256+j] = j for j in 0..256
        assert_eq!(rlimit[256], 0);
        assert_eq!(rlimit[511], 255);
        // Saturate at 255 for [512..896)
        assert_eq!(rlimit[512], 255);
        assert_eq!(rlimit[895], 255);
        // Zero region [896..1280)
        assert_eq!(rlimit[896], 0);
        // IDCT uses index 384 + (x & 1023); for x=0 -> tbl[384] = 384-256=128 in identity -> 128
        assert_eq!(rlimit[384], 128);
    }
}
