// Quantization table building, matching ast2100.js load_quant_table exactly.
// Net effect: quant[r*8+c] = clamp(base[r*8+c], 1, 255) * scalefactor[r] * scalefactor[c] * 65536

use crate::tables::{ZIGZAG, SCALE_FACTOR};

// Build a pre-scaled quantization table (64 entries, i64) from a base table.
// scale_factor = 16 (default) -> base * 16/16 = base (no scaling).
// The result is pre-multiplied by AAN scalefactor[r]*scalefactor[c]*65536 for use in IDCT.
pub fn build_quant_table(base_table: &[i32; 64], scale_factor: i32) -> Box<[i64; 64]> {
    // Step 1: set_quant_table -> temp_qt[zigzag[i]] = clamp(base[i]*16/scale_factor, 1, 255)
    let mut temp_qt = [0i32; 64];
    for i in 0usize..64 {
        let mut v = base_table[i] * 16 / scale_factor;
        if v <= 0 { v = 1; }
        if v > 255 { v = 255; }
        temp_qt[ZIGZAG[i]] = v;
    }

    // Step 2: load_quant_table -> quant[j] = temp_qt[zigzag[j]] (double-zigzag cancels -> natural order)
    let mut quant_table = [0i32; 64];
    for j in 0usize..64 {
        quant_table[j] = temp_qt[ZIGZAG[j]];
    }

    // Step 3: pre-scale for AAN IDCT: quant[r*8+c] *= scalefactor[r] * scalefactor[c] * 65536
    let mut result = Box::new([0i64; 64]);
    let mut j = 0usize;
    for row in 0usize..8 {
        for col in 0usize..8 {
            result[j] = (quant_table[j] as f64 * SCALE_FACTOR[row] * SCALE_FACTOR[col] * 65536.0) as i64;
            j += 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::TBL_057Y;

    #[test]
    fn test_quant_table_dc_entry() {
        // For TBL_057Y, base[0] = 9, scale_factor=16 -> clamp(9*16/16,1,255)=9
        // Pre-scaled: 9 * scalefactor[0] * scalefactor[0] * 65536 = 9 * 1.0 * 1.0 * 65536 = 589824
        let qt = build_quant_table(&TBL_057Y, 16);
        assert_eq!(qt[0], 9 * 65536);
    }

    #[test]
    fn test_quant_table_nonzero() {
        let qt = build_quant_table(&TBL_057Y, 16);
        for &v in qt.iter() {
            assert!(v > 0, "all quant entries must be positive");
        }
    }
}
