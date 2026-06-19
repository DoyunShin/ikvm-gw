// Huffman table construction and decode, ported verbatim from ast2100.js.

use crate::tables::{
    STD_DC_LUMINANCE_NRCODES, STD_DC_LUMINANCE_VALUES,
    STD_DC_CHROMINANCE_NRCODES, STD_DC_CHROMINANCE_VALUES,
    STD_AC_LUMINANCE_NRCODES, STD_AC_LUMINANCE_VALUES,
    STD_AC_CHROMINANCE_NRCODES, STD_AC_CHROMINANCE_VALUES,
    DC_LUMINANCE_HUFFMANCODE, DC_CHROMINANCE_HUFFMANCODE,
    AC_LUMINANCE_HUFFMANCODE, AC_CHROMINANCE_HUFFMANCODE,
};

// A single Huffman table, mirroring the JS HT object.
pub struct HuffTable {
    // table_len: 65536-entry lookup, keyed by top 16 bits of codebuf.
    // Value = number of bits for that code.
    pub table_len: Vec<u8>,
    // V: keyed by `len + (offset << 8)` where offset = hcode - minor_code[len]
    pub v: Vec<u8>,
    // minor_code[k] = first code of length k
    pub minor_code: [u16; 17],
}

impl HuffTable {
    fn new() -> Self {
        HuffTable {
            table_len: vec![0u8; 65536],
            v: vec![0u8; 65536],
            minor_code: [0u16; 17],
        }
    }
}

// WORD_hi_lo(hi, lo) = hi + (lo << 8)
#[inline(always)]
fn word_hi_lo(hi: usize, lo: usize) -> usize {
    hi + (lo << 8)
}

fn load_huffman_table(nrcodes: &[u32; 17], values: &[u8], huff_code: &[u32]) -> HuffTable {
    let mut ht = HuffTable::new();

    // table_length[k] = nrcodes[k]
    let mut table_length = [0u32; 17];
    for j in 1..=16 {
        table_length[j] = nrcodes[j];
    }

    // Populate V array: V[WORD_hi_lo(k, j)] = values[i]
    let mut i = 0usize;
    for k in 1usize..=16 {
        for j in 0..table_length[k] as usize {
            let idx = word_hi_lo(k, j);
            if idx < ht.v.len() {
                ht.v[idx] = values[i];
            }
            i += 1;
        }
    }

    // Build minor_code and major_code (we only need minor_code for decode)
    let mut code = 0u32;
    for k in 1usize..=16 {
        ht.minor_code[k] = (code & 0xFFFF) as u16;
        for _ in 0..table_length[k] {
            code += 1;
        }
        // major_code not needed
        code *= 2;
        if table_length[k] == 0 {
            ht.minor_code[k] = 0xFFFF;
        }
    }

    // Build fast table_len[] from the precomputed HUFFMANCODE pairs.
    // Format: (threshold, codelength) pairs.
    // table_len[code_index] = codelength such that code_index < next_threshold.
    let pairs = huff_code;
    ht.table_len[0] = 2;
    let mut pi = 2usize; // start at second pair
    for code_index in 1usize..65535 {
        if (code_index as u32) < pairs[pi] {
            ht.table_len[code_index] = (pairs[pi + 1] & 0xFF) as u8;
        } else {
            pi += 2;
            if pi + 1 < pairs.len() {
                ht.table_len[code_index] = (pairs[pi + 1] & 0xFF) as u8;
            }
        }
    }

    ht
}

// Container for the four Huffman tables used by the decoder.
pub struct HuffmanTables {
    pub dc_luma: HuffTable,
    pub ac_luma: HuffTable,
    pub dc_chroma: HuffTable,
    pub ac_chroma: HuffTable,
}

impl HuffmanTables {
    pub fn build() -> Self {
        HuffmanTables {
            dc_luma: load_huffman_table(
                &STD_DC_LUMINANCE_NRCODES,
                &STD_DC_LUMINANCE_VALUES,
                &DC_LUMINANCE_HUFFMANCODE,
            ),
            ac_luma: load_huffman_table(
                &STD_AC_LUMINANCE_NRCODES,
                &STD_AC_LUMINANCE_VALUES,
                &AC_LUMINANCE_HUFFMANCODE,
            ),
            dc_chroma: load_huffman_table(
                &STD_DC_CHROMINANCE_NRCODES,
                &STD_DC_CHROMINANCE_VALUES,
                &DC_CHROMINANCE_HUFFMANCODE,
            ),
            ac_chroma: load_huffman_table(
                &STD_AC_CHROMINANCE_NRCODES,
                &STD_AC_CHROMINANCE_VALUES,
                &AC_CHROMINANCE_HUFFMANCODE,
            ),
        }
    }
}

// Decode one 8x8 block of DCT coefficients into dct_coeff[pos..pos+63].
// Returns the updated DC predictor.
// Mirrors process_Huffman_data_unit in ast2100.js.
pub fn decode_block(
    br: &mut crate::bitreader::BitReader,
    dc_ht: &HuffTable,
    ac_ht: &HuffTable,
    prev_dc: i32,
    dct_coeff: &mut [i32],
    pos: usize,
) -> i32 {
    use crate::tables::DEZIGZAG;

    // DC coefficient
    let k = dc_ht.table_len[br.peek16() as usize] as u32;
    let hcode = br.peek_n(k) as u16;
    br.consume_bits(k);
    let size_val = dc_ht.v[word_hi_lo(k as usize, (hcode.wrapping_sub(dc_ht.minor_code[k as usize])) as usize)];
    let dc = if size_val == 0 {
        prev_dc
    } else {
        prev_dc + br.get_kbits(size_val as u32)
    };
    dct_coeff[pos] = dc;

    // AC coefficients
    let mut nr = 1usize;
    loop {
        let k = ac_ht.table_len[(br.codebuf() >> 16) as u16 as usize] as u32;
        let hcode = br.peek_n(k) as u16;
        br.consume_bits(k);
        let byte_temp = ac_ht.v[word_hi_lo(
            k as usize,
            ((hcode.wrapping_sub(ac_ht.minor_code[k as usize])) as u8) as usize,
        )];
        let size_val = (byte_temp & 0x0F) as u32;
        let count_0 = (byte_temp >> 4) as usize;

        if size_val == 0 {
            if count_0 != 15 {
                // EOB
                break;
            }
            // ZRL: skip 16 zeros
            nr += 16;
        } else {
            nr += count_0;
            if nr < 64 {
                let coeff_idx = pos + DEZIGZAG[nr];
                dct_coeff[coeff_idx] = br.get_kbits(size_val);
            }
            nr += 1;
        }

        if nr >= 64 {
            break;
        }
    }

    dc
}

#[cfg(all(test, feature = "integration"))]
mod debug_tests {
    use super::*;
    use crate::bitreader::BitReader;
    use std::fs;

    #[test]
    fn test_first_block_dc_decode() {
        let raw = fs::read("/home/elice/ikvm-gateway/.claude/worktrees/m0-spike/captures/frame_rect0.bin").unwrap();
        let codec_data = &raw[8..];
        let tables = HuffmanTables::build();
        let mut br = BitReader::new(codec_data, 4);
        // Consume 4 flag bits
        br.consume_bits(4);
        // Decode first DC luma coefficient
        let mut dct_coeff = vec![0i32; 384];
        let dc = decode_block(&mut br, &tables.dc_luma, &tables.ac_luma, 0, &mut dct_coeff, 0);
        assert_eq!(dc, -99, "first DC Y should be -99, got {}", dc);
        assert_eq!(dct_coeff[0], -99, "dct_coeff[0] should be -99");
        // After block decode, peek at next bits for next block
        let next_flag = (br.codebuf() >> 28) & 0xF;
        println!("After block 0: DC={}, next_flag={}, codebuf=0x{:08x}", dc, next_flag, br.codebuf());
    }
}
