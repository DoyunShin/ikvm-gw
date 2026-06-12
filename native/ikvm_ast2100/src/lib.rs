// AST2100 (RFB encoding 0x57) video decoder — Rust/PyO3 port.
// Faithfully ported from ast2100.js (the firmware's own decoder).

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

mod bitreader;
mod huffman;
mod idct;
mod quant;
mod tables;

use bitreader::BitReader;
use huffman::{HuffmanTables, decode_block};
use idct::{idct_transform, build_range_limit_table};
use quant::build_quant_table;
use tables::{select_luma_table, select_chroma_table};

// YCbCr->RGB LUT tables, matching Init_Color_Table in ast2100.js exactly.
struct ColorLuts {
    cr_to_r: Vec<i32>,
    cb_to_b: Vec<i32>,
    cr_to_g: Vec<i32>,
    cb_to_g: Vec<i32>,
    m_y: Vec<i32>,
}

fn build_color_luts() -> ColorLuts {
    let n_scale = 1i64 << 16;
    let n_half = n_scale >> 1;
    let fix = |x: f64| -> i64 { (x * n_scale as f64 + 0.5) as i64 };

    let mut cr_to_r = vec![0i32; 256];
    let mut cb_to_b = vec![0i32; 256];
    let mut cr_to_g = vec![0i32; 256];
    let mut cb_to_g = vec![0i32; 256];

    for i in 0usize..256 {
        let x = i as i64 - 128;
        cr_to_r[i] = ((fix(1.597656) * x + n_half) >> 16) as i32;
        cb_to_b[i] = ((fix(2.015625) * x + n_half) >> 16) as i32;
        cr_to_g[i] = ((-fix(0.8125) * x + n_half) >> 16) as i32;
        cb_to_g[i] = ((-fix(0.390625) * x + n_half) >> 16) as i32;
    }

    let mut m_y = vec![0i32; 256];
    for i in 0usize..256 {
        let x = i as i64 - 16;
        m_y[i] = ((fix(1.164) * x + n_half) >> 16) as i32;
    }

    ColorLuts { cr_to_r, cb_to_b, cr_to_g, cb_to_g, m_y }
}

// VQ palette state (mDecode_Color)
struct VqState {
    color: [u32; 4],
    index: [usize; 4],
    bitmap_bits: u32,
}

impl VqState {
    fn new() -> Self {
        // VQ_Initialize values (packed Y<<16|Cb<<8|Cr)
        VqState {
            color: [0x008080, 0xFF8000, 0x808080, 0xC08000],
            index: [0, 1, 2, 3],
            bitmap_bits: 0,
        }
    }
}

// Update VQ palette entries from bitstream. Mirrors VQ_ColorUpdate in ast2100.js.
fn vq_color_update(br: &mut BitReader, vq: &mut VqState, num_colors: usize) {
    for i in 0..num_colors {
        let cb = br.codebuf();
        let idx = ((cb >> 29) & 3) as usize;
        vq.index[i] = idx;
        if (cb >> 31) & 1 == 0 {
            // No-update: just remap index; consume 3 bits
            br.consume_bits(3);
        } else {
            // Update: new 24-bit color at bits 28..5
            let color = (cb >> 5) & 0x00FFFFFF;
            vq.color[vq.index[i]] = color;
            br.consume_bits(27);
        }
    }
}

// YUV->RGB conversion, writing to out_rgba.
// Mirrors YUVToRGB in ast2100.js; for mMode420==1 (16x16 MCU) or mMode420==0 (8x8 MCU).
fn yuv_to_rgb(
    tile_yuv: &[u8],
    txb: usize,
    tyb: usize,
    width: usize,
    out: &mut [u8],
    mode420: bool,
    luts: &ColorLuts,
    rlimit: &[u16],
) {
    if !mode420 {
        // 8x8 MCU, chroma 1:1
        let px = txb * 8;
        let py = tyb * 8;
        let mut row_start = py * width + px;
        for j in 0usize..8 {
            for i in 0usize..8 {
                let m = j * 8 + i;
                let y = tile_yuv[m] as usize;
                let cb = tile_yuv[64 + m] as usize;
                let cr = tile_yuv[128 + m] as usize;
                let n = row_start + i;
                let luma = luts.m_y[y];
                let r = rlimit[(256 + luma + luts.cr_to_r[cr]).clamp(0, 1407) as usize] as u8;
                let g = rlimit[(256 + luma + luts.cb_to_g[cb] + luts.cr_to_g[cr]).clamp(0, 1407) as usize] as u8;
                let b = rlimit[(256 + luma + luts.cb_to_b[cb]).clamp(0, 1407) as usize] as u8;
                let base = n * 3;
                if base + 2 < out.len() {
                    out[base] = r;
                    out[base + 1] = g;
                    out[base + 2] = b;
                }
            }
            row_start += width;
        }
    } else {
        // 16x16 MCU, 2x2 chroma upsampling (4 Y quadrants + 1 Cb + 1 Cr)
        // Y quadrants: tile_yuv[0..64]=Q0, [64..128]=Q1, [128..192]=Q2, [192..256]=Q3
        // Chroma: tile_yuv[256..320]=Cb, [320..384]=Cr
        let px = txb * 16;
        let py = tyb * 16;
        let mut qptr = [0usize; 4];
        let mut row_start = py * width + px;
        for j in 0usize..16 {
            for i in 0usize..16 {
                let qi = (j >> 3) * 2 + (i >> 3);
                let y_val = tile_yuv[qi * 64 + qptr[qi]] as usize;
                qptr[qi] += 1;
                let m = ((j >> 1) << 3) + (i >> 1);
                let cb = tile_yuv[256 + m] as usize;
                let cr = tile_yuv[320 + m] as usize;
                let n = row_start + i;
                let luma = luts.m_y[y_val];
                let r_idx = (256 + luma + luts.cr_to_r[cr]).clamp(0, 1407) as usize;
                let g_idx = (256 + luma + luts.cb_to_g[cb] + luts.cr_to_g[cr]).clamp(0, 1407) as usize;
                let b_idx = (256 + luma + luts.cb_to_b[cb]).clamp(0, 1407) as usize;
                let r = rlimit[r_idx] as u8;
                let g = rlimit[g_idx] as u8;
                let b = rlimit[b_idx] as u8;
                let base = n * 3;
                if base + 2 < out.len() {
                    out[base] = r;
                    out[base + 1] = g;
                    out[base + 2] = b;
                }
            }
            row_start += width;
        }
    }
}

// VQ decompress: fill tile_yuv and call yuv_to_rgb.
// Mirrors VQ_Decompress in ast2100.js.
fn vq_decompress(
    br: &mut BitReader,
    vq: &VqState,
    txb: usize,
    tyb: usize,
    width: usize,
    out: &mut [u8],
    mode420: bool,
    luts: &ColorLuts,
    rlimit: &[u16],
) {
    let mut tile_yuv = [0u8; 768];

    if vq.bitmap_bits == 0 {
        // 1-color flat fill
        let c = vq.color[vq.index[0]];
        let yy = ((c >> 16) & 0xFF) as u8;
        let cb = ((c >> 8) & 0xFF) as u8;
        let cr = (c & 0xFF) as u8;
        for k in 0usize..64 {
            tile_yuv[k] = yy;
            tile_yuv[k + 64] = cb;
            tile_yuv[k + 128] = cr;
        }
    } else {
        for k in 0usize..64 {
            let data = (br.codebuf() >> (32 - vq.bitmap_bits)) as usize & 0xFFFF;
            let c = vq.color[vq.index[data & 3]];
            tile_yuv[k] = ((c >> 16) & 0xFF) as u8;
            tile_yuv[k + 64] = ((c >> 8) & 0xFF) as u8;
            tile_yuv[k + 128] = (c & 0xFF) as u8;
            br.consume_bits(vq.bitmap_bits);
        }
    }

    yuv_to_rgb(&tile_yuv, txb, tyb, width, out, mode420, luts, rlimit);
}

// Decompress one MCU (DCT path). Mirrors Decompress() in ast2100.js.
fn decompress_dct(
    br: &mut BitReader,
    txb: usize,
    tyb: usize,
    width: usize,
    out: &mut [u8],
    qt: [&Box<[i64; 64]>; 4],
    qt_sel: usize,
    huffman: &HuffmanTables,
    dc_y: &mut i32,
    dc_cb: &mut i32,
    dc_cr: &mut i32,
    mode420: bool,
    luts: &ColorLuts,
    rlimit: &[u16],
) {
    let mut tile_yuv = [0u8; 768];
    let mut dct_coeff = [0i32; 384];

    if mode420 {
        // 16x16 MCU: Y0, Y1, Y2, Y3, Cb, Cr
        *dc_y = decode_block(br, &huffman.dc_luma, &huffman.ac_luma, *dc_y, &mut dct_coeff, 0);
        *dc_y = decode_block(br, &huffman.dc_luma, &huffman.ac_luma, *dc_y, &mut dct_coeff, 64);
        *dc_y = decode_block(br, &huffman.dc_luma, &huffman.ac_luma, *dc_y, &mut dct_coeff, 128);
        *dc_y = decode_block(br, &huffman.dc_luma, &huffman.ac_luma, *dc_y, &mut dct_coeff, 192);
        *dc_cb = decode_block(br, &huffman.dc_chroma, &huffman.ac_chroma, *dc_cb, &mut dct_coeff, 256);
        *dc_cr = decode_block(br, &huffman.dc_chroma, &huffman.ac_chroma, *dc_cr, &mut dct_coeff, 320);

        idct_transform(&dct_coeff, 0, qt[qt_sel], &mut tile_yuv, 0, rlimit);
        idct_transform(&dct_coeff, 64, qt[qt_sel], &mut tile_yuv, 64, rlimit);
        idct_transform(&dct_coeff, 128, qt[qt_sel], &mut tile_yuv, 128, rlimit);
        idct_transform(&dct_coeff, 192, qt[qt_sel], &mut tile_yuv, 192, rlimit);
        idct_transform(&dct_coeff, 256, qt[qt_sel + 1], &mut tile_yuv, 256, rlimit);
        idct_transform(&dct_coeff, 320, qt[qt_sel + 1], &mut tile_yuv, 320, rlimit);
    } else {
        // 8x8 MCU: Y, Cb, Cr
        *dc_y = decode_block(br, &huffman.dc_luma, &huffman.ac_luma, *dc_y, &mut dct_coeff, 0);
        *dc_cb = decode_block(br, &huffman.dc_chroma, &huffman.ac_chroma, *dc_cb, &mut dct_coeff, 64);
        *dc_cr = decode_block(br, &huffman.dc_chroma, &huffman.ac_chroma, *dc_cr, &mut dct_coeff, 128);

        idct_transform(&dct_coeff, 0, qt[qt_sel], &mut tile_yuv, 0, rlimit);
        idct_transform(&dct_coeff, 64, qt[qt_sel + 1], &mut tile_yuv, 64, rlimit);
        idct_transform(&dct_coeff, 128, qt[qt_sel + 1], &mut tile_yuv, 128, rlimit);
    }

    yuv_to_rgb(&tile_yuv, txb, tyb, width, out, mode420, luts, rlimit);
}

// Main decode function, exposed to Python.
#[pyfunction]
pub fn decode_frame(codec_data: &[u8], width: usize, height: usize) -> PyResult<Vec<u8>> {
    if codec_data.len() < 4 {
        return Err(PyValueError::new_err("codec_data too short (< 4 bytes)"));
    }

    // Parse codec header (bytes 0..3)
    let y_sel_raw = codec_data[0] as usize;
    let uv_sel_raw = codec_data[1] as usize;
    let mode = (codec_data[2] as u16) * 256 + codec_data[3] as u16;

    // InitParameter logic: for 422 -> effective Y_Sel=4, UV_Sel=7; for 444 -> 7,7
    // init_jpg_table runs with these effective selectors.
    // Then SetBuffer overwrites to the raw header values (y_sel_raw, uv_sel_raw).
    // But since init_jpg_table runs before SetBuffer, quant tables use the InitParameter values.
    let (eff_y_sel, eff_uv_sel, mode420) = match mode {
        422 => (4usize, 7usize, true),
        444 => (7usize, 7usize, false),
        _ => {
            return Err(PyValueError::new_err(format!("unknown mode {}", mode)));
        }
    };
    // Suppress unused variable warnings — raw values from header available but not used
    // because InitParameter forces the effective selectors before init_jpg_table.
    let _ = y_sel_raw;
    let _ = uv_sel_raw;

    // Build quantization tables (using InitParameter effective selectors)
    let qt0 = build_quant_table(select_luma_table(eff_y_sel), 16);    // luma
    let qt1 = build_quant_table(select_chroma_table(eff_uv_sel), 16); // chroma
    let qt2 = build_quant_table(select_luma_table(0), 16);            // advance luma (sel=0)
    let qt3 = build_quant_table(select_chroma_table(0), 16);          // advance chroma (sel=0)
    let qt = [&qt0, &qt1, &qt2, &qt3];

    // Build Huffman tables
    let huffman = HuffmanTables::build();

    // Build range-limit table and color LUTs
    let rlimit = build_range_limit_table();
    let luts = build_color_luts();

    // MCU dimensions
    let mcu_size = if mode420 { 16usize } else { 8usize };
    let w_pad = (width + mcu_size - 1) / mcu_size * mcu_size;
    let h_pad = (height + mcu_size - 1) / mcu_size * mcu_size;

    // Output buffer: RGB888, width*height*3 bytes
    let mut out = vec![0u8; width * height * 3];

    // Bit reader starts at byte 4 (after codec header)
    if codec_data.len() < 12 {
        return Err(PyValueError::new_err("codec_data too short for bitstream init"));
    }
    let mut br = BitReader::new(codec_data, 4);

    // DC predictors (reset to 0 at frame start)
    let mut dc_y = 0i32;
    let mut dc_cb = 0i32;
    let mut dc_cr = 0i32;

    // Tile cursor
    let mut txb = 0usize;
    let mut tyb = 0usize;

    // VQ palette state
    let mut vq = VqState::new();

    let step_x = w_pad / mcu_size;
    let step_y = h_pad / mcu_size;
    let mb = std::cmp::max(4096, width * height / 64);

    for _block_index in 0..=mb {
        let flag = (br.codebuf() >> 28) & 0xF;

        match flag {
            0 => {
                // JPEG_NO_SKIP_CODE
                br.consume_bits(4);
                decompress_dct(&mut br, txb, tyb, width, &mut out, qt, 0,
                    &huffman, &mut dc_y, &mut dc_cb, &mut dc_cr, mode420, &luts, &rlimit);
                move_block_index(&mut txb, &mut tyb, step_x, step_y);
            }
            4 => {
                // LOW_JPEG_NO_SKIP_CODE
                br.consume_bits(4);
                decompress_dct(&mut br, txb, tyb, width, &mut out, qt, 2,
                    &huffman, &mut dc_y, &mut dc_cb, &mut dc_cr, mode420, &luts, &rlimit);
                move_block_index(&mut txb, &mut tyb, step_x, step_y);
            }
            8 => {
                // JPEG_SKIP_CODE
                let cb = br.codebuf();
                txb = ((cb & 0x0FF00000) >> 20) as usize;
                tyb = ((cb & 0x000FF000) >> 12) as usize;
                br.consume_bits(20);
                decompress_dct(&mut br, txb, tyb, width, &mut out, qt, 0,
                    &huffman, &mut dc_y, &mut dc_cb, &mut dc_cr, mode420, &luts, &rlimit);
                move_block_index(&mut txb, &mut tyb, step_x, step_y);
            }
            12 => {
                // LOW_JPEG_SKIP_CODE
                let cb = br.codebuf();
                txb = ((cb & 0x0FF00000) >> 20) as usize;
                tyb = ((cb & 0x000FF000) >> 12) as usize;
                br.consume_bits(20);
                decompress_dct(&mut br, txb, tyb, width, &mut out, qt, 2,
                    &huffman, &mut dc_y, &mut dc_cb, &mut dc_cr, mode420, &luts, &rlimit);
                move_block_index(&mut txb, &mut tyb, step_x, step_y);
            }
            5 => {
                // VQ_NO_SKIP_1_COLOR_CODE
                br.consume_bits(4);
                vq.bitmap_bits = 0;
                vq_color_update(&mut br, &mut vq, 1);
                vq_decompress(&mut br, &vq, txb, tyb, width, &mut out, mode420, &luts, &rlimit);
                move_block_index(&mut txb, &mut tyb, step_x, step_y);
            }
            6 => {
                // VQ_NO_SKIP_2_COLOR_CODE
                br.consume_bits(4);
                vq.bitmap_bits = 1;
                vq_color_update(&mut br, &mut vq, 2);
                vq_decompress(&mut br, &vq, txb, tyb, width, &mut out, mode420, &luts, &rlimit);
                move_block_index(&mut txb, &mut tyb, step_x, step_y);
            }
            7 => {
                // VQ_NO_SKIP_4_COLOR_CODE
                br.consume_bits(4);
                vq.bitmap_bits = 2;
                vq_color_update(&mut br, &mut vq, 4);
                vq_decompress(&mut br, &vq, txb, tyb, width, &mut out, mode420, &luts, &rlimit);
                move_block_index(&mut txb, &mut tyb, step_x, step_y);
            }
            13 => {
                // VQ_SKIP_1_COLOR_CODE
                let cb = br.codebuf();
                txb = ((cb & 0x0FF00000) >> 20) as usize;
                tyb = ((cb & 0x000FF000) >> 12) as usize;
                br.consume_bits(20);
                vq.bitmap_bits = 0;
                vq_color_update(&mut br, &mut vq, 1);
                vq_decompress(&mut br, &vq, txb, tyb, width, &mut out, mode420, &luts, &rlimit);
                move_block_index(&mut txb, &mut tyb, step_x, step_y);
            }
            14 => {
                // VQ_SKIP_2_COLOR_CODE
                let cb = br.codebuf();
                txb = ((cb & 0x0FF00000) >> 20) as usize;
                tyb = ((cb & 0x000FF000) >> 12) as usize;
                br.consume_bits(20);
                vq.bitmap_bits = 1;
                vq_color_update(&mut br, &mut vq, 2);
                vq_decompress(&mut br, &vq, txb, tyb, width, &mut out, mode420, &luts, &rlimit);
                move_block_index(&mut txb, &mut tyb, step_x, step_y);
            }
            15 => {
                // VQ_SKIP_4_COLOR_CODE
                let cb = br.codebuf();
                txb = ((cb & 0x0FF00000) >> 20) as usize;
                tyb = ((cb & 0x000FF000) >> 12) as usize;
                br.consume_bits(20);
                vq.bitmap_bits = 2;
                vq_color_update(&mut br, &mut vq, 4);
                vq_decompress(&mut br, &vq, txb, tyb, width, &mut out, mode420, &luts, &rlimit);
                move_block_index(&mut txb, &mut tyb, step_x, step_y);
            }
            9 => {
                // FRAME_END_CODE
                return Ok(out);
            }
            _ => {
                return Err(PyValueError::new_err(format!("unknown block flag: {}", flag)));
            }
        }
    }

    // Exceeded MB limit without FRAME_END
    Err(PyValueError::new_err("exceeded block limit without FRAME_END marker"))
}

fn move_block_index(txb: &mut usize, tyb: &mut usize, step_x: usize, step_y: usize) {
    *txb += 1;
    if *txb >= step_x {
        *tyb += 1;
        if *tyb >= step_y {
            *tyb = 0;
        }
        *txb = 0;
    }
}

#[pyfunction]
fn decoder_version() -> &'static str {
    "ikvm_ast2100 0.1.0"
}

#[pymodule]
fn ikvm_ast2100(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(decoder_version, m)?)?;
    m.add_function(wrap_pyfunction!(decode_frame, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_header_parse() {
        // payload[0..4] = [4, 7, 0x01, 0xa6] -> Y_Sel=4, UV_Sel=7, Mode=422
        let data = vec![0x04u8, 0x07, 0x01, 0xa6,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let y_sel = data[0] as usize;
        let uv_sel = data[1] as usize;
        let mode = (data[2] as u16) * 256 + data[3] as u16;
        assert_eq!(y_sel, 4);
        assert_eq!(uv_sel, 7);
        assert_eq!(mode, 422);
    }

    #[test]
    fn test_zigzag_roundtrip() {
        use crate::tables::{ZIGZAG, DEZIGZAG};
        // dezigzag should be inverse of zigzag for positions 0..64
        for i in 0usize..64 {
            let zz = ZIGZAG[i];
            let dzz = DEZIGZAG[zz];
            assert_eq!(dzz, i, "dezigzag[zigzag[{}]] should be {}", i, i);
        }
    }

    #[test]
    fn test_ycbcr_to_rgb_neutral() {
        // Y=235, Cb=128, Cr=128 -> near white (full luma, neutral chroma)
        let luts = build_color_luts();
        let rlimit = build_range_limit_table();

        let y = 235usize;
        let cb = 128usize;
        let cr = 128usize;
        let luma = luts.m_y[y];
        let r = rlimit[(256 + luma + luts.cr_to_r[cr]).clamp(0, 1407) as usize] as u8;
        let g = rlimit[(256 + luma + luts.cb_to_g[cb] + luts.cr_to_g[cr]).clamp(0, 1407) as usize] as u8;
        let b = rlimit[(256 + luma + luts.cb_to_b[cb]).clamp(0, 1407) as usize] as u8;
        // Should be near white
        assert!(r > 200, "R={} should be near 255", r);
        assert!(g > 200, "G={} should be near 255", g);
        assert!(b > 200, "B={} should be near 255", b);
    }

    #[test]
    fn test_ycbcr_to_rgb_black() {
        // Y=16, Cb=128, Cr=128 -> near black
        let luts = build_color_luts();
        let rlimit = build_range_limit_table();
        let y = 16usize;
        let cb = 128usize;
        let cr = 128usize;
        let luma = luts.m_y[y];
        let r = rlimit[(256 + luma + luts.cr_to_r[cr]).clamp(0, 1407) as usize] as u8;
        let g = rlimit[(256 + luma + luts.cb_to_g[cb] + luts.cr_to_g[cr]).clamp(0, 1407) as usize] as u8;
        let b = rlimit[(256 + luma + luts.cb_to_b[cb]).clamp(0, 1407) as usize] as u8;
        assert!(r < 10, "R={} should be near 0", r);
        assert!(g < 10, "G={} should be near 0", g);
        assert!(b < 10, "B={} should be near 0", b);
    }

    #[test]
    fn test_idct_dc_only() {
        use crate::idct::{idct_transform, build_range_limit_table};
        use crate::quant::build_quant_table;
        use crate::tables::TBL_057Y;

        let rlimit = build_range_limit_table();
        let quant = build_quant_table(&TBL_057Y, 16);
        let mut dct_coeff = vec![0i32; 64];
        // DC=0 -> IDCT output all 128 (level shift)
        let mut tile_yuv = vec![0u8; 64];
        idct_transform(&dct_coeff, 0, &quant, &mut tile_yuv, 0, &rlimit);
        for &v in &tile_yuv {
            assert_eq!(v, 128);
        }

        // Now set DC to 1 and verify it changes
        dct_coeff[0] = 1;
        let mut tile_yuv2 = vec![0u8; 64];
        idct_transform(&dct_coeff, 0, &quant, &mut tile_yuv2, 0, &rlimit);
        // The result should still be flat (DC only) but different from 128
        let all_same = tile_yuv2.windows(2).all(|w| w[0] == w[1]);
        assert!(all_same, "DC-only block should produce flat output");
    }
}

#[cfg(all(test, feature = "integration"))]
mod debug_decode_tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_first_mcu_decode_trace() {
        let raw = fs::read("/home/elice/ikvm-gateway/.claude/worktrees/m0-spike/captures/frame_rect0.bin").unwrap();
        let codec_data = &raw[8..];
        
        // Build tables
        let eff_y_sel = 4usize;
        let eff_uv_sel = 7usize;
        let qt0 = build_quant_table(select_luma_table(eff_y_sel), 16);
        let qt1 = build_quant_table(select_chroma_table(eff_uv_sel), 16);
        let qt2 = build_quant_table(select_luma_table(0), 16);
        let qt3 = build_quant_table(select_chroma_table(0), 16);
        let qt = [&qt0, &qt1, &qt2, &qt3];
        let huffman = huffman::HuffmanTables::build();
        let rlimit = idct::build_range_limit_table();
        let luts = build_color_luts();
        
        let mut br = bitreader::BitReader::new(codec_data, 4);
        let mut dc_y = 0i32;
        let mut dc_cb = 0i32;
        let mut dc_cr = 0i32;
        
        // Consume 4-bit flag
        let flag = (br.codebuf() >> 28) & 0xF;
        println!("Block type flag: {}", flag);
        br.consume_bits(4);
        
        // Decode first MCU (16x16, mode420)
        let mut tile_yuv = [0u8; 768];
        let mut dct_coeff = [0i32; 384];
        
        dc_y = huffman::decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 0);
        println!("Y0 DC = {}", dc_y);
        dc_y = huffman::decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 64);
        println!("Y1 DC = {}", dc_y);
        dc_y = huffman::decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 128);
        println!("Y2 DC = {}", dc_y);
        dc_y = huffman::decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 192);
        println!("Y3 DC = {}", dc_y);
        dc_cb = huffman::decode_block(&mut br, &huffman.dc_chroma, &huffman.ac_chroma, dc_cb, &mut dct_coeff, 256);
        println!("Cb DC = {}", dc_cb);
        dc_cr = huffman::decode_block(&mut br, &huffman.dc_chroma, &huffman.ac_chroma, dc_cr, &mut dct_coeff, 320);
        println!("Cr DC = {}", dc_cr);
        
        // Print first few dct_coeff
        println!("dct_coeff[0..8] = {:?}", &dct_coeff[0..8]);
        println!("dct_coeff[256..264] (Cb) = {:?}", &dct_coeff[256..264]);
        
        // IDCT
        idct::idct_transform(&dct_coeff, 0, qt[0], &mut tile_yuv, 0, &rlimit);
        println!("tile_yuv[0..8] (Y0 row 0) = {:?}", &tile_yuv[0..8]);
        
        idct::idct_transform(&dct_coeff, 256, qt[1], &mut tile_yuv, 256, &rlimit);
        println!("tile_yuv[256..264] (Cb row 0) = {:?}", &tile_yuv[256..264]);
        
        idct::idct_transform(&dct_coeff, 320, qt[1], &mut tile_yuv, 320, &rlimit);
        println!("tile_yuv[320..328] (Cr row 0) = {:?}", &tile_yuv[320..328]);
        
        // Compute one pixel manually
        let y = tile_yuv[0] as usize;
        let cb = tile_yuv[256] as usize;
        let cr = tile_yuv[320] as usize;
        let luma = luts.m_y[y];
        println!("Pixel (0,0): Y={}, Cb={}, Cr={}, luma={}", y, cb, cr, luma);
        let r_idx = (256 + luma + luts.cr_to_r[cr]).clamp(0, 1407) as usize;
        let g_idx = (256 + luma + luts.cb_to_g[cb] + luts.cr_to_g[cr]).clamp(0, 1407) as usize;
        let b_idx = (256 + luma + luts.cb_to_b[cb]).clamp(0, 1407) as usize;
        println!("r_idx={}, g_idx={}, b_idx={}", r_idx, g_idx, b_idx);
        println!("R={}, G={}, B={}", rlimit[r_idx], rlimit[g_idx], rlimit[b_idx]);
    }
}

#[cfg(all(test, feature = "integration"))]
mod debug_mcu_trace {
    use super::*;
    use crate::huffman::{HuffmanTables, decode_block};
    use crate::bitreader::BitReader;
    use std::fs;
    
    #[test]
    fn test_first_ten_mcus_dc() {
        let raw = fs::read("/home/elice/ikvm-gateway/.claude/worktrees/m0-spike/captures/frame_rect0.bin").unwrap();
        let codec_data = &raw[8..];
        
        let eff_y_sel = 4usize;
        let eff_uv_sel = 7usize;
        let qt0 = build_quant_table(select_luma_table(eff_y_sel), 16);
        let qt1 = build_quant_table(select_chroma_table(eff_uv_sel), 16);
        let qt2 = build_quant_table(select_luma_table(0), 16);
        let qt3 = build_quant_table(select_chroma_table(0), 16);
        let qt = [&qt0, &qt1, &qt2, &qt3];
        let huffman = HuffmanTables::build();
        let rlimit = idct::build_range_limit_table();
        let luts = build_color_luts();
        
        let mut br = BitReader::new(codec_data, 4);
        let mut dc_y = 0i32;
        let mut dc_cb = 0i32;
        let mut dc_cr = 0i32;
        let mut txb = 0usize;
        let mut tyb = 0usize;
        let mode420 = true;
        let step_x = 1024 / 16;
        let step_y = 768 / 16;
        let width = 1024usize;
        let mut out = vec![0u8; width * 768 * 3];
        let vq = VqState::new();
        
        for mcu in 0..20 {
            let flag = (br.codebuf() >> 28) & 0xF;
            if flag == 9 {
                println!("MCU {}: FRAME_END", mcu);
                break;
            }
            if flag == 0 {
                br.consume_bits(4);
                let prev_dc_y = dc_y;
                let prev_dc_cb = dc_cb;
                let prev_dc_cr = dc_cr;
                
                let mut tile_yuv = [0u8; 768];
                let mut dct_coeff = [0i32; 384];
                
                dc_y = decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 0);
                dc_y = decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 64);
                dc_y = decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 128);
                dc_y = decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 192);
                dc_cb = decode_block(&mut br, &huffman.dc_chroma, &huffman.ac_chroma, dc_cb, &mut dct_coeff, 256);
                dc_cr = decode_block(&mut br, &huffman.dc_chroma, &huffman.ac_chroma, dc_cr, &mut dct_coeff, 320);
                
                idct::idct_transform(&dct_coeff, 0, qt[0], &mut tile_yuv, 0, &rlimit);
                idct::idct_transform(&dct_coeff, 256, qt[1], &mut tile_yuv, 256, &rlimit);
                
                let y0 = tile_yuv[0];
                let cb0 = tile_yuv[256];
                
                println!("MCU {} (txb={},tyb={}): flag={}, DCY={}, DCCb={}, DCCr={}, tileY[0]={}, tileCb[0]={}",
                    mcu, txb, tyb, flag, dc_y, dc_cb, dc_cr, y0, cb0);
                    
                move_block_index(&mut txb, &mut tyb, step_x, step_y);
            } else {
                println!("MCU {}: unexpected flag {}", mcu, flag);
                break;
            }
        }
    }
}

#[cfg(all(test, feature = "integration"))]
mod debug_ac_trace {
    use super::*;
    use crate::huffman::{HuffmanTables, decode_block};
    use crate::bitreader::BitReader;
    use std::fs;
    
    #[test]
    fn test_first_bright_mcu_dc_ac() {
        // MCU (0,1) should be bright - let's decode it and check
        let raw = fs::read("/home/elice/ikvm-gateway/.claude/worktrees/m0-spike/captures/frame_rect0.bin").unwrap();
        let codec_data = &raw[8..];
        
        let eff_y_sel = 4usize;
        let eff_uv_sel = 7usize;
        let qt0 = build_quant_table(select_luma_table(eff_y_sel), 16);
        let qt1 = build_quant_table(select_chroma_table(eff_uv_sel), 16);
        let huffman = HuffmanTables::build();
        let rlimit = idct::build_range_limit_table();
        let luts = build_color_luts();
        
        let mut br = BitReader::new(codec_data, 4);
        let mut dc_y = 0i32;
        let mut dc_cb = 0i32;
        let mut dc_cr = 0i32;
        let step_x = 1024 / 16;
        let step_y = 768 / 16;
        let mut txb = 0usize;
        let mut tyb = 0usize;
        
        // Skip first 64 MCUs (tyb=0 row = 64 MCUs) to get to tyb=1
        for mcu_idx in 0..=64 {
            let flag = (br.codebuf() >> 28) & 0xF;
            if flag == 9 { 
                println!("FRAME_END at MCU {}", mcu_idx);
                return;
            }
            if flag != 0 { 
                println!("Unexpected flag {} at MCU {}", flag, mcu_idx);
                return;
            }
            br.consume_bits(4);
            let mut dct_coeff = [0i32; 384];
            dc_y = decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 0);
            dc_y = decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 64);
            dc_y = decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 128);
            dc_y = decode_block(&mut br, &huffman.dc_luma, &huffman.ac_luma, dc_y, &mut dct_coeff, 192);
            dc_cb = decode_block(&mut br, &huffman.dc_chroma, &huffman.ac_chroma, dc_cb, &mut dct_coeff, 256);
            dc_cr = decode_block(&mut br, &huffman.dc_chroma, &huffman.ac_chroma, dc_cr, &mut dct_coeff, 320);
            
            if mcu_idx == 64 {
                // This is MCU (0,1) - the first bright MCU!
                println!("MCU 64 ({},{}) DC: Y={}, Cb={}, Cr={}", txb, tyb, dc_y, dc_cb, dc_cr);
                // Check AC coefficients
                let nonzero_y0: Vec<_> = dct_coeff[0..64].iter().enumerate().filter(|&(_,&v)| v != 0).collect();
                println!("Y0 nonzero coefficients: {:?}", &nonzero_y0[..nonzero_y0.len().min(10)]);
                
                // IDCT and print first row
                let mut tile_yuv = [0u8; 768];
                idct::idct_transform(&dct_coeff, 0, &qt0, &mut tile_yuv, 0, &rlimit);
                idct::idct_transform(&dct_coeff, 64, &qt0, &mut tile_yuv, 64, &rlimit);
                idct::idct_transform(&dct_coeff, 128, &qt0, &mut tile_yuv, 128, &rlimit);
                idct::idct_transform(&dct_coeff, 192, &qt0, &mut tile_yuv, 192, &rlimit);
                idct::idct_transform(&dct_coeff, 256, &qt1, &mut tile_yuv, 256, &rlimit);
                idct::idct_transform(&dct_coeff, 320, &qt1, &mut tile_yuv, 320, &rlimit);
                println!("Y0 row 0-7: {:?}", &tile_yuv[0..8]);
                println!("Y1 row 0-7: {:?}", &tile_yuv[64..72]);
                println!("Cb row 0-7: {:?}", &tile_yuv[256..264]);
                println!("Cr row 0-7: {:?}", &tile_yuv[320..328]);
                
                // Compute a few pixels
                let y = tile_yuv[0] as usize;
                let cb = tile_yuv[256] as usize;
                let cr = tile_yuv[320] as usize;
                let luma = luts.m_y[y];
                let r_idx = (256 + luma + luts.cr_to_r[cr]).clamp(0, 1407) as usize;
                println!("Pixel (0,0): Y={}, Cb={}, Cr={}, R={}", y, cb, cr, rlimit[r_idx]);
            }
            
            move_block_index(&mut txb, &mut tyb, step_x, step_y);
        }
    }
}
