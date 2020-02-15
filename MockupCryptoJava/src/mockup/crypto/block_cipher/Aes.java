/**
 * The MIT License
 *
 * Copyright (c) 2020 Ilwoong Jeong (https://github.com/ilwoong)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package mockup.crypto.block_cipher;

import static mockup.crypto.util.Rotations.rotr32;

import mockup.crypto.BlockCipher;

public class Aes extends BlockCipher implements AesConstants {

	private static final int BLOCKSIZE = 16;
	private int keysize;
	private int rounds;
	private byte[] rks;
	private byte[] block = new byte[BLOCKSIZE];

	@Override
	public String getName() {
		return "AES-" + (keysize << 3);
	}

	@Override
	public int getBlocksize() {
		return BLOCKSIZE;
	}

	@Override
	public int getKeysize() {
		return keysize;
	}

	@Override
	public void init(byte[] mk) {
		rks = null;
		keysize = mk.length;

		switch (keysize) {
		case 16:
			init128(mk);
			break;

		case 24:
			init192(mk);
			break;

		case 32:
			init256(mk);
			break;

		default:
			throw new IllegalArgumentException("Unsuppported keysize: " + keysize);
		}
	}

	private void init128(byte[] mk) {
		rounds = AES128_ROUNDS;
		rks = new byte[(rounds + 1) * BLOCKSIZE];

		var rk = convertIntKeys(mk);
		var idx = 0;
		for (var i = 0; i < 10; ++i, idx += 4) {
			var tmp = subword(rotr32(rk[idx + 3], 8));
			rk[idx + 4] = rk[idx + 0] ^ tmp ^ RC[i];
			rk[idx + 5] = rk[idx + 1] ^ rk[idx + 4];
			rk[idx + 6] = rk[idx + 2] ^ rk[idx + 5];
			rk[idx + 7] = rk[idx + 3] ^ rk[idx + 6];
		}

		writeRoundKeys(rk);
	}

	private void init192(byte[] mk) {
		rounds = AES192_ROUNDS;
		rks = new byte[(rounds + 1) * BLOCKSIZE];

		var rk = convertIntKeys(mk);
		var idx = 0;
		for (var i = 0; i < 8; ++i, idx += 6) {
			var tmp = subword(rotr32(rk[idx + 5], 8));
			rk[idx + 6] = rk[idx + 0] ^ tmp ^ RC[i];
			rk[idx + 7] = rk[idx + 1] ^ rk[idx + 6];
			rk[idx + 8] = rk[idx + 2] ^ rk[idx + 7];
			rk[idx + 9] = rk[idx + 3] ^ rk[idx + 8];

			if (i == 7) {
				break;
			}

			rk[idx + 10] = rk[idx + 4] ^ rk[idx + 9];
			rk[idx + 11] = rk[idx + 5] ^ rk[idx + 10];
		}

		writeRoundKeys(rk);
	}

	private void init256(byte[] mk) {
		rounds = AES256_ROUNDS;
		rks = new byte[(rounds + 1) * BLOCKSIZE];

		var rk = convertIntKeys(mk);
		var idx = 0;
		for (var i = 0; i < 7; ++i, idx += 8) {
			var tmp = subword(rotr32(rk[idx + 7], 8));
			rk[idx + 8] = rk[idx + 0] ^ tmp ^ RC[i];
			rk[idx + 9] = rk[idx + 1] ^ rk[idx + 8];
			rk[idx + 10] = rk[idx + 2] ^ rk[idx + 9];
			rk[idx + 11] = rk[idx + 3] ^ rk[idx + 10];

			if (i == 6) {
				break;
			}

			rk[idx + 12] = rk[idx + 4] ^ subword(rk[idx + 11]);
			rk[idx + 13] = rk[idx + 5] ^ rk[idx + 12];
			rk[idx + 14] = rk[idx + 6] ^ rk[idx + 13];
			rk[idx + 15] = rk[idx + 7] ^ rk[idx + 14];
		}

		writeRoundKeys(rk);
	}

	private int[] convertIntKeys(byte[] mk) {
		var rk = new int[rks.length >> 2];
		var ki = 0;
		for (var i = 0; i < keysize >> 2; ++i) {
			rk[i] ^= mk[ki++] & 0xff;
			rk[i] ^= (mk[ki++] & 0xff) << 8;
			rk[i] ^= (mk[ki++] & 0xff) << 16;
			rk[i] ^= (mk[ki++] & 0xff) << 24;
		}
		return rk;
	}

	private void writeRoundKeys(int[] rk) {
		var ki = 0;
		for (var i = 0; i < rk.length; ++i) {
			rks[ki++] = (byte) (rk[i]);
			rks[ki++] = (byte) (rk[i] >>> 8);
			rks[ki++] = (byte) (rk[i] >>> 16);
			rks[ki++] = (byte) (rk[i] >>> 24);
		}
	}

	private int subword(int value) {
		int result = 0;
		result ^= (SBOX[(value >>> 24) & 0xff] & 0xff) << 24;
		result ^= (SBOX[(value >>> 16) & 0xff] & 0xff) << 16;
		result ^= (SBOX[(value >>> 8) & 0xff] & 0xff) << 8;
		result ^= (SBOX[value & 0xff] & 0xff);
		return result;
	}

	@Override
	public void encryptBlock(final byte[] src, int srcOff, byte[] dst, int dstOff) {
		System.arraycopy(src, srcOff, block, 0, BLOCKSIZE);
		transposeBlock();

		var ridx = 0;
		addRoundKey(ridx);
		ridx += 16;

		for (int i = 0; i < rounds - 1; ++i) {
			encryptRound(ridx);
			ridx += 16;
		}
		encryptLastRound(ridx);

		transposeBlock();
		System.arraycopy(block, 0, dst, dstOff, BLOCKSIZE);
	}

	private void encryptRound(int ridx) {
		shiftRows();
		subBytesAndMixColumns();
		addRoundKey(ridx);
	}

	private void encryptLastRound(int ridx) {
		subBytes();
		shiftRows();
		addRoundKey(ridx);
	}

	private void addRoundKey(int ridx) {
		block[0] ^= rks[ridx + 0];
		block[1] ^= rks[ridx + 4];
		block[2] ^= rks[ridx + 8];
		block[3] ^= rks[ridx + 12];

		block[4] ^= rks[ridx + 1];
		block[5] ^= rks[ridx + 5];
		block[6] ^= rks[ridx + 9];
		block[7] ^= rks[ridx + 13];

		block[8] ^= rks[ridx + 2];
		block[9] ^= rks[ridx + 6];
		block[10] ^= rks[ridx + 10];
		block[11] ^= rks[ridx + 14];

		block[12] ^= rks[ridx + 3];
		block[13] ^= rks[ridx + 7];
		block[14] ^= rks[ridx + 11];
		block[15] ^= rks[ridx + 15];
	}

	private void subBytes() {
		for (var i = 0; i < block.length; ++i) {
			block[i] = SBOX[block[i] & 0xff];
		}
	}

	private void shiftRows() {
		var tmp = block[4];
		block[4] = block[5];
		block[5] = block[6];
		block[6] = block[7];
		block[7] = tmp;

		swapBlockElement(8, 10);
		swapBlockElement(9, 11);

		tmp = block[15];
		block[15] = block[14];
		block[14] = block[13];
		block[13] = block[12];
		block[12] = tmp;
	}

	private void subBytesAndMixColumns() {
		for (var i = 0; i < 4; ++i) {
			var value = SMC0[block[i] & 0xff] ^ SMC1[block[i + 4] & 0xff];
			value ^= SMC2[block[i + 8] & 0xff] ^ SMC3[block[i + 12] & 0xff];

			block[i + 0] = (byte) ((value >> 24) & 0xff);
			block[i + 4] = (byte) ((value >> 16) & 0xff);
			block[i + 8] = (byte) ((value >> 8) & 0xff);
			block[i + 12] = (byte) ((value) & 0xff);
		}
	}

	@Override
	public void decryptBlock(final byte[] src, int srcOff, byte[] dst, int dstOff) {
		System.arraycopy(src, srcOff, block, 0, BLOCKSIZE);
		transposeBlock();

		var ridx = BLOCKSIZE * rounds;
		addRoundKey(ridx);
		ridx -= 16;

		for (int i = 0; i < rounds - 1; ++i) {
			decryptRound(ridx);
			ridx -= 16;
		}
		decryptLastRound(ridx);

		transposeBlock();
		System.arraycopy(block, 0, dst, dstOff, BLOCKSIZE);
	}

	private void decryptRound(int ridx) {
		inverseShiftRows();
		inverseSubBytes();
		addRoundKey(ridx);
		inverseMixColumns();
	}

	private void decryptLastRound(int ridx) {
		inverseSubBytes();
		inverseShiftRows();
		addRoundKey(ridx);
	}

	private void inverseSubBytes() {
		for (var i = 0; i < block.length; ++i) {
			block[i] = SINV[block[i] & 0xff];
		}
	}

	private void inverseShiftRows() {
		var tmp = block[7];
		block[7] = block[6];
		block[6] = block[5];
		block[5] = block[4];
		block[4] = tmp;

		swapBlockElement(8, 10);
		swapBlockElement(9, 11);

		tmp = block[12];
		block[12] = block[13];
		block[13] = block[14];
		block[14] = block[15];
		block[15] = tmp;
	}

	private void inverseMixColumns() {
		subBytes();
		inverseSubBytesAndMixColumns();
	}

	private void inverseSubBytesAndMixColumns() {
		for (int i = 0; i < 4; ++i) {
			var value = ISMC0[block[i] & 0xff] ^ ISMC1[block[i + 4] & 0xff];
			value ^= ISMC2[block[i + 8] & 0xff] ^ ISMC3[block[i + 12] & 0xff];

			block[i + 0] = (byte) ((value >> 24) & 0xff);
			block[i + 4] = (byte) ((value >> 16) & 0xff);
			block[i + 8] = (byte) ((value >> 8) & 0xff);
			block[i + 12] = (byte) ((value) & 0xff);
		}
	}

	private void transposeBlock() {
		swapBlockElement(1, 4);
		swapBlockElement(2, 8);
		swapBlockElement(3, 12);
		swapBlockElement(6, 9);
		swapBlockElement(7, 13);
		swapBlockElement(11, 14);
	}

	private void swapBlockElement(int lhs, int rhs) {
		var tmp = block[lhs];
		block[lhs] = block[rhs];
		block[rhs] = tmp;
	}
}
