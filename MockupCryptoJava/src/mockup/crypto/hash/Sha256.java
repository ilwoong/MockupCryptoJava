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

package mockup.crypto.hash;

import java.util.Arrays;

import mockup.crypto.Hash;
import mockup.crypto.util.DataConversions;

/**
 * SHA-256
 * 
 * @author ilwoong.jeong
 *
 */
public class Sha256 extends Hash {

	//@formatter:off
	private static final int BLOCK_SIZE = 64;
	
	private static final int[] CONSTANT = { 
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};
	//@formatter:on

	private long msgLength;
	private int blockIdx;
	private byte[] block;
	private int[] chain;
	private int[] W;

	public Sha256() {
		reset();
	}

	@Override
	public String getName() {
		return "SHA-256";
	}

	@Override
	public int getBlockSize() {
		return BLOCK_SIZE;
	}

	@Override
	public int getOutputLength() {
		return 32;
	}

	@Override
	public void reset() {
		chain = new int[] { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
				0x5be0cd19 };
		W = new int[64];
		block = new byte[64];
		blockIdx = 0;
		msgLength = 0;
	}

	@Override
	public void update(byte[] msg) {
		if (msg == null || msg.length == 0) {
			return;
		}

		int offset = 0;
		int length = msg.length;
		msgLength += length;

		// 내부 블록에 남은 데이터가 있는 경우
		if (blockIdx > 0) {
			int gap = BLOCK_SIZE - blockIdx;
			if (length >= gap) {
				System.arraycopy(msg, offset, block, blockIdx, gap);
				process(block, 0);

				blockIdx = 0;
				offset += gap;
				length -= gap;

			} else {
				System.arraycopy(msg, offset, block, blockIdx, length);
				blockIdx += length;
				offset += gap;
				length = 0;
			}
		}

		// 블록 길이 이상의 데이터가 존재하는 경우
		while (length >= BLOCK_SIZE) {
			process(msg, offset);

			offset += BLOCK_SIZE;
			length -= BLOCK_SIZE;
		}

		// 블록 길이보다 작은 길이의 데이터가 남은 경우
		if (length > 0) {
			System.arraycopy(msg, offset, block, blockIdx, length);
			blockIdx += length;
			length = 0;
		}
	}

	@Override
	public byte[] doFinal() {
		block[blockIdx++] = (byte) 0x80;
		Arrays.fill(block, blockIdx, block.length, (byte) 0);

		if (blockIdx > 56) {
			process(block, 0);
			Arrays.fill(block, 0, block.length, (byte) 0);
		}

		DataConversions.l2bs_be(msgLength << 3, block, 56);
		process(block, 0);

		byte[] digest = DataConversions.is2bs_be(chain);

		reset();

		return digest;
	}

	private void process(byte[] message, int offset) {
		int[] imt = new int[chain.length];
		System.arraycopy(chain, 0, imt, 0, chain.length);

		expand(message, offset);

		for (int t = 0; t < 64; ++t) {
			int t1 = imt[7] + sum1(imt[4]) + ch(imt[4], imt[5], imt[6]) + CONSTANT[t] + W[t];
			int t2 = sum0(imt[0]) + maj(imt[0], imt[1], imt[2]);

			imt[7] = imt[6];
			imt[6] = imt[5];
			imt[5] = imt[4];
			imt[4] = imt[3] + t1;
			imt[3] = imt[2];
			imt[2] = imt[1];
			imt[1] = imt[0];
			imt[0] = t1 + t2;
		}

		for (int i = 0; i < 8; ++i) {
			chain[i] += imt[i];
		}
	}

	private static int ch(int x, int y, int z) {
		return (x & y) ^ (~x & z);
	}

	private static int maj(int x, int y, int z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}

	private static int rotr(int x, int rot) {
		return (x >>> rot) | (x << (32 - rot));
	}

	private static int sum0(int x) {
		return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
	}

	private static int sum1(int x) {
		return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
	}

	private static int sigma0(int x) {
		return rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
	}

	private static int sigma1(int x) {
		return rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10);
	}

	private void expand(byte[] message, int offset) {
		DataConversions.bs2is_be(message, offset, W, 0, 16);

		for (int t = 16; t < 64; ++t) {
			W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
		}
	}

}
