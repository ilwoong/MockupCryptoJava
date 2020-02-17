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

package mockup.crypto.mode;

import java.util.Arrays;

import mockup.crypto.BufferedBlockCipher;
import mockup.crypto.util.ByteArray;

public class CbcMode extends BufferedBlockCipher {

	private byte[] initialIv;
	private byte[] workingIv;
	private byte[] xorbuffer;

	@Override
	public String getName() {
		return "CBC/" + cipher.getName();
	}

	@Override
	protected void restoreToInitialState() {
		Arrays.fill(xorbuffer, (byte) 0);
		System.arraycopy(initialIv, 0, workingIv, 0, blocksize);
	}

	@Override
	protected void init(byte[] iv) {
		xorbuffer = new byte[blocksize];
		initialIv = new byte[blocksize];
		workingIv = new byte[blocksize];

		System.arraycopy(iv, 0, initialIv, 0, blocksize);
		System.arraycopy(iv, 0, workingIv, 0, blocksize);
	}

	@Override
	public void updateBlock(byte[] src, int srcpos, byte[] dst, int dstpos) {
		if (cipherMode == CipherMode.ENCRYPT) {
			ByteArray.xor(xorbuffer, 0, workingIv, 0, src, srcpos, blocksize);
			cipher.encryptBlock(xorbuffer, 0, workingIv, 0);
			System.arraycopy(workingIv, 0, dst, dstpos, blocksize);

		} else {
			cipher.decryptBlock(src, srcpos, xorbuffer, 0);
			ByteArray.xor(dst, dstpos, xorbuffer, 0, workingIv, 0, blocksize);
			System.arraycopy(src, srcpos, workingIv, 0, blocksize);
		}
	}
}
