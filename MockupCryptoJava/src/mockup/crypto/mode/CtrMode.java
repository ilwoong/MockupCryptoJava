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

public class CtrMode extends BufferedBlockCipher {

	private byte[] initialCounter;
	private byte[] workingCounter;
	private byte[] keystream;

	@Override
	public String getName() {
		return "CTR/" + cipher.getName();
	}

	@Override
	protected void restoreToInitialState() {
		System.arraycopy(initialCounter, 0, workingCounter, 0, blocksize);
		Arrays.fill(keystream, (byte) 0);
	}

	@Override
	protected void init(byte[] iv) {
		if (iv == null || iv.length != blocksize) {
			throw new IllegalArgumentException("Unsupported initial counter length");
		}

		keystream = new byte[blocksize];

		initialCounter = new byte[blocksize];
		workingCounter = new byte[blocksize];
		System.arraycopy(iv, 0, initialCounter, 0, blocksize);
		System.arraycopy(iv, 0, workingCounter, 0, blocksize);
	}

	@Override
	public void updateBlock(byte[] src, int srcpos, byte[] dst, int dstpos) {
		cipher.encryptBlock(workingCounter, 0, keystream, 0);
		ByteArray.xor(dst, dstpos, src, srcpos, keystream, 0, blocksize);
		increaseCounter();
	}

	private void increaseCounter() {
		var idx = workingCounter.length - 1;
		while (++workingCounter[idx] == 0) {
			idx -= 1;

			if (idx < 0) {
				idx = workingCounter.length - 1;
			}
		}
	}
}
