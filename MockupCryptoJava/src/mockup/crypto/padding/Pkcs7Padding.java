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

package mockup.crypto.padding;

import java.util.Arrays;

import mockup.crypto.Padding;
import mockup.crypto.util.ByteArray;

public class Pkcs7Padding extends Padding {

	public Pkcs7Padding(int blocksize) {
		super(blocksize);
	}

	@Override
	public String getName() {
		return "PKCS7-Padding";
	}

	@Override
	public byte[] pad(byte[] in, int length) {
		var pad = blocksize - (length % blocksize);
		var buffer = new byte[length + pad];

		System.arraycopy(in, 0, buffer, 0, length);
		Arrays.fill(buffer, length, buffer.length, (byte) pad);
		
		return buffer;
	}

	public byte[] unpad(byte[] in) {
		var pad = in[in.length - 1];

		if (pad < 0 || pad > blocksize) {
			throw new InvalidPaddingException("Wrong padding size: " + pad);
		}

		for (int i = in.length - 1; i >= in.length - pad; --i) {
			if (in[i] != pad) {
				throw new InvalidPaddingException("Wrong padding value");
			}
		}

		var buffer = new byte[in.length - pad];
		System.arraycopy(in, 0, buffer, 0, in.length - pad);
		return buffer;
	}
}
