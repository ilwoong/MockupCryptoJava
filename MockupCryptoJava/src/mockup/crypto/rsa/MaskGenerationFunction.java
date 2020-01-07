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

package mockup.crypto.rsa;

import java.io.ByteArrayOutputStream;

import mockup.crypto.Hash;
import mockup.crypto.util.ByteArray;
import mockup.crypto.util.DataConversions;

public class MaskGenerationFunction {

	private Hash _hash;

	public void init(String hashName) {
		_hash = Hash.getInstance(hashName);
	}

	public byte[] generate(byte[] mgfSeed, int maskLen) {
		ByteArrayOutputStream mask = new ByteArrayOutputStream();

		int maxCounter = (int) Math.ceil((double)maskLen / _hash.getOutputLength());
		
		System.out.println("maxcounter = " + maxCounter);

		for (int counter = 0; counter < maxCounter; ++counter) {
			byte[] d = DataConversions.i2bs(counter, 4);

			_hash.reset();
			_hash.update(mgfSeed);
			byte[] digest = _hash.doFinal(d);

			mask.writeBytes(digest);
		}

		return mask.toByteArray();
	}

	public byte[] applyMask(byte[] data, byte[] mgfSeed, int maskLen) {
		byte[] mask = generate(mgfSeed, maskLen);
		return ByteArray.xor(data, mask);
	}

}
