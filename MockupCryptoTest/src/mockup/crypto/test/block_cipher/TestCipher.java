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

package mockup.crypto.test.block_cipher;

import java.util.Arrays;

import mockup.crypto.BlockCipher;
import mockup.crypto.util.ByteArray;

public class TestCipher {

	public static class BlockCipherTestVector {
		public final byte[] mk;
		public final byte[] pt;
		public final byte[] ct;

		public BlockCipherTestVector(String mk, String pt, String ct) {
			this.mk = ByteArray.toByteArray(mk);
			this.pt = ByteArray.toByteArray(pt);
			this.ct = ByteArray.toByteArray(ct);
		}
	}

	public static void testCipher(BlockCipher cipher, BlockCipherTestVector tv) {

		byte[] enc = new byte[cipher.getBlocksize()];
		byte[] dec = new byte[cipher.getBlocksize()];

		cipher.init(tv.mk);
		cipher.encryptBlock(tv.pt, 0, enc, 0);
		cipher.decryptBlock(tv.ct, 0, dec, 0);

		var isEncPassed = Arrays.equals(tv.ct, enc);
		var isDecPassed = Arrays.equals(tv.pt, dec);

		System.out.println(cipher.getName() + " encryption: " + isEncPassed);
		if (isEncPassed == false) {
			System.out.println("\t ct: " + ByteArray.toString(tv.ct));
			System.out.println("\tenc: " + ByteArray.toString(enc));
		}

		System.out.println(cipher.getName() + " decryption: " + isDecPassed);
		if (isDecPassed == false) {
			System.out.println("\t pt: " + ByteArray.toString(tv.pt));
			System.out.println("\tdec: " + ByteArray.toString(dec));
		}
		System.out.println();
	}

}
