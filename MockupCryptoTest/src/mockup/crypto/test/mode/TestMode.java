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

package mockup.crypto.test.mode;

import java.util.Arrays;

import mockup.crypto.BufferedBlockCipher;
import mockup.crypto.BufferedBlockCipher.CipherMode;
import mockup.crypto.block_cipher.Aes;
import mockup.crypto.mode.CbcMode;
import mockup.crypto.mode.CfbMode;
import mockup.crypto.mode.CtrMode;
import mockup.crypto.mode.EcbMode;
import mockup.crypto.mode.OfbMode;
import mockup.crypto.padding.Pkcs7Padding;
import mockup.crypto.util.ByteArray;

public class TestMode {
	public static void run() {
		testAes128();
	}

	public static void testMode(BufferedBlockCipher bbc, byte[] mk, byte[] iv, byte[] msg) {
		bbc.init(CipherMode.ENCRYPT, new Aes(), mk, iv);
		if (bbc instanceof EcbMode || bbc instanceof CbcMode) {
			bbc.setPadding(new Pkcs7Padding(16));
		}
		byte[] enc = bbc.doFinal(msg);

		bbc.init(CipherMode.DECRYPT, new Aes(), mk, iv);
		if (bbc instanceof EcbMode || bbc instanceof CbcMode) {
			bbc.setPadding(new Pkcs7Padding(16));
		}
		byte[] dec = bbc.doFinal(enc);

		System.out.println(bbc.getName() + ": " + ByteArray.toString(enc));
		if (Arrays.equals(msg, dec) == false) {
			System.out.println(bbc.getName() + ": decryption failed");
		}
	}

	public static void testAes128() {

		byte[] mk = new byte[16];
		byte[] iv = new byte[16];
		byte[] msg = new byte[54];

		for (var i = 0; i < mk.length; ++i) {
			mk[i] = (byte) i;
			iv[i] = (byte) (i + 0x10);
		}

		for (var i = 0; i < msg.length; ++i) {
			msg[i] = (byte) i;
		}

		testMode(new EcbMode(), mk, iv, msg);
		testMode(new CbcMode(), mk, iv, msg);
		testMode(new CfbMode(), mk, iv, msg);
		testMode(new OfbMode(), mk, iv, msg);
		testMode(new CtrMode(), mk, iv, msg);
	}
}
