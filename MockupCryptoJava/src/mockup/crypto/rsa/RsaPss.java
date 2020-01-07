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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import mockup.crypto.Hash;
import mockup.crypto.util.ByteArray;

/**
 * RSASSA-PSS Implementation based on RFC 3447
 * 
 * @author ilwoong
 */
public class RsaPss {

	private static final byte[] PADDING = new byte[8];
	private static final byte[] ONE = { 0x1 };
	private static final byte[] BC = { (byte) 0xbc };

	private Random _rand;
	private Hash _hash;
	private MaskGenerationFunction _mgf;
	private int _saltLen;
	private int _emLen;

	private BigInteger _privModulus;
	private BigInteger _privExponent;

	public RsaPss() {
		_rand = new SecureRandom();
		_hash = Hash.getInstance("SHA-256");
		_mgf = new MaskGenerationFunction();
		_mgf.init("SHA-256");
		_saltLen = 20;
		_emLen = 2048 / 8;
	}

	public byte[] sign(byte[] msg) {
		byte[] encoded = pssEncode(msg);
		var s = RsaPrimitive.rsaep(_privModulus, _privExponent, new BigInteger(encoded));
		return s.toByteArray();
	}

	public boolean verify(byte[] msg, byte[] encodedMessage) {
		if (encodedMessage[encodedMessage.length - 1] != BC[0]) {
			throw new IllegalArgumentException("Invalid signature tail");
		}

		if (encodedMessage.length < _hash.getOutputLength() + _saltLen + 2) {
			throw new IllegalArgumentException("Invalid signature length");
		}

		var mHash = digest(msg);
		var maskedDB = ByteArray.left(encodedMessage, encodedMessage.length - _hash.getOutputLength() - 1);
		var H = ByteArray.extract(encodedMessage, maskedDB.length, _hash.getOutputLength());
		var db = _mgf.applyMask(maskedDB, H, maskedDB.length);

		var salt = ByteArray.extract(db, db.length - _saltLen, _saltLen);

		var mHashToBeCompared = digestWithPadAndSalt(msg, salt);

		return Arrays.equals(mHash, mHashToBeCompared);
	}

	private byte[] digest(byte[]... args) {
		_hash.reset();
		for (byte[] arg : args) {
			_hash.update(arg);
		}
		return _hash.doFinal();
	}

	public byte[] digestWithPadAndSalt(byte[] msg, byte[] salt) {
		byte[] mHash = digest(msg);
		return digest(PADDING, mHash, salt);
	}

	private byte[] pssEncode(byte[] msg) {
		var salt = new byte[_saltLen];
		_rand.nextBytes(salt);

		var H = digestWithPadAndSalt(msg, salt);

		var ps = new byte[_emLen - _saltLen - _hash.getOutputLength() - 2];
		var db = ByteArray.merge(ps, ONE, salt);
		var maskedDB = _mgf.applyMask(db, H, db.length);
		var em = ByteArray.merge(maskedDB, H, BC);

		return em;
	}

}
