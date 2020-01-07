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
import java.util.Random;

import mockup.crypto.Hash;
import mockup.crypto.util.ByteArray;

/**
 * 
 * RSA with Optimal Asymmetric Encryption Padding (RSA-OAEP)
 * 
 * @author ilwoong.jeong
 *
 */
public class RsaOaep {

	private Random _rand;
	private Hash _hash;
	private MaskGenerationFunction _mgf;

	private static final byte[] ZERO = { 0, 0, 0, 0 };
	private static final byte[] ONE = { 1 };

	public void init(String hashName) {
		_rand = new SecureRandom();
		_hash = Hash.getInstance(hashName);
		_mgf = new MaskGenerationFunction();
		_mgf.init(hashName);
	}

	public byte[] encrypt(BigInteger n, BigInteger e, byte[] k, byte[] a) {
		byte[] mgfSeed = new byte[_hash.getOutputLength()]; // and make random
		_rand.nextBytes(mgfSeed);

		return encrypt(n, e, k, a, mgfSeed);
	}

	public byte[] encrypt(BigInteger n, BigInteger e, byte[] k, byte[] a, byte[] seed) {
		if (k == null || k.length == 0) {
			throw new IllegalArgumentException("keying material is null");
		}

		int nLen = Math.floorDiv(n.bitLength(), 8);
		int hashLen = _hash.getOutputLength();

		if (k.length > nLen - 2 * hashLen - 2) {
			throw new IllegalArgumentException("keying material is too long");
		}

		BigInteger em = encodeOaep(seed, k, a, nLen);

		// rsa encryption
		BigInteger c = RsaPrimitive.rsaep(n, e, em);

		return c.toByteArray();
	}

	private BigInteger encodeOaep(byte[] mgfSeed, byte[] k, byte[] a, int nLen) {
		// oaep encoding
		byte[] HA = _hash.doFinal(a);
		byte[] PS = new byte[nLen - k.length - 2 * _hash.getOutputLength() - 2];
		byte[] DB = ByteArray.merge(HA, PS, ONE, k);

		byte[] maskedDB = _mgf.applyMask(DB, mgfSeed, nLen - _hash.getOutputLength() - 1);
		byte[] maskedMGFSeed = _mgf.applyMask(mgfSeed, maskedDB, _hash.getOutputLength());

		byte[] EM = ByteArray.merge(ZERO, maskedMGFSeed, maskedDB);

		BigInteger em = new BigInteger(EM);
		return em;
	}



}
