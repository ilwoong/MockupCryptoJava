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

package mockup.crypto.util;

import java.io.ByteArrayOutputStream;

public class ByteArray {

	public static byte[] left(byte[] lhs, int count) {
		if (lhs.length < count) {
			throw new IllegalArgumentException("byte array is too short");
		}

		byte[] subbytes = new byte[count];
		System.arraycopy(lhs, 0, subbytes, 0, count);

		return subbytes;
	}

	public static byte[] extract(byte[] org, int offset, int count) {
		if (org.length < offset + count) {
			throw new IllegalArgumentException("byte array is too short");
		}

		byte[] subbytes = new byte[count];
		System.arraycopy(org, offset, subbytes, 0, count);
		return subbytes;
	}

	public static byte[] merge(byte[]... args) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		for (byte[] arg : args) {
			if (arg != null) {
				baos.writeBytes(arg);
			}
		}

		return baos.toByteArray();
	}

	public static byte[] getXoredBytes(byte[] lhs, byte[] rhs) {
		if (lhs == null || rhs == null) {
			throw new IllegalArgumentException("null array is not allowed");
		}

		return getXoredBytes(lhs, rhs, lhs.length);
	}

	public static byte[] getXoredBytes(byte[] lhs, byte[] rhs, int count) {
		byte[] dst = new byte[count];
		xor(dst, 0, lhs, 0, rhs, 0, count);
		return dst;
	}

	public static void xor(byte[] dst, int dstoff, final byte[] lhs, int lhsoff, final byte[] rhs, int rhsoff,
			int count) {

		if (dst == null || lhs == null || rhs == null) {
			throw new IllegalArgumentException("null array is not allowed");
		}

		if ((dst.length < dstoff + count) || (lhs.length < lhsoff + count) || (rhs.length < rhsoff + count)) {
			var msg = String.format("%d, %d, %d", dst.length, lhs.length, rhs.length);
			throw new IllegalArgumentException("wrong array length: " + msg);
		}

		for (int i = 0; i < count; ++i) {
			dst[dstoff + i] = (byte) (lhs[lhsoff + i] ^ rhs[rhsoff + i]);
		}
	}

	public static String toString(byte[] bs) {
		if (bs == null) {
			return null;
		}

		StringBuilder sb = new StringBuilder();

		var count = 0;
		for (byte d : bs) {
			sb.append(String.format("%02x", d));
			count += 1;
			if ((count & 0x3) == 0) {
				sb.append(" ");
			}
		}

		return sb.toString();
	}

	public static byte[] toByteArray(String hexString) {
		if (hexString == null) {
			return null;
		}

		hexString = hexString.replace(" ", "");

		byte[] buf = new byte[hexString.length() / 2];

		for (int i = 0; i < buf.length; ++i) {
			buf[i] = (byte) (16 * decode(hexString.charAt(i * 2)));
			buf[i] += decode(hexString.charAt(i * 2 + 1));
		}

		return buf;
	}

	private static final byte decode(char ch) {
		if (ch >= '0' && ch <= '9') {
			return (byte) (ch - '0');
		}

		if (ch >= 'a' && ch <= 'f') {
			return (byte) (ch - 'a' + 10);
		}

		if (ch >= 'A' && ch <= 'F') {
			return (byte) (ch - 'A' + 10);
		}

		return 0;
	}
}
