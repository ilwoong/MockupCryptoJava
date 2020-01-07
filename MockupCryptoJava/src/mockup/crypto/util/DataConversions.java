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

public class DataConversions {

	// integer to byte string
	public static byte[] i2bs(int value, int length) {
		byte[] bs = new byte[length];

		for (int i = 0; i < length; ++i) {
			bs[i] = (byte) (value & 0xff);
			value >>>= 8;
		}

		return bs;
	}

	// byte string to integer
	public static int bs2i(byte[] bs) {
		int value = 0;

		for (byte b : bs) {
			value <<= 8;
			value += b;
		}

		return value;
	}

	// integer to byte stream (Big Endian)
	public static byte[] i2bs_be(int in) {
		byte[] out = new byte[4];
		i2bs_be(in, out, 0);
		return out;
	}

	// integer to byte stream (Big Endian)
	public static void i2bs_be(int in, byte[] out, int offset) {
		out[offset++] = (byte) (in >>> 24);
		out[offset++] = (byte) (in >>> 16);
		out[offset++] = (byte) (in >>> 8);
		out[offset++] = (byte) (in);
	}

	// long to byte stream (Big Endian)
	public static byte[] l2bs_be(long in) {
		byte[] out = new byte[8];
		l2bs_be(in, out, 0);
		return out;
	}

	// long to byte stream (Big Endian)
	public static void l2bs_be(long in, byte[] out, int offset) {
		out[offset++] = (byte) (in >>> 56);
		out[offset++] = (byte) (in >>> 48);
		out[offset++] = (byte) (in >>> 40);
		out[offset++] = (byte) (in >>> 32);
		out[offset++] = (byte) (in >>> 24);
		out[offset++] = (byte) (in >>> 16);
		out[offset++] = (byte) (in >>> 8);
		out[offset++] = (byte) (in);
	}

	// integer stream to byte stream (Big Endian)
	public static byte[] is2bs_be(int[] is) {
		byte[] bs = new byte[is.length * 4];
		is2bs_be(is, 0, bs, 0, is.length);
		return bs;
	}

	// integer stream to byte stream (Big Endian)
	public static void is2bs_be(int[] in, int inoff, byte[] out, int outoff, int icount) {
		for (int i = 0; i < icount; ++i) {
			out[outoff++] = (byte) (in[inoff + i] >>> 24);
			out[outoff++] = (byte) (in[inoff + i] >>> 16);
			out[outoff++] = (byte) (in[inoff + i] >>> 8);
			out[outoff++] = (byte) (in[inoff + i]);
		}
	}

	// byte stream to integer stream (Big Endian)
	public static int[] bs2is_be(byte[] bs) {
		int[] is = new int[bs.length / 4];
		bs2is_be(bs, 0, is, 0, is.length);
		return is;
	}

	// byte stream to integer stream (Big Endian)
	public static void bs2is_be(byte[] bs, int inoff, int[] is, int outoff, int icount) {
		for (int idx = outoff; idx < outoff + icount; ++idx) {
			is[idx] = (bs[inoff++] & 0xff) << 24;
			is[idx] |= (bs[inoff++] & 0xff) << 16;
			is[idx] |= (bs[inoff++] & 0xff) << 8;
			is[idx] |= (bs[inoff++] & 0xff);
		}
	}
}
