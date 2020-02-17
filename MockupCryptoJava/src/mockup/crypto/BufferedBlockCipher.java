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

package mockup.crypto;

import java.util.Arrays;

import mockup.crypto.util.ByteArray;

public abstract class BufferedBlockCipher implements NamedAlgorithm {

	public enum CipherMode {
		ENCRYPT, DECRYPT
	}

	protected CipherMode cipherMode;
	protected BlockCipher cipher;
	protected byte[] buffer;
	protected int offset;
	protected int blocksize;
	protected int shift;

	private Padding padding;

	public void init(CipherMode mode, BlockCipher cipher, byte[] mk, byte[] iv) {
		this.cipherMode = mode;
		this.cipher = cipher;
		cipher.init(mk);
		blocksize = cipher.getBlocksize();
		shift = blocksize;
		buffer = new byte[shift];

		init(iv);
	}

	public void setPadding(Padding padding) {
		this.padding = padding;
	}

	protected void reset() {
		offset = 0;
		Arrays.fill(buffer, (byte) 0);

		restoreToInitialState();
	}

	protected abstract void restoreToInitialState();

	protected abstract void init(byte[] iv);

	public void setShift(int shift) {

		if (shift > blocksize) {
			throw new IllegalArgumentException("shift should be less or equal to " + blocksize);
		}
		this.shift = shift;
	}

	public byte[] update(final byte[] msg) {
		if (msg == null || msg.length == 0) {
			return null;
		}

		var msgpos = 0;
		var dstpos = 0;
		var length = msg.length;

		var dst = getUpdateBuffer(msg.length);

		if (offset > 0) {
			var gap = Math.min(length, shift - offset);

			System.arraycopy(msg, 0, buffer, offset, gap);

			msgpos += gap;
			offset += gap;
			length -= gap;

			if (offset == shift) {
				updateBlock(buffer, 0, dst, 0);

				dstpos += shift;
				offset = 0;
			}
		}

		while (length >= shift) {
			if ((padding != null) && (cipherMode == CipherMode.DECRYPT) && (length == shift)) {
				break;
			}

			updateBlock(msg, msgpos, dst, dstpos);

			msgpos += shift;
			dstpos += shift;
			length -= shift;
		}

		if (length > 0) {
			System.arraycopy(msg, msgpos, buffer, offset, length);
			offset += length;
		}

		return dst;
	}

	public byte[] getUpdateBuffer(int length) {

		var count = length + offset;

		if (count < shift) {
			return null;
		}

		if (padding != null && cipherMode == CipherMode.DECRYPT) {
			return new byte[count - shift];
		}

		return new byte[count - (count % shift)];
	}

	public abstract void updateBlock(final byte[] src, int srcpos, byte[] dst, int dstpos);

	public byte[] doFinal(final byte[] msg) {
		var head = update(msg);
		var tail = doFinal();

		return ByteArray.merge(head, tail);
	}

	public byte[] doFinal() {
		return padding == null ? doFinalWithoutPadding() : doFinalWithPadding();
	}

	private byte[] doFinalWithPadding() {
		byte[] dst = null;

		if (cipherMode == CipherMode.ENCRYPT) {
			var padded = padding.pad(buffer, offset);
			dst = new byte[padded.length];
			updateBlock(padded, 0, dst, 0);
			// cipher.decryptBlock(padded, 0, dst, 0);

		} else {
			var padded = new byte[blocksize];
			updateBlock(buffer, 0, padded, 0);
			// cipher.decryptBlock(buffer, 0, padded, 0);
			dst = padding.unpad(padded);
		}

		reset();

		return dst;
	}

	private byte[] doFinalWithoutPadding() {
		byte[] tail = null;

		if (offset > 0) {
			var tmp = new byte[blocksize];
			updateBlock(buffer, 0, tmp, 0);

			tail = Arrays.copyOfRange(tmp, 0, offset);
			offset = 0;
		}

		reset();

		return tail;
	}

}
