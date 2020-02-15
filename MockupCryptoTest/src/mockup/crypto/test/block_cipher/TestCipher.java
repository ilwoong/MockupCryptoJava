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
