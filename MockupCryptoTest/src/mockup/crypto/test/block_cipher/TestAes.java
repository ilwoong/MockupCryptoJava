package mockup.crypto.test.block_cipher;

import mockup.crypto.block_cipher.Aes;
import mockup.crypto.test.block_cipher.TestCipher.BlockCipherTestVector;

public class TestAes {

	public static void run() {
		test128();
		test192();
		test256();
	}

	public static void test128() {

		var mk = "2b7e1516 28aed2a6 abf71588 09cf4f3c";
		var pt = "3243f6a8885a308d313198a2e0370734";
		var ct = "3925841d02dc09fbdc118597196a0b32";
		var tv = new BlockCipherTestVector(mk, pt, ct);

		var cipher = new Aes();
		TestCipher.testCipher(cipher, tv);
	}

	public static void test192() {
		var mk = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
		var pt = "6bc1bee22e409f96e93d7e117393172a";
		var ct = "bd334f1d6e45f25ff712a214571fa5cc";
		var tv = new BlockCipherTestVector(mk, pt, ct);

		var cipher = new Aes();
		TestCipher.testCipher(cipher, tv);
	}

	public static void test256() {
		var mk = "603deb1015ca71be2b73aef0857d7781 1f352c07 3b6108d72d9810a30914dff4";
		var pt = "6bc1bee22e409f96e93d7e117393172a";
		var ct = "f3eed1bdb5d2a03c064b5a7e3db181f8";
		var tv = new BlockCipherTestVector(mk, pt, ct);

		var cipher = new Aes();
		TestCipher.testCipher(cipher, tv);
	}

}
