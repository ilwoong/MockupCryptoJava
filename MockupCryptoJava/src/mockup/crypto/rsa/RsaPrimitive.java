package mockup.crypto.rsa;

import java.math.BigInteger;

public class RsaPrimitive {
	
	// c = m^e mod n
	public static BigInteger rsaep(BigInteger modulus, BigInteger exponent, BigInteger msg) {
		if (msg.compareTo(BigInteger.ONE) == -1) {
			throw new IllegalArgumentException("msg is too small");
		}

		if (msg.compareTo(modulus) == 1) {
			throw new IllegalArgumentException("msg is too large");
		}

		return msg.modPow(exponent, modulus);
	}

	// m = c^e mod n
	public static BigInteger rsadp(BigInteger modulus, BigInteger exponent, BigInteger ct) {
		if (ct.compareTo(BigInteger.ONE) == -1) {
			throw new IllegalArgumentException("ct is too small");
		}

		if (ct.compareTo(modulus) == 1) {
			throw new IllegalArgumentException("ct is too large");
		}

		return ct.modPow(exponent, modulus);
	}

}
