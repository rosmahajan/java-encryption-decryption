package com.ros.utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptDecryptUtils {

	public static Cipher initialize(byte[] salt, boolean encryptFlag) throws UnsupportedEncodingException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		String keyValue = "761A8A65DA156D24FF2A093277530143";

		// Derive the secret key specification with given key
		SecretKeySpec keySpec = new SecretKeySpec(keyValue.getBytes("UTF-8"), "AES");
		// Derive the Iv parameter specification with given salt
		IvParameterSpec ivSpec = new IvParameterSpec(salt);

		if (encryptFlag) {
			Cipher encCipher = Cipher.getInstance("AES/CFB8/NoPadding");
			encCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
			return encCipher;
		} else {
			Cipher decCipher = Cipher.getInstance("AES/CFB8/NoPadding");
			decCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
			return decCipher;
		}

	}

	public static byte[] encrypt(Cipher encCipher, byte[] data) throws IllegalBlockSizeException, BadPaddingException {
		return encCipher.doFinal(data);
	}

	public static byte[] decrypt(Cipher decCipher, byte[] data) throws IllegalBlockSizeException, BadPaddingException {
		return decCipher.doFinal(data);
	}

	public static byte[] getNextSalt() throws Exception {
		byte[] salt = new byte[16];
		try {
			new Random().nextBytes(salt);
		} catch (Exception e) {
			throw e;
		}
		return salt;
	}
}
