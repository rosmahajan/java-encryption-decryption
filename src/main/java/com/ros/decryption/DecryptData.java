package com.ros.decryption;

import javax.crypto.Cipher;

import com.ros.utils.EncryptDecryptUtils;

import sun.misc.BASE64Decoder;

public class DecryptData {

	@SuppressWarnings("restriction")
	public static String decryptData(String encryptedDataToDecrypt, String encodedSalt) throws Exception {

		String decryptedString = null;
		try {
			/* Decode encrypted values */
			byte[] finalDecodedValue = new BASE64Decoder().decodeBuffer(encryptedDataToDecrypt);
			byte[] finalDecodedSaltValue = new BASE64Decoder().decodeBuffer(encodedSalt);

			/* Decryption process started */
			Cipher decCipher = EncryptDecryptUtils.initialize(finalDecodedSaltValue, false);
			byte[] decryptedData = EncryptDecryptUtils.decrypt(decCipher, finalDecodedValue);
			/* Decryption process completed */

			decryptedString = new String(decryptedData);
		} catch (Exception e) {

			throw e;
		}
		return decryptedString;
	}
}
