package com.ros.encryption;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ros.utils.EncryptDecryptUtils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public final class EncryptData
{
	
	@SuppressWarnings("restriction")
	public static Map<String, String> encryptData(String dataForEncryption) throws Exception
	{
		HashMap<String, String> encryptHashMap = new HashMap<String, String>();

		try
		{
			byte[] salt = EncryptDecryptUtils.getNextSalt();
			byte[] originalData = dataForEncryption.getBytes();

			/** Encryption process started */
			Cipher encCipher = EncryptDecryptUtils.initialize(salt, true);
			byte[] encryptedData = EncryptDecryptUtils.encrypt(encCipher, originalData);
			/** Encryption process completed */

			/** Encode encrypted values */
			String finalEncryptedValue = new BASE64Encoder().encode(encryptedData);
			String finalSaltValue = new BASE64Encoder().encode(salt);

			encryptHashMap.put("ENCRYPTED_DATA", finalEncryptedValue);
			encryptHashMap.put("ENCODED_SALT", finalSaltValue);
		}
		catch (Exception e)
		{
			
			throw e;
		}
		return encryptHashMap;
	}
}

