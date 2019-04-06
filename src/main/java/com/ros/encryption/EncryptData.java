package com.test;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public final class EncryptData
{
	
	public static void main(String[] args) {
		String encrypData = "12324234234234345";
		
		try {
			Map<String, String> encryptedData = EncryptData.encryptSoPin(encrypData);
			
			System.out.println(encryptedData);
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static Cipher initialize(byte[] salt, boolean encryptFlag) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		/* Getting key value from resource bundle */
		String keyValue = "761A8A65DA156D24FF2A093277530143";

		// Derive the secret key specification with given key
		SecretKeySpec keySpec = new SecretKeySpec(keyValue.getBytes("UTF-8"), "AES");
		// Derive the Iv parameter specification with given salt
		IvParameterSpec ivSpec = new IvParameterSpec(salt);

		if (encryptFlag)
		{
			Cipher encCipher = Cipher.getInstance("AES/CFB8/NoPadding");
			System.out.println(encCipher.getMaxAllowedKeyLength("AES"));
			encCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
			return encCipher;
		}
		else
		{
			Cipher decCipher = Cipher.getInstance("AES/CFB8/NoPadding");
			decCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
			return decCipher;
		}

	}

	public static byte[] encrypt(Cipher encCipher, byte[] data) throws IllegalBlockSizeException, BadPaddingException
	{
		return encCipher.doFinal(data);
	}

	public static byte[] decrypt(Cipher decCipher, byte[] data) throws IllegalBlockSizeException, BadPaddingException
	{
		return decCipher.doFinal(data);
	}

	public static byte[] getNextSalt() throws Exception
	{
		byte[] salt = new byte[16];
		try
		{
			new Random().nextBytes(salt);
		}
		catch (Exception e)
		{
		 throw e;
		}
		return salt;
	}

	public static Map<String, String> encryptSoPin(String soPin) throws Exception
	{
		HashMap<String, String> encryptHashMap = new HashMap<>();

		try
		{
			byte[] salt = getNextSalt();
			byte[] originalData = soPin.getBytes();

			/** Encryption process started */
			Cipher encCipher = EncryptData.initialize(salt, true);
			byte[] encryptedData = EncryptData.encrypt(encCipher, originalData);
			/** Encryption process completed */

			/** Encode encrypted values */
			String finalEncryptedValue = new BASE64Encoder().encode(encryptedData);
			String finalSaltValue = new BASE64Encoder().encode(salt);

			encryptHashMap.put("ENCRYPTED_SOPIN", finalEncryptedValue);
			encryptHashMap.put("ENCODED_SALT", finalSaltValue);
		}
		catch (Exception e)
		{
			
			throw e;
		}
		return encryptHashMap;
	}

	public static String decryptSoPin(String encryptedSoPin, String encodedSalt) throws Exception
	{

		String decryptedString = null;
		try
		{
			/* Decode encrypted values */
			byte[] finalDecodedValue = new BASE64Decoder().decodeBuffer(encryptedSoPin);
			byte[] finalDecodedSaltValue = new BASE64Decoder().decodeBuffer(encodedSalt);

			/* Decryption process started */
			Cipher decCipher = EncryptData.initialize(finalDecodedSaltValue, false);
			byte[] decryptedData = EncryptData.decrypt(decCipher, finalDecodedValue);
			/* Decryption process completed */

			decryptedString = new String(decryptedData);
		}
		catch (Exception e)
		{
			
			throw e;
		}
		return decryptedString;
	}

	private static String encryptRSA(String data, String publicKeyString) throws Exception
	{
		byte[] cipherText = null;
		String encryptedSOPin = null;
		try
		{
			byte[] publicKeyBytes = new BASE64Decoder().decodeBuffer(publicKeyString);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
			PublicKey newPublicKey = keyFactory.generatePublic(publicKeySpec);

			// get an RSA cipher object
			final Cipher cipher = Cipher.getInstance("RSA");
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, newPublicKey);
			cipherText = cipher.doFinal(data.getBytes());

			encryptedSOPin = new BASE64Encoder().encode(cipherText);
		}
		catch (Exception e)
		{
			throw e;
		}
		return encryptedSOPin;
	}

	
	public static String encryptDecryptedSoPin(String soPinTrs, String saltTrs, String publicKey) throws Exception
	{
		String finalSoPin = null;

		if (publicKey != null)
		{
			String decryptedSoPin = EncryptData.decryptSoPin(soPinTrs, saltTrs);
			if (decryptedSoPin.contains("SOPIN"))
			{
				String encryptDecryptedSOPin = EncryptData.encryptRSA(decryptedSoPin.replace("SOPIN", ""), publicKey);
				if (encryptDecryptedSOPin != null)
				{
					finalSoPin = encryptDecryptedSOPin;
				}
				else
				{
					throw new Exception();
				}
			}
			else
			{
				throw new Exception();
			}
		}
		else
		{
		}
		return finalSoPin;

	}

}

