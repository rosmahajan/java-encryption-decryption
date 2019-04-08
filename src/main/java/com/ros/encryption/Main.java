package com.ros.encryption;

import java.util.Map;

import com.ros.decryption.DecryptData;

public class Main {

	public static void main(String[] args) {
		String encryptData = "1234";

		try {
			Map<String, String> encryptedData = EncryptData.encryptData(encryptData);

			System.out.println(encryptedData);

			String deString = DecryptData.decryptData(encryptedData.get("ENCRYPTED_DATA"), encryptedData.get("ENCODED_SALT"));

			System.out.println(deString);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
