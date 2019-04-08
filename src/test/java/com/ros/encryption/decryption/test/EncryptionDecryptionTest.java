package com.ros.encryption.decryption.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.Map;

import org.junit.Test;

import com.ros.decryption.DecryptData;
import com.ros.encryption.EncryptData;

public class EncryptionDecryptionTest {

	@Test
	public void testEncryptData() {
		String encryptData = "1234";
		try {
			Map<String, String> encryptedData = EncryptData.encryptData(encryptData);
			
			assertNotNull(encryptedData);
			String deString = DecryptData.decryptData(encryptedData.get("ENCRYPTED_DATA"), encryptedData.get("ENCODED_SALT"));
			assertEquals(deString, encryptData);

		} catch (Exception e) {
			fail("Did not expected an exception got an exception "+e.getMessage());
		}
	}
}
