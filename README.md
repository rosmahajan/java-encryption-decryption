# java-encryptiondecryption
AES encryption and decryption using salt.

This Java program shows how we can encrypt the String and how salt can be used to decrpyt it and get the orginal value back.

# Persist
Persist the encrypted value in database rather than plain text with salt value. Decryption always require encrypted data with salt value. Tempering the salt value won't give original value which ensure the data remains secured.
