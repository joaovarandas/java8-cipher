package br.com.joaovarandas.cipher;

import org.junit.Assert;
import org.junit.Test;

public class AESTest {

	@Test
	public void simpleTest() throws CipherException  {
		
		int numberOfTests = 5;

		byte[] secret = AES.getInstance().generateSecretKey();
		
		
		final String randomString = RandomString.generate(5000);		
		final String encryptedString[] = new String[numberOfTests];
		
		for (int i = 0; i < numberOfTests; i++) {
			encryptedString[i] = AES.getInstance().encryptAsString(randomString.getBytes(), secret);
		}
			
		final String decryptedString[] = new String[numberOfTests];

		for (int i = 0; i < numberOfTests; i++) {
			decryptedString[i] = new String(AES.getInstance().decrypt(encryptedString[i], secret));
		}
		

		for (int i = 0; i < numberOfTests -1; i++) {
			Assert.assertNotEquals("Encrypted strings should be differente from each other!", encryptedString[i], encryptedString[i+1]);
			
			Assert.assertEquals("Decrypted strings must be equal!", decryptedString[i], decryptedString[i+1]);
			
		}
		
		
		System.out.println(randomString.length());
		
		
		

	}
	
}
