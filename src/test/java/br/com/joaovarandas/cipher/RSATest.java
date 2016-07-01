package br.com.joaovarandas.cipher;

import java.security.PrivateKey;

import org.junit.Assert;
import org.junit.Test;

public class RSATest {

	@Test
	public void fullTest() throws CipherException  {
		
		int numberOfTests = 5;
		PrivateKey privateKey = RSA.getInstance().generateKey();
		
		
		final String randomString = RandomString.generate(128);
		final String encryptedString[] = new String[numberOfTests];
		
		final byte[] privKeyBytes = privateKey.getEncoded();
		final String signatureData = RSA.getInstance().signAsString(randomString.getBytes(), privKeyBytes);
		
		for (int i = 0; i < numberOfTests; i++) {
			byte[] publicKey = RSA.getInstance().getPublicKey(privateKey).getEncoded();
			
			encryptedString[i] = RSA.getInstance().encryptAsString(randomString.getBytes(), publicKey);
			
			Assert.assertTrue("Message signature is invalid.", RSA.getInstance().validateSign(randomString.getBytes(), signatureData, publicKey));
		}
			
		
		final String decryptedString[] = new String[numberOfTests];

		for (int i = 0; i < numberOfTests; i++) {
			decryptedString[i] = new String(RSA.getInstance().decrypt(encryptedString[i], privKeyBytes));
		}
		

		for (int i = 0; i < numberOfTests -1; i++) {
			Assert.assertNotEquals("Encrypted strings should be differente from each other!", encryptedString[i], encryptedString[i+1]);
			
			Assert.assertEquals("Decrypted strings must be equal!", decryptedString[i], decryptedString[i+1]);
			
		}

		
		
		
		
		
		

		
		

	}
	
}
