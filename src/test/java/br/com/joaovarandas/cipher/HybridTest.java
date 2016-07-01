package br.com.joaovarandas.cipher;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Assert;
import org.junit.Test;

public class HybridTest {

	@Test
	public void hybridTest() throws CipherException {
		
		byte[] sampleData = RandomString.generate(5000).getBytes();
		
		PrivateKey privateKey = RSA.getInstance().generateKey();
		PublicKey publicKey = RSA.getInstance().getPublicKey(privateKey);
		
		byte[] encryptedData = Hybrid.getInstance().encrypt(sampleData, publicKey.getEncoded());
		
		byte[] decryptedData = Hybrid.getInstance().decrypt(encryptedData, privateKey.getEncoded());
		
		Assert.assertArrayEquals(sampleData, decryptedData);
		
		
	}
}
