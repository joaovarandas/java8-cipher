package br.com.joaovarandas.cipher;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

abstract class BasicAsymmetricEngine {
	
	protected abstract String getAlgorithm();

	private KeyFactory keyFactory;

	protected KeyFactory getKeyFactory() throws CipherException {
		try {
			if (keyFactory == null)
				keyFactory = KeyFactory.getInstance(getAlgorithm());

		} catch (NoSuchAlgorithmException e) {
			throw new CipherException("error.cipher.algorithm", e);

		}

		return keyFactory;
	}
	

	/**
	 * Generate a new KeyPair (public/private keys)
	 * 
	 * @return PrivateKey
	 * @throws CipherException 
	 */
	public final PrivateKey generateKey() throws CipherException {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(getAlgorithm());
			keyGen.initialize(2048, new SecureRandom());
			
			return keyGen.generateKeyPair().getPrivate();
			
		} catch (NoSuchAlgorithmException e) {
			throw new CipherException("error.cipher.algorithm", e);

		}
	}
	
	public final PublicKey getPublicKey(PrivateKey privateKey) throws CipherException {
		try {
			RSAPrivateCrtKey privk = (RSAPrivateCrtKey) privateKey;
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());
			
			KeyFactory keyFactory = KeyFactory.getInstance(getAlgorithm());
		    PublicKey publicKey = keyFactory.generatePublic(keySpec);
		    
		    return publicKey;

		} catch (NoSuchAlgorithmException e) {
			throw new CipherException("error.cipher.algorithm", e);

		} catch (InvalidKeySpecException e) {
			throw new CipherException("error.cipher.invalidkey", e);
		}
	}

	/**
	 * Obtain a PublicKey Instance from a byte array Used in encryption
	 * 
	 * @param publicKeyBytes
	 * @return PublicKey
	 * 
	 * @throws CipherException
	 */
	public final PublicKey getPublicKey(byte[] publicKeyBytes) throws CipherException {
		try {
			KeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
			PublicKey publicKey = getKeyFactory().generatePublic(keySpec);

			return publicKey;

		} catch (InvalidKeySpecException e) {
			throw new CipherException("error.cipher.invalidkey", e);

		}
	}

	/**
	 * Obtain a PrivateKey Instance from a byte array Used in decryption
	 * 
	 * @param privateKeyBytes
	 * @return PrivateKey
	 * 
	 * @throws CipherException
	 */
	public final PrivateKey getPrivateKey(byte[] privateKeyBytes) throws CipherException {
		try {
			KeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			PrivateKey privateKey = getKeyFactory().generatePrivate(keySpec);

			return privateKey;

		} catch (InvalidKeySpecException e) {
			throw new CipherException("error.cipher.invalidkey", e);

		}
	}
}
