/*
The MIT License (MIT)
Copyright (c) 2016 João Paulo Varandas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */
package br.com.joaovarandas.cipher;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.migcomponents.migbase64.Base64;

/**
 * AES Helper Class (Singleton) to simplify the encrypting/decrypting proccess
 * in Java See https://github.com/joaovarandas for more examples
 * 
 * @author jpvarandas
 *
 */
public class AES {

	private final static String AESCBCPKCS5Padding = "AES/CBC/PKCS5Padding";
	private final static String AES = "AES";
	
	private final static int SEED_LENGTH = 16;
	private final static int PWD_LENGTH = 16;
	
	private final static AES instance = new AES();
	
	/**
	 * Obtain an instance of AES object
	 * 
	 * @return A singleton instance
	 */
	public static AES getInstance() {
		return instance;
	}

	private final SecureRandom secureRandom = new SecureRandom();
	
	private byte[] getRandomSeed() {
		return secureRandom.generateSeed(SEED_LENGTH);
	}
	
	/**
	 * Initiates the Cipher engine
	 * 
	 * @param mode
	 * @param key
	 * @return
	 * @throws CipherException
	 */
	protected Cipher getCipher(int mode, Key key, AlgorithmParameterSpec paramSpec) throws CipherException {
		final Cipher cipher;

		try {
			cipher = Cipher.getInstance(AESCBCPKCS5Padding);
			cipher.init(mode, key, paramSpec);

		} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
			throw new CipherException("error.cipher.algorithm", e);

		} catch (NoSuchPaddingException e) {
			throw new CipherException("error.cipher.padding", e);

		} catch (InvalidKeyException e) {
			throw new CipherException("error.cipher.invalidkey", e);

		} finally {

		}

		return cipher;
	}

	/**
	 * Create a 256-bit AES Secret Key and return as a byte[] array
	 * 
	 * @return byte[]
	 * @throws CipherException
	 */
	public byte[] generateSecretKey() throws CipherException {
		try {
			KeyGenerator gen = KeyGenerator.getInstance(AES); 			
		    gen.init(128, new SecureRandom());
		    
		    return gen.generateKey().getEncoded();

		} catch (NoSuchAlgorithmException e) {
			throw new CipherException("error.cipher.algorithm", e);
			
		} finally {
			
		}
	}
	
	/**
	 * Encrypt the data using AES algorithm and the provided secretKey
	 * 
	 * @param data
	 * @param secretKeyBytes
	 * 
	 * @return byte[]
	 * @throws CipherException
	 */
	public byte[] encrypt(byte[] data, byte[] secretKeyBytes) throws CipherException {
		try {
			SecretKey secretKey = new SecretKeySpec(secretKeyBytes, AES);

			byte[] seed = getRandomSeed();
			AlgorithmParameterSpec paramSpec = new IvParameterSpec(seed);

			byte[] encryptedMessageBytes = getCipher(Cipher.ENCRYPT_MODE, secretKey, paramSpec).doFinal(data);

			byte[] bytesToEncode = new byte[seed.length + encryptedMessageBytes.length];
			System.arraycopy(seed, 0, bytesToEncode, 0, seed.length);
			System.arraycopy(encryptedMessageBytes, 0, bytesToEncode, seed.length, encryptedMessageBytes.length);
			return bytesToEncode;
			
		} catch (BadPaddingException e) {
			throw new CipherException("error.cipher.padding", e);
			
		} catch (IllegalBlockSizeException e) {
			throw new CipherException("error.cipher.padding", e);
			
		}
	}
	
	/**
	 * Encrypt the data using AES algorithm and the provided secretKey and return a Base64
	 * 
	 * @param data
	 * @param secretKeyBytes
	 * @return String
	 * @throws CipherException
	 */
	public String encryptAsString(byte[] data, byte[] secretKeyBytes) throws CipherException {
		return Base64.encodeToString(encrypt(data, secretKeyBytes), false);
	}

	/**
	 * Decrypt the Base64 data with the AES algorithm using the provided secretKey
	 * 
	 * @param base64scrambled
	 * @param secretKeyBytes
	 * @return byte[] 
	 * @throws CipherException
	 */
	public byte[] decrypt(String base64scrambled, byte[] secretKeyBytes) throws CipherException {		
		return decrypt(Base64.decode(base64scrambled), secretKeyBytes);	
	}
	
	/**
	 * Decrypt the byte[] data with the AES algorithm using the provided secretKey
	 * 
	 * @param scrambled
	 * @param secretKeyBytes
	 * @return byte[] 
	 * @throws CipherException
	 */
	public byte[] decrypt(byte[] scrambled, byte[] secretKeyBytes) throws CipherException {
		try {
			byte[] emptySeed = new byte[SEED_LENGTH];
			System.arraycopy(scrambled, 0, emptySeed, 0, SEED_LENGTH);
	
			int messageDecryptedBytesLength = scrambled.length - SEED_LENGTH;
			byte[] messageDecryptedBytes = new byte[messageDecryptedBytesLength];
			System.arraycopy(scrambled, SEED_LENGTH, messageDecryptedBytes, 0, messageDecryptedBytesLength);
	
			SecretKey secretKey = new SecretKeySpec(secretKeyBytes, AES);
			
			return getCipher(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(emptySeed)).doFinal(messageDecryptedBytes);
			
		} catch (BadPaddingException e) {
			throw new CipherException("error.cipher.padding", e);
			
		} catch (IllegalBlockSizeException e) {
			throw new CipherException("error.cipher.padding", e);
			
		}
	}


	protected char[] getRandomPassword() {
		char[] randomPassword = new char[PWD_LENGTH];

		Random random = new Random();
		for (int i = 0; i < PWD_LENGTH; i++) {
			randomPassword[i] = (char) (random.nextInt('~' - '!' + 1) + '!');
		}

		return randomPassword;
	}

}
