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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.migcomponents.migbase64.Base64;

/**
 * RSA Helper Class (Singleton) to simplify the encrypting/decrypting proccess
 * in Java See https://github.com/joaovarandas for more examples
 * 
 * @author jpvarandas
 *
 */
public class RSA extends BasicAsymmetricEngine {

	private static final RSA instance = new RSA();

	/**
	 * Obtain an instance of RSA object
	 * 
	 * @return A singleton instance
	 */
	public static RSA getInstance() {
		return instance;
	}

	private final static String RSA_ALGORITHM = "RSA";
	private final static String SHA512withRSA = "SHA512withRSA";

	@Override
	protected String getAlgorithm() {
		return RSA_ALGORITHM;
	}
	
	/**
	 * Encrypts data using a byte array as the PublicKey Source (shortcut
	 * method)
	 * 
	 * @param data
	 * @param publicKeyBytes
	 * @return byte[]
	 * @throws CipherException
	 */
	public final byte[] encrypt(byte[] data, byte[] publicKeyBytes) throws CipherException {
		return encrypt(data, getPublicKey(publicKeyBytes));
	}


	/**
	 * Decrypts data using a byte array as the PrivateKey Source (shortcut method)
	 * 
	 * @param base64data
	 * @param privateKeyBytes
	 * @return byte[]
	 * @throws CipherException
	 */
	public final byte[] decrypt(String base64data, byte[] privateKeyBytes) throws CipherException {
		return decrypt(Base64.decode(base64data), privateKeyBytes);
	}
	
	/**
	 * Decrypts data using a byte array as the PrivateKey Source (shortcut
	 * method)
	 * 
	 * @param data
	 * @param privateKeyBytes
	 * @return byte[]
	 * @throws CipherException
	 */
	public final byte[] decrypt(byte[] data, byte[] privateKeyBytes) throws CipherException {
		return decrypt(data, getPrivateKey(privateKeyBytes));
	}

	/**
	 * Initiates the Cipher engine
	 * 
	 * @param mode
	 * @param key
	 * @return
	 * @throws CipherException
	 */
	protected Cipher getCipher(int mode, Key key) throws CipherException {
		final Cipher cipher;

		try {
			cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(mode, key, new SecureRandom());

		} catch (NoSuchAlgorithmException e) {
			throw new CipherException("error.cipher.algorithm", e);

		} catch (NoSuchPaddingException e) {
			throw new CipherException("error.cipher.padding", e);

		} catch (InvalidKeyException e) {
			throw new CipherException("error.cipher.invalidkey", e);

		} finally {

		}

		return cipher;
	}
	
	protected Signature getSignature(PrivateKey key) throws CipherException {
		try {
			Signature sign = Signature.getInstance(SHA512withRSA);
			sign.initSign(key);
			
			return sign;
			
		} catch (NoSuchAlgorithmException e) {
			throw new CipherException("error.cipher.algorithm", e);
			
		} catch (InvalidKeyException e) {
			throw new CipherException("error.cipher.invalidkey", e);
			
		} finally {

		}
	}

	protected Signature getSignature(PublicKey key) throws CipherException {
		try {
			Signature sign = Signature.getInstance(SHA512withRSA);
			sign.initVerify(key);
			
			return sign;
			
		} catch (NoSuchAlgorithmException e) {
			throw new CipherException("error.cipher.algorithm", e);
			
		} catch (InvalidKeyException e) {
			throw new CipherException("error.cipher.invalidkey", e);
			
		} finally {

		}
	}

	/**
	 * Encrypts data using the providade PublicKey Instance
	 * 
	 * @param data
	 * @param publicKey
	 * @return byte[]
	 * @throws CipherException
	 */
	public final byte[] encrypt(byte[] data, PublicKey publicKey) throws CipherException {
		try {
			return getCipher(Cipher.ENCRYPT_MODE, publicKey).doFinal(data);
			
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new CipherException("error.cipher.proccess", e);
			
		}
	}

	/**
	 * Encrypts data using the provided PublicKey Instance and returns a Base64
	 * string
	 * 
	 * @param data
	 * @param publicKey
	 * @return String
	 * @throws CipherException
	 */
	public final String encryptAsString(byte[] data, PublicKey publicKey) throws CipherException {
		return Base64.encodeToString(encrypt(data, publicKey), false);
	}

	/**
	 * Encrypts data using the provided PublicKey Instance and returns a Base64
	 * string
	 * 
	 * @param data
	 * @param publicKey
	 * @return String
	 * @throws CipherException
	 */
	public final String encryptAsString(byte[] data, byte[] publicKey) throws CipherException {
		return Base64.encodeToString(encrypt(data, publicKey), false);
	}
	
	
	/**
	 * Decrypts data using the provided PrivateKey Instance
	 * 
	 * @param data
	 * @param privateKey
	 * @return String
	 * @throws CipherException
	 */
	public final byte[] decrypt(String data, PrivateKey privateKey) throws CipherException {
		return decrypt(Base64.decode(data), privateKey);
	}

	/**
	 * Decrypts data using the provided PrivateKey Instance
	 * 
	 * @param data
	 * @param privateKey
	 * @return byte[]
	 * @throws CipherException
	 */
	public final byte[] decrypt(byte[] data, PrivateKey privateKey) throws CipherException {
		try {
			return getCipher(Cipher.DECRYPT_MODE, privateKey).doFinal(data);
			
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new CipherException("error.cipher.proccess", e);
			
		}
	}

	protected final void readSignatureData(Signature sign, byte[] data) throws CipherException {
		try {
			ByteArrayInputStream fis = new ByteArrayInputStream(data);
			BufferedInputStream bufin = new BufferedInputStream(fis);
			byte[] buffer = new byte[1024];
			int len;
			while ((len = bufin.read(buffer)) >= 0) {
				sign.update(buffer, 0, len);
			};
			
			bufin.close();
		} catch (IOException e) {
			throw new CipherException("error.cipher.io", e);
			
		} catch (SignatureException e) {
			throw new CipherException("error.cipher.invalidsign", e);
			
		}

	}
	
	/**
	 * Sign a message using the provided PrivateKey 
	 * 
	 * @param data
	 * @param privateKey
	 * @return byte[]
	 * @throws CipherException
	 */
	public final byte[] sign(byte[] data, PrivateKey privateKey) throws CipherException {
		try {
			Signature sign = getSignature(privateKey);
			
			readSignatureData(sign, data);
			byte[] realSignature = sign.sign();
			
			return realSignature;		
		
		} catch (SignatureException e) {
			throw new CipherException("error.cipher.invalidsign", e);
			
		}	
	}
	
	/**
	 * Sign a message using the provided PrivateKey and return a Base64 String
	 * 
	 * @param data
	 * @param privateKey
	 * @return String
	 * @throws CipherException
	 */
	public final String signAsString(byte[] data, PrivateKey privateKey) throws CipherException {
		return Base64.encodeToString(sign(data, privateKey), false);
	}

	/**
	 * Sign a message using the provided PrivateKey and return a Base64 String
	 * 
	 * @param data
	 * @param privateKeyBytes
	 * @return String
	 * @throws CipherException
	 */
	public final String signAsString(byte[] data, byte[] privateKeyBytes) throws CipherException {
		return Base64.encodeToString(sign(data, getPrivateKey(privateKeyBytes)), false);
	}
	
	/**
	 * Validate the signature using the provided PublicKey
	 * 
	 * @param data
	 * @param signature
	 * @param publicKey
	 * 
	 * @return boolean
	 * 
	 * @throws CipherException
	 */	public final boolean validateSign(byte[] data, byte[] signature, PublicKey publicKey) throws CipherException {
		try {
			Signature sign = getSignature(publicKey);
			readSignatureData(sign, data);
			
			return sign.verify(signature);
		} catch (SignatureException e) {
			throw new CipherException("error.cipher.invalidsign", e);
		}
	}

	/**
	 * Validate the signature using the provided PublicKey
	 * 
	 * @param data Message data
	 * @param signature Signature (Base64)
	 * @param publicKey
	 * @return boolean
	 * @throws CipherException
	 */
	public final boolean validateSign(byte[] data, String signature, PublicKey publicKey) throws CipherException {
		return validateSign(data, Base64.decode(signature), publicKey);
	}

	/**
	 * Validate the signature using the provided PublicKey
	 * 
	 * @param data
	 * @param signature
	 * @param publicKeyBytes
	 * @return boolean
	 * @throws CipherException
	 */
	public final boolean validateSign(byte[] data, String signature, byte[] publicKeyBytes) throws CipherException {
		return validateSign(data, Base64.decode(signature), getPublicKey(publicKeyBytes));
	}	

	
}
