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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * RSA Helper Class (Singleton) to simplify the encrypting/decrypting proccess
 * in Java See https://github.com/joaovarandas for more examples
 * 
 * @author jpvarandas
 *
 */
public class Hybrid {

	private static final Hybrid instance = new Hybrid();

	/**
	 * Obtain instance for the Hybrid crypto engine
	 * 
	 * @return Hybrid
	 */
	public static Hybrid getInstance() {
		return instance;
	}

	/**
	 * Encrypt data using the provided publicKey, a Key will be generated and encrypted using the publicKey, all
	 * data will be encrypted with that Key.
	 * 
	 * @param data
	 * @param publicKey
	 * @return byte[]
	 * @throws CipherException
	 */
	public byte[] encrypt(byte[] data, byte[] publicKey) throws CipherException {
		try {
			byte[] secretKey = AES.getInstance().generateSecretKey();
			byte[] encryptedSecret = RSA.getInstance().encrypt(secretKey, publicKey);
			byte[] encryptedData = AES.getInstance().encrypt(data, secretKey);

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			bos.write("#@!".getBytes());
			bos.write(encryptedSecret);
			bos.write(encryptedData);
			return bos.toByteArray();

		} catch (IOException e) {
			throw new CipherException("error.cipher.io", e);
		}
	}
	
	/**
	 * Decrypt data using the provided privateKey
	 * First, decrypts the secretKey and then use that key to decrypt the Data.
	 * 
	 * @param data
	 * @param privateKey
	 * @return byte[]
	 * @throws CipherException
	 */
	public byte[] decrypt(byte[] data, byte[] privateKey) throws CipherException {
		try {
			int headerLength = 3;
			int keyLength = 256;
			
			byte[] encryptedSecret = new byte[keyLength];
			System.arraycopy(data, headerLength, encryptedSecret, 0, keyLength);
			
			byte[] encryptedData = new byte[data.length - keyLength - headerLength];
			System.arraycopy(data, keyLength+headerLength, encryptedData, 0, data.length - keyLength - headerLength);
			
			byte[] secretKey = RSA.getInstance().decrypt(encryptedSecret, privateKey);
			byte[] cleanData = AES.getInstance().decrypt(encryptedData, secretKey);
			
			return cleanData;
			
		} finally {
			
		}
	}

}
