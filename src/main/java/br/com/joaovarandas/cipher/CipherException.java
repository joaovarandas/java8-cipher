package br.com.joaovarandas.cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CipherException
 * @author jpvarandas
 *
 */
class CipherException extends Exception {

	private static final Logger logger = LoggerFactory.getLogger("cipher");
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -2505743468475544383L;

	public CipherException(String message, Throwable cause) {
		super(message, cause);

		logger.error("CipherException: {}", message, cause);
	}

}