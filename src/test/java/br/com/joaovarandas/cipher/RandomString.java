package br.com.joaovarandas.cipher;

public interface RandomString {

	public static String generate(int length) {
		StringBuffer buffer = new StringBuffer();
		String characters = "123456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ123456789";

		int charactersLength = characters.length();

		for (int i = 0; i < length; i++) {
			double index = Math.random() * charactersLength;
			buffer.append(characters.charAt((int) index));
		}
		return buffer.toString();
	}	
	
}
