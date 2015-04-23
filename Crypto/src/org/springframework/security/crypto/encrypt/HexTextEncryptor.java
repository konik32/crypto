package org.springframework.security.crypto.encrypt;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;

public class HexTextEncryptor implements TextEncryptor {

	private final BytesEncryptor encryptor;

	public HexTextEncryptor(BytesEncryptor encryptor) {
		this.encryptor = encryptor;
	}

	public String encrypt(String text) {
		return new String(Hex.encode(encryptor.encrypt(Utf8.encode(text))));
	}

	public String decrypt(String encryptedText) {
		return Utf8.decode(encryptor.decrypt(Hex.decode(encryptedText)));
	}

}
