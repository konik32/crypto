package org.springframework.security.crypto.encrypt;

import static org.springframework.security.crypto.encrypt.CipherUtils.doFinal;
import static org.springframework.security.crypto.encrypt.CipherUtils.initCipher;
import static org.springframework.security.crypto.encrypt.CipherUtils.newCipher;
import static org.springframework.security.crypto.encrypt.CipherUtils.newSecretKey;
import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import static org.springframework.security.crypto.util.EncodingUtils.subArray;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;

public class Aes128BytesEncryptor implements BytesEncryptor {

	private final SecretKey secretKey;

	private final Cipher encryptor;

	private final Cipher decryptor;

	private final BytesKeyGenerator ivGenerator;

	public Aes128BytesEncryptor(String password, CharSequence salt) {
		this(password, salt, null, 128);
	}

	public Aes128BytesEncryptor(String password, CharSequence salt, int keyLength) {
		this(password, salt, null, keyLength);
	}

	public Aes128BytesEncryptor(String password, CharSequence salt, BytesKeyGenerator ivGenerator, int keyLength) {
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), Hex.decode(salt), 1024, 128);
		SecretKey secretKey = newSecretKey("PBKDF2WithHmacSHA1", keySpec);
		this.secretKey = new SecretKeySpec(secretKey.getEncoded(), "AES");
		encryptor = newCipher(AES_ALGORITHM);
		decryptor = newCipher(AES_ALGORITHM);
		this.ivGenerator = ivGenerator != null ? ivGenerator : NULL_IV_GENERATOR;
	}

	public byte[] encrypt(byte[] bytes) {
		synchronized (encryptor) {
			byte[] iv = ivGenerator.generateKey();
			initCipher(encryptor, Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
			byte[] encrypted = doFinal(encryptor, bytes);
			return ivGenerator != NULL_IV_GENERATOR ? concatenate(iv, encrypted) : encrypted;
		}
	}

	public byte[] decrypt(byte[] encryptedBytes) {
		synchronized (decryptor) {
			byte[] iv = iv(encryptedBytes);
			initCipher(decryptor, Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
			return doFinal(decryptor, ivGenerator != NULL_IV_GENERATOR ? encrypted(encryptedBytes, iv.length)
					: encryptedBytes);
		}
	}

	// internal helpers

	private byte[] iv(byte[] encrypted) {
		return ivGenerator != NULL_IV_GENERATOR ? subArray(encrypted, 0, ivGenerator.getKeyLength())
				: NULL_IV_GENERATOR.generateKey();
	}

	private byte[] encrypted(byte[] encryptedBytes, int ivLength) {
		return subArray(encryptedBytes, ivLength, encryptedBytes.length);
	}

	private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";

	private static final BytesKeyGenerator NULL_IV_GENERATOR = new BytesKeyGenerator() {

		private final byte[] VALUE = new byte[16];

		public int getKeyLength() {
			return VALUE.length;
		}

		public byte[] generateKey() {
			return VALUE;
		}

	};
}
