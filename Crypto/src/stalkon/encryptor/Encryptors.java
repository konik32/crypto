package stalkon.encryptor;

import org.springframework.security.crypto.encrypt.Aes128BytesEncryptor;
import org.springframework.security.crypto.encrypt.HexTextEncryptor;
import org.springframework.security.crypto.encrypt.TextEncryptor;

public class Encryptors {

	public static TextEncryptor text(String password, String salt) {
		return new HexTextEncryptor(new Aes128BytesEncryptor(password, salt));
	}

	public static TextEncryptor text(String password, String salt, int keyLength) {
		return new HexTextEncryptor(new Aes128BytesEncryptor(password, salt, keyLength));
	}
}
