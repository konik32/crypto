package stalkon.encryptor.app;

import org.springframework.security.crypto.keygen.KeyGenerators;

public class HexGenerator {
	public static void main(String[] args) {
		System.out.println(KeyGenerators.string().generateKey());
	}
}
