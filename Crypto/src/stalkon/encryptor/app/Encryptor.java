package stalkon.encryptor.app;

import java.io.UnsupportedEncodingException;
import java.util.Scanner;

import org.springframework.security.crypto.encrypt.TextEncryptor;

import stalkon.encryptor.Encryptors;

public class Encryptor {

	private TextEncryptor encryptor;

	public Encryptor(String password, String salt) {
		encryptor = Encryptors.text(password, salt);
	}

	public String encrypt(String str) {
		return encryptor.encrypt(str);
	}

	public static void main(String[] args) throws UnsupportedEncodingException {

		Scanner in = new Scanner(System.in);

		System.out.println("Provider password");
		String password = in.nextLine();
		System.out.println("Provide salt in hex");
		String salt = in.nextLine();
		Encryptor gen = new Encryptor(password, salt);
		while (true) {
			System.out.println("Provide string to encrypt");
			System.out.println(gen.encrypt(in.nextLine()));
		}
	}

}
