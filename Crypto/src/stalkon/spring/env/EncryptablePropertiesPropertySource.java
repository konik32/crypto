package stalkon.spring.env;

import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.core.env.MapPropertySource;
import org.springframework.security.crypto.encrypt.TextEncryptor;

public class EncryptablePropertiesPropertySource extends MapPropertySource {

	private final TextEncryptor encryptor;
	private static final Pattern ENC_PATTERN = Pattern.compile("enc\\((.*)\\)");

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public EncryptablePropertiesPropertySource(String name, Properties source, TextEncryptor encryptor) {
		super(name, (Map) source);
		this.encryptor = encryptor;
	}

	protected EncryptablePropertiesPropertySource(String name, Map<String, Object> source, TextEncryptor encryptor) {
		super(name, source);
		this.encryptor = encryptor;
	}

	@Override
	public Object getProperty(String name) {
		Object property = super.getProperty(name);
		if (property != null && property instanceof String) {
			Matcher matcher = ENC_PATTERN.matcher((String) property);
			if (matcher.find()) {
				String encrypted = matcher.group(1);
				String decrypted = encryptor.decrypt(encrypted);
				return decrypted;
			}
		}
		return property;
	}

}