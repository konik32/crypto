package stalkon.spring.env;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import org.springframework.beans.factory.config.YamlProcessor;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.yaml.SpringProfileDocumentMatcher;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.Resource;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import stalkon.encryptor.Encryptors;

public class EncryptedYamlPropertySourceLoader extends YamlPropertySourceLoader implements PriorityOrdered {

	private final TextEncryptor encryptor;

	public EncryptedYamlPropertySourceLoader() {
		String password = System.getenv("SPRING_YAML_ENCRYPT_PASSWORD");
		String salt = System.getenv("SPRING_YAML_ENCRYPT_SALT");
		Assert.notNull(password, "You have to set SPRING_YAML_ENCRYPT_PASSWORD environment variable");
		Assert.notNull(salt, "You have to set SPRING_YAML_ENCRYPT_SALT environment variable");
		encryptor = Encryptors.text(password, salt);
	}

	@Override
	public PropertySource<?> load(String name, Resource resource, String profile) throws IOException {
		if (ClassUtils.isPresent("org.yaml.snakeyaml.Yaml", null)) {
			Processor processor = new Processor(resource, profile);
			Map<String, Object> source = processor.process();
			if (!source.isEmpty()) {
				return new EncryptablePropertiesPropertySource(name, source, encryptor);
			}
		}
		return null;
	}

	/**
	 * {@link YamlProcessor} to create a {@link Map} containing the property
	 * values. Similar to {@link YamlPropertiesFactoryBean} but retains the
	 * order of entries.
	 */
	private static class Processor extends YamlProcessor {

		public Processor(Resource resource, String profile) {
			if (profile == null) {
				setMatchDefault(true);
				setDocumentMatchers(new SpringProfileDocumentMatcher());
			} else {
				setMatchDefault(false);
				setDocumentMatchers(new SpringProfileDocumentMatcher(profile));
			}
			setResources(new Resource[] { resource });
		}

		public Map<String, Object> process() {
			final Map<String, Object> result = new LinkedHashMap<>();
			process(new MatchCallback() {
				@Override
				public void process(Properties properties, Map<String, Object> map) {
					result.putAll(getFlattenedMap(map));
				}
			});
			return result;
		}

	}

	@Override
	public int getOrder() {
		return Ordered.HIGHEST_PRECEDENCE;
	}
}
