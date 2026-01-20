package io.contexa.autoconfigure.identity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;


@Slf4j
@AutoConfiguration
public class IdentityWebAuthnAutoConfiguration {

    
    @Bean
    @ConditionalOnMissingBean(PublicKeyCredentialUserEntityRepository.class)
    public PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository(
            JdbcOperations jdbcOperations) {
        log.info("Initializing PublicKeyCredentialUserEntityRepository (JDBC-based)");
        return new JdbcPublicKeyCredentialUserEntityRepository(jdbcOperations);
    }

    
    @Bean
    @ConditionalOnMissingBean(UserCredentialRepository.class)
    public UserCredentialRepository userCredentialRepository(
            JdbcOperations jdbcOperations) {
        log.info("Initializing UserCredentialRepository (JDBC-based)");
        return new JdbcUserCredentialRepository(jdbcOperations);
    }

    
    public IdentityWebAuthnAutoConfiguration() {
        log.info("WebAuthn Persistence Configuration initialized");
        log.info("   - User entities will be stored in: user_entities table");
        log.info("   - Credentials will be stored in: user_credentials table");
        log.info("   - Spring Security will automatically use JDBC repositories");
    }
}
