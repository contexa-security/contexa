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
                return new JdbcPublicKeyCredentialUserEntityRepository(jdbcOperations);
    }

    
    @Bean
    @ConditionalOnMissingBean(UserCredentialRepository.class)
    public UserCredentialRepository userCredentialRepository(
            JdbcOperations jdbcOperations) {
                return new JdbcUserCredentialRepository(jdbcOperations);
    }

    
    public IdentityWebAuthnAutoConfiguration() {
                                    }
}
