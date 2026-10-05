/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.identity;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.service.PasskeyUserStatePurgeContributor;
import io.contexa.contexaidentity.security.webauthn.codec.DefaultPasskeyCreationOptionsCodec;
import io.contexa.contexaidentity.security.webauthn.codec.PasskeyCreationOptionsCodec;
import io.contexa.contexaidentity.security.webauthn.repository.SerializablePasskeyCreationOptionsRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsRepository;

@Slf4j
@AutoConfiguration
@ConditionalOnBean(PlatformConfig.class)
public class IdentityWebAuthnAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(PublicKeyCredentialUserEntityRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository(
            @Qualifier("contexaJdbcTemplate")
            JdbcOperations jdbcOperations) {
        return new JdbcPublicKeyCredentialUserEntityRepository(jdbcOperations);
    }

    @Bean
    @ConditionalOnMissingBean(UserCredentialRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public UserCredentialRepository userCredentialRepository(
            @Qualifier("contexaJdbcTemplate")
            JdbcOperations jdbcOperations) {
        return new JdbcUserCredentialRepository(jdbcOperations);
    }

    @Bean
    @ConditionalOnMissingBean
    public PasskeyUserStatePurgeContributor passkeyUserStatePurgeContributor(
            ObjectProvider<PublicKeyCredentialUserEntityRepository> userEntities,
            ObjectProvider<UserCredentialRepository> userCredentials) {
        return new PasskeyUserStatePurgeContributor(userEntities, userCredentials);
    }

    @Bean
    @ConditionalOnMissingBean(PasskeyCreationOptionsCodec.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    public PasskeyCreationOptionsCodec passkeyCreationOptionsCodec() {
        return new DefaultPasskeyCreationOptionsCodec();
    }

    @Bean
    @ConditionalOnMissingBean(PublicKeyCredentialCreationOptionsRepository.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    public PublicKeyCredentialCreationOptionsRepository publicKeyCredentialCreationOptionsRepository(
            PasskeyCreationOptionsCodec codec) {
        return new SerializablePasskeyCreationOptionsRepository(codec);
    }

    public IdentityWebAuthnAutoConfiguration() {
    }
}

