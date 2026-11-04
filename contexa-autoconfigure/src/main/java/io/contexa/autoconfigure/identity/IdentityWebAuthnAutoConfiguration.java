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
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexaidentity.security.service.PasskeyUserStatePurgeContributor;
import io.contexa.contexaidentity.security.zerotrust.stepup.ContexaPasskeyStores;
import io.contexa.contexaidentity.security.webauthn.codec.DefaultPasskeyCreationOptionsCodec;
import io.contexa.contexaidentity.security.webauthn.codec.PasskeyCreationOptionsCodec;
import io.contexa.contexaidentity.security.webauthn.repository.SerializablePasskeyCreationOptionsRepository;
import io.contexa.contexacommon.jdbc.LibraryTableNames;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

    /** Spring Security's {@code webAuthn()} of Contexa's chain finds its repositories as beans; no chain of an application is there. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnOwnership(SecurityOwnershipMode.CONTEXA_OWNED)
    static class ContexaOwnedPasskeys {

        @Bean(name = "contexaPublicKeyCredentialUserEntityRepository")
        @ConditionalOnMissingBean(PublicKeyCredentialUserEntityRepository.class)
        @ConditionalOnBean(name = "contexaJdbcTemplate")
        public PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository(
                @Qualifier("contexaJdbcTemplate")
                JdbcOperations jdbcOperations) {
            return new JdbcPublicKeyCredentialUserEntityRepository(LibraryTableNames.wrap(jdbcOperations));
        }

        @Bean(name = "contexaUserCredentialRepository")
        @ConditionalOnMissingBean(UserCredentialRepository.class)
        @ConditionalOnBean(name = "contexaJdbcTemplate")
        public UserCredentialRepository userCredentialRepository(
                @Qualifier("contexaJdbcTemplate")
                JdbcOperations jdbcOperations) {
            return new JdbcUserCredentialRepository(LibraryTableNames.wrap(jdbcOperations));
        }
    }

    /** The application's {@code webAuthn()} must not find Contexa's repositories, so that they are held instead of being beans. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnOwnership(SecurityOwnershipMode.HOST_OWNED)
    static class HostOwnedPasskeys {

        @Bean(name = "contexaPasskeyStores")
        @ConditionalOnMissingBean
        @ConditionalOnBean(name = "contexaJdbcTemplate")
        public ContexaPasskeyStores contexaPasskeyStores(@Qualifier("contexaJdbcTemplate") JdbcOperations jdbcOperations) {
            JdbcOperations ctxaTables = LibraryTableNames.wrap(jdbcOperations);
            return new ContexaPasskeyStores(new JdbcPublicKeyCredentialUserEntityRepository(ctxaTables),
                    new JdbcUserCredentialRepository(ctxaTables));
        }
    }

    @Bean(name = "contexaPasskeyUserStatePurgeContributor")
    @ConditionalOnMissingBean
    public PasskeyUserStatePurgeContributor passkeyUserStatePurgeContributor(
            ObjectProvider<ContexaPasskeyStores> held,
            ObjectProvider<PublicKeyCredentialUserEntityRepository> userEntities,
            ObjectProvider<UserCredentialRepository> userCredentials) {
        return new PasskeyUserStatePurgeContributor(
                () -> held.getIfAvailable() != null ? held.getObject().userEntities() : userEntities.getIfAvailable(),
                () -> held.getIfAvailable() != null ? held.getObject().userCredentials() : userCredentials.getIfAvailable());
    }

    @Bean(name = "contexaPasskeyCreationOptionsCodec")
    @ConditionalOnMissingBean(PasskeyCreationOptionsCodec.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    public PasskeyCreationOptionsCodec passkeyCreationOptionsCodec() {
        return new DefaultPasskeyCreationOptionsCodec();
    }

    @Bean(name = "contexaPublicKeyCredentialCreationOptionsRepository")
    @ConditionalOnMissingBean(PublicKeyCredentialCreationOptionsRepository.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    public PublicKeyCredentialCreationOptionsRepository publicKeyCredentialCreationOptionsRepository(
            PasskeyCreationOptionsCodec codec) {
        return new SerializablePasskeyCreationOptionsRepository(codec);
    }

    public IdentityWebAuthnAutoConfiguration() {
    }
}

