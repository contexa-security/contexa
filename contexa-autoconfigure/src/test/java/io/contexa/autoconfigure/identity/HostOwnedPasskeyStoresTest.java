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

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.zerotrust.stepup.ContexaPasskeyStores;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * As beans, Contexa's repositories were what Spring Security's {@code webAuthn()} found: an application's own passkeys were
 * stored in Contexa's tables. The step-up keeps its own now, and shares the application's only when told to.
 */
class HostOwnedPasskeyStoresTest {

    private final ContexaPasskeyStores contexa = new ContexaPasskeyStores(
            mock(PublicKeyCredentialUserEntityRepository.class), mock(UserCredentialRepository.class));
    private final PublicKeyCredentialUserEntityRepository applicationEntities = mock(PublicKeyCredentialUserEntityRepository.class);
    private final UserCredentialRepository applicationCredentials = mock(UserCredentialRepository.class);

    private ContexaPasskeyStores chosen(boolean share, boolean applicationHasStores) {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("contexaPasskeyStores", contexa);
        if (applicationHasStores) {
            beans.registerSingleton("entities", applicationEntities);
            beans.registerSingleton("credentials", applicationCredentials);
        }
        BridgeProperties properties = new BridgeProperties();
        properties.getStepUp().setShareApplicationPasskeys(share);
        return HostOwnedStepUpAutoConfiguration.passkeyStores(properties, beans.getBeanProvider(ContexaPasskeyStores.class),
                beans.getBeanProvider(PublicKeyCredentialUserEntityRepository.class), beans.getBeanProvider(UserCredentialRepository.class));
    }

    @Test
    void theStepUpKeepsItsOwnPasskeysBesideTheApplicationsByDefault() {
        assertThat(chosen(false, true)).isSameAs(contexa);
    }

    @Test
    void theApplicationCanShareThePasskeysItAlreadyHas() {
        ContexaPasskeyStores shared = chosen(true, true);

        assertThat(shared.userEntities()).isSameAs(applicationEntities);
        assertThat(shared.userCredentials()).isSameAs(applicationCredentials);
    }

    @Test
    void sharingWithoutStoresToShareStaysWithContexas() {
        assertThat(chosen(true, false)).isSameAs(contexa);
    }

    private ApplicationContextRunner webAuthnConfiguration(String ownership) {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.bridge.ownership=" + ownership)
                .withBean("contexaJdbcTemplate", JdbcOperations.class, () -> mock(JdbcTemplate.class))
                .withBean(PlatformConfig.class, () -> mock(PlatformConfig.class))
                .withConfiguration(AutoConfigurations.of(IdentityWebAuthnAutoConfiguration.class));
    }

    @Test
    void underHostOwnedNoRepositoryOfASharedTypeIsThereForTheApplicationsWebAuthnToFind() {
        webAuthnConfiguration("HOST_OWNED").run(context -> {
            assertThat(context).hasSingleBean(ContexaPasskeyStores.class);
            assertThat(context).doesNotHaveBean(PublicKeyCredentialUserEntityRepository.class);
            assertThat(context).doesNotHaveBean(UserCredentialRepository.class);
        });
    }

    /** Contexa's own chain calls webAuthn() here, and Spring Security finds repositories only as beans. */
    @Test
    void underContexaOwnedTheRepositoriesStayBeansForContexasOwnChain() {
        webAuthnConfiguration("CONTEXA_OWNED").run(context -> {
            assertThat(context).hasSingleBean(PublicKeyCredentialUserEntityRepository.class);
            assertThat(context).hasSingleBean(UserCredentialRepository.class);
            assertThat(context).doesNotHaveBean(ContexaPasskeyStores.class);
        });
    }
}
