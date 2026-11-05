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

import io.contexa.contexaidentity.security.zerotrust.stepup.ContexaPasskeyStores;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.PasskeyUrls;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.webauthn.codec.DefaultPasskeyCreationOptionsCodec;
import io.contexa.contexaidentity.security.webauthn.codec.PasskeyCreationOptionsCodec;
import io.contexa.autoconfigure.ai.HostOwnedEnforcementOrder;
import io.contexa.contexaidentity.security.zerotrust.ChallengeResolution;
import io.contexa.contexaidentity.security.zerotrust.HostOwnedUserPathGuard;
import io.contexa.contexaidentity.security.zerotrust.HostOwnedSignInListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexaidentity.security.zerotrust.stepup.HostOwnedStepUpController;
import io.contexa.contexaidentity.security.zerotrust.stepup.HostOwnedStepUpService;
import io.contexa.contexaidentity.security.zerotrust.stepup.StepUpOptionsStore;
import io.contexa.contexacommon.jdbc.LibraryTableNames;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.JdbcOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.Webauthn4JRelyingPartyOperations;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The verification-only step-up when the application owns sign-in (HOST_OWNED, ownership design S-2): the service the
 * enforcement filters send a CHALLENGE to and its pages under {@code /contexa/step-up}. What a step-up hands out is kept
 * in the store of {@link StepUpOptionsStoreAutoConfiguration}. Under CONTEXA_OWNED Contexa's own MFA answers a CHALLENGE
 * and none of this is created.
 */
@AutoConfiguration
@AutoConfigureAfter({IdentitySecurityCoreAutoConfiguration.class, IdentityWebAuthnAutoConfiguration.class,
        IdentityServiceAutoConfiguration.class})
@ConditionalOnBean(PlatformConfig.class)
@ConditionalOnOwnership(SecurityOwnershipMode.HOST_OWNED)
public class HostOwnedStepUpAutoConfiguration {

    @Bean(name = "contexaHostOwnedStepUpService")
    @ConditionalOnMissingBean
    public HostOwnedStepUpService hostOwnedStepUpService(
            ZeroTrustActionRepository actionRepository,
            UserRepository userRepository,
            BridgeProperties bridgeProperties,
            AuthContextProperties authContextProperties,
            Environment environment,
            StepUpOptionsStore contexaStepUpOptionsStore,
            ObjectProvider<SecurityLearningService> securityLearningService,
            ObjectProvider<VerificationLearningService> verificationLearningService,
            ObjectProvider<SecurityContextDataStore> securityContextDataStore,
            ObjectProvider<BlockingSignalBroadcaster> blockingSignalBroadcaster,
            ObjectProvider<IBlockedUserRecorder> blockedUserRecorder,
            ObjectProvider<BlockMfaStateStore> blockMfaStateStore,
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcTemplate> contexaJdbcTemplate,
            ObjectProvider<EmailService> emailService,
            ObjectProvider<ContexaPasskeyStores> contexaPasskeyStores,
            ObjectProvider<PublicKeyCredentialUserEntityRepository> userEntities,
            ObjectProvider<UserCredentialRepository> userCredentials,
            ObjectProvider<PasskeyCreationOptionsCodec> passkeyCreationOptionsCodec) {
        ChallengeResolution resolution = new ChallengeResolution(actionRepository,
                securityLearningService.getIfAvailable(), verificationLearningService::getIfAvailable,
                securityContextDataStore::getIfAvailable, blockingSignalBroadcaster.getIfAvailable(),
                blockedUserRecorder.getIfAvailable(), blockMfaStateStore.getIfAvailable());

        // Spring Security's one-time token engine over Contexa's ctxa_one_time_tokens; the service keys it short.
        JdbcTemplate jdbcTemplate = contexaJdbcTemplate.getIfAvailable();
        OneTimeTokenService stepUpCodes = jdbcTemplate != null ? new JdbcOneTimeTokenService(LibraryTableNames.wrap(jdbcTemplate)) : null;

        ContexaPasskeyStores stores = passkeyStores(bridgeProperties, contexaPasskeyStores, userEntities, userCredentials);
        PublicKeyCredentialUserEntityRepository entities = stores != null ? stores.userEntities() : null;
        UserCredentialRepository credentials = stores != null ? stores.userCredentials() : null;
        Webauthn4JRelyingPartyOperations relyingParty = entities != null && credentials != null
                ? relyingParty(entities, credentials, authContextProperties, environment) : null;

        return new HostOwnedStepUpService(actionRepository, resolution, userRepository,
                bridgeProperties.getSync().getSyntheticEmailDomain(), contexaStepUpOptionsStore,
                stepUpCodes, emailService.getIfAvailable(), relyingParty, entities,
                credentials, passkeyCreationOptionsCodec.getIfAvailable(DefaultPasskeyCreationOptionsCodec::new),
                bridgeProperties.getStepUp().getReauthenticationUrl());
    }

    @Bean(name = "contexaHostOwnedStepUpController")
    @ConditionalOnMissingBean
    public HostOwnedStepUpController hostOwnedStepUpController(HostOwnedStepUpService contexaHostOwnedStepUpService) {
        return new HostOwnedStepUpController(contexaHostOwnedStepUpService);
    }

    /** The application's interactive sign-in goes to the engine as Contexa's own does (ownership design S-8). */
    @Bean(name = "contexaHostOwnedSignInListener")
    @ConditionalOnMissingBean
    @ConditionalOnBean(ZeroTrustEventPublisher.class)
    public HostOwnedSignInListener hostOwnedSignInListener(ZeroTrustEventPublisher contexaZeroTrustEventPublisher) {
        return new HostOwnedSignInListener(contexaZeroTrustEventPublisher);
    }

    /** Contexa's pages for the signed-in user answer only a signed-in user (ownership design S-3). */
    @Bean(name = "contexaHostOwnedUserPathGuardRegistration")
    @ConditionalOnMissingBean(name = "contexaHostOwnedUserPathGuardRegistration")
    public FilterRegistrationBean<HostOwnedUserPathGuard> hostOwnedUserPathGuardRegistration(
            ObjectProvider<SecurityProperties> securityProperties) {
        FilterRegistrationBean<HostOwnedUserPathGuard> registration =
                new FilterRegistrationBean<>(new HostOwnedUserPathGuard());
        registration.setName("contexaHostOwnedUserPathGuard");
        registration.setUrlPatterns(HostOwnedUserPathGuard.URL_PATTERNS);
        registration.setOrder(HostOwnedEnforcementOrder.securityFilterOrder(securityProperties)
                + HostOwnedEnforcementOrder.USER_PATH_GUARD);
        return registration;
    }

    /** The same relying party as Contexa's own passkey factor ({@code contexa.auth.urls.factors.passkey.*}). */
    /** Contexa's own, unless the application asks to share the passkeys it already has and has one store of each to share. */
    static ContexaPasskeyStores passkeyStores(BridgeProperties bridgeProperties, ObjectProvider<ContexaPasskeyStores> contexaPasskeyStores,
                                              ObjectProvider<PublicKeyCredentialUserEntityRepository> userEntities,
                                              ObjectProvider<UserCredentialRepository> userCredentials) {
        if (bridgeProperties.getStepUp().isShareApplicationPasskeys()) {
            PublicKeyCredentialUserEntityRepository entities = userEntities.getIfUnique();
            UserCredentialRepository credentials = userCredentials.getIfUnique();
            if (entities != null && credentials != null) {
                return new ContexaPasskeyStores(entities, credentials);
            }
        }
        return contexaPasskeyStores.getIfAvailable();
    }

    private static Webauthn4JRelyingPartyOperations relyingParty(PublicKeyCredentialUserEntityRepository entities,
                                                                 UserCredentialRepository credentials,
                                                                 AuthContextProperties properties,
                                                                 Environment environment) {
        PasskeyUrls passkey = properties.getUrls().getFactors().getPasskey();
        String configured = passkey.getAllowedOrigins();
        Set<String> origins = configured != null && !configured.isBlank()
                ? Arrays.stream(configured.split(",")).map(String::trim).filter(o -> !o.isEmpty())
                .collect(Collectors.toSet())
                : Set.of("http://localhost:" + environment.getProperty("server.port", "8080"));
        return new Webauthn4JRelyingPartyOperations(entities, credentials,
                PublicKeyCredentialRpEntity.builder().id(passkey.getRpId()).name(passkey.getRpName()).build(),
                origins);
    }
}
