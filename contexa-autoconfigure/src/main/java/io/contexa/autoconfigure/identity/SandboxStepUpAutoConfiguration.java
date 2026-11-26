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
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.operating.ConditionalOnMode;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.webauthn.PasskeyLibrary;
import io.contexa.contexaidentity.security.webauthn.codec.DefaultPasskeyCreationOptionsCodec;
import io.contexa.contexaidentity.security.webauthn.codec.PasskeyCreationOptionsCodec;
import io.contexa.autoconfigure.ai.ContexaSlotFilterRegistration;
import io.contexa.autoconfigure.ai.ContexaServletFilterOrder;
import io.contexa.contexaidentity.security.zerotrust.ChallengeResolution;
import io.contexa.contexaidentity.security.zerotrust.SandboxUserPathGuard;
import io.contexa.contexaidentity.security.zerotrust.SandboxSignInFailureListener;
import io.contexa.contexaidentity.security.zerotrust.SandboxSignInListener;
import io.contexa.contexaidentity.security.zerotrust.SandboxSignOutListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.HostSignInEvents;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import io.contexa.contexaidentity.security.zerotrust.stepup.SandboxStepUpController;
import io.contexa.contexaidentity.security.zerotrust.stepup.SandboxStepUpService;
import io.contexa.contexaidentity.security.zerotrust.stepup.StepUpOptionsStore;
import io.contexa.contexacommon.jdbc.LibraryTableNames;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.JdbcOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;

/**
 * The verification-only step-up where the application signs its users in itself (mode SANDBOX, ownership design S-2, R-16
 * of docs/agent/운영모드-정상화-구현계획.md): the service the enforcement filters behind the application's chain send a
 * CHALLENGE to, its pages under {@code /contexa/step-up}, the listeners that hand the application's sign-ins to the
 * decisions and the guard of the user paths. What a step-up hands out is kept in the store of
 * {@link StepUpOptionsStoreAutoConfiguration}. In mode FULL Contexa's main chain signs the application's users in and its
 * own MFA answers a CHALLENGE, so none of this is created. The mode decides it, not the ownership.
 */
@AutoConfiguration
@AutoConfigureAfter({IdentitySecurityCoreAutoConfiguration.class, IdentityWebAuthnAutoConfiguration.class,
        IdentityServiceAutoConfiguration.class})
@ConditionalOnBean(PlatformConfig.class)
@ConditionalOnMode(SecurityMode.SANDBOX)
public class SandboxStepUpAutoConfiguration {

    @Bean(name = "contexaSandboxStepUpService")
    @ConditionalOnMissingBean
    public SandboxStepUpService sandboxStepUpService(
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
            ObjectProvider<PasskeyCreationOptionsCodec> passkeyCreationOptionsCodec,
            ObjectProvider<BridgeUserMirrorSyncService> userMirror,
            ObjectProvider<ZeroTrustDecisionOutcomes> decisionOutcomes) {
        ChallengeResolution resolution = new ChallengeResolution(actionRepository,
                securityLearningService.getIfAvailable(), verificationLearningService::getIfAvailable,
                securityContextDataStore::getIfAvailable, blockingSignalBroadcaster.getIfAvailable(),
                blockedUserRecorder.getIfAvailable(), blockMfaStateStore.getIfAvailable());
        // Console design 7.3: a passed challenge is recorded as the decision's outcome.
        resolution.setDecisionOutcomes(decisionOutcomes.getIfAvailable());

        // Spring Security's one-time token engine over Contexa's ctxa_one_time_tokens; the service keys it short.
        JdbcTemplate jdbcTemplate = contexaJdbcTemplate.getIfAvailable();
        OneTimeTokenService stepUpCodes = jdbcTemplate != null ? new JdbcOneTimeTokenService(LibraryTableNames.wrap(jdbcTemplate)) : null;

        ContexaPasskeyStores stores = passkeyStores(bridgeProperties, contexaPasskeyStores, userEntities, userCredentials);
        PublicKeyCredentialUserEntityRepository entities = stores != null ? stores.userEntities() : null;
        UserCredentialRepository credentials = stores != null ? stores.userCredentials() : null;
        // Without webauthn4j on the class path there is no relying party, and the step-up has no passkey.
        WebAuthnRelyingPartyOperations relyingParty = entities != null && credentials != null
                && PasskeyLibrary.available(SandboxStepUpAutoConfiguration.class.getClassLoader())
                ? Webauthn4jRelyingParty.create(entities, credentials, authContextProperties, environment) : null;

        SandboxStepUpService service = new SandboxStepUpService(actionRepository, resolution, userRepository,
                bridgeProperties.getSync().getSyntheticEmailDomain(), contexaStepUpOptionsStore,
                stepUpCodes, emailService.getIfAvailable(), relyingParty, entities,
                credentials, passkeyCreationOptionsCodec.getIfAvailable(DefaultPasskeyCreationOptionsCodec::new),
                bridgeProperties.getStepUp().getReauthenticationUrl(),
                authContextProperties.getMfa().getMaxRetryAttempts());
        // An address the application showed for a copy that has one waits for the user's proof of the address on record.
        service.setUserMirror(userMirror.getIfAvailable());
        return service;
    }

    @Bean(name = "contexaSandboxStepUpController")
    @ConditionalOnMissingBean
    public SandboxStepUpController sandboxStepUpController(SandboxStepUpService contexaSandboxStepUpService) {
        return new SandboxStepUpController(contexaSandboxStepUpService);
    }

    /** The application's interactive sign-in is sent on as Contexa's own is; the model is not asked about it. */
    @Bean(name = "contexaSandboxSignInListener")
    @ConditionalOnMissingBean
    @ConditionalOnBean(ZeroTrustEventPublisher.class)
    public SandboxSignInListener sandboxSignInListener(ZeroTrustEventPublisher contexaZeroTrustEventPublisher) {
        return new SandboxSignInListener(contexaZeroTrustEventPublisher);
    }

    /** Whether the application's sign-ins reach Contexa: what a count of no failed sign-ins is worth. */
    @Bean(name = "contexaHostSignInEvents")
    @ConditionalOnMissingBean
    public HostSignInEvents hostSignInEvents() {
        return new HostSignInEvents();
    }

    /** The application's failed sign-ins, for the decisions to read; no lock or address limit counts them. */
    @Bean(name = "contexaSandboxSignInFailureListener")
    @ConditionalOnMissingBean
    @ConditionalOnBean(ZeroTrustEventPublisher.class)
    public SandboxSignInFailureListener sandboxSignInFailureListener(
            ObjectProvider<SecurityContextDataStore> securityContextDataStore,
            HostSignInEvents contexaHostSignInEvents) {
        return new SandboxSignInFailureListener(securityContextDataStore::getIfAvailable, contexaHostSignInEvents);
    }

    /** bridge v2 B5-2: the application's Spring Security sign-out ends Contexa's tracking of it, as ContexaBridge tells. */
    @Bean(name = "contexaSandboxSignOutListener")
    @ConditionalOnMissingBean
    public SandboxSignOutListener sandboxSignOutListener() {
        return new SandboxSignOutListener();
    }

    /**
     * Contexa's pages for the signed-in user answer only a signed-in user (ownership design S-3): on their paths only, in
     * Contexa's filter slot after the zero trust filters (R-10 of docs/agent/운영모드-정상화-구현계획.md).
     */
    @Bean(name = "contexaSandboxUserPathGuardRegistration")
    @ConditionalOnMissingBean(name = "contexaSandboxUserPathGuardRegistration")
    public ContexaSlotFilterRegistration<SandboxUserPathGuard> sandboxUserPathGuardRegistration(
            ObjectProvider<SecurityProperties> securityProperties) {
        ContexaSlotFilterRegistration<SandboxUserPathGuard> registration = ContexaServletFilterOrder.member(
                new SandboxUserPathGuard(), "contexaSandboxUserPathGuard",
                ContexaServletFilterOrder.securityFilterOrder(securityProperties), ContexaServletFilterOrder.USER_PATH_GUARD);
        registration.setUrlPatterns(SandboxUserPathGuard.URL_PATTERNS);
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
}
