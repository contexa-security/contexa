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

import io.contexa.autoconfigure.iam.admin.IamAdminBlacklistAutoConfiguration;
import io.contexa.autoconfigure.iam.aiam.IamAiamWebAutoConfiguration;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.aiam.web.ZeroTrustPageController;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.zerotrust.ChallengeMfaInitializer;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustAccessControlFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** What reads a verification is handed the store: without it the block list stays shut for good. */
class BlockVerificationWiringTest {

    private final BlockMfaStateStore store = mock(BlockMfaStateStore.class);

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> provider(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        when(provider.getIfAvailable(any())).thenReturn(value);
        return provider;
    }

    @Test
    @DisplayName("the access filter reads the verification of an administrator under a BLOCK")
    void theFilter() {
        ZeroTrustAccessControlFilter filter = new IdentitySecurityCoreAutoConfiguration().zeroTrustAccessControlFilter(
                mock(ZeroTrustActionRepository.class), mock(AuthResponseWriter.class), mock(IBlockedUserRecorder.class),
                mock(ChallengeMfaInitializer.class), mock(AuthUrlProvider.class), mock(BlockingSignalBroadcaster.class),
                new SecurityZeroTrustProperties(), mock(MfaFlowUrlRegistry.class), provider(null), provider(null),
                provider(null), provider(null), provider(new TieredStrategyProperties()), provider(store));

        assertThat(ReflectionTestUtils.getField(filter, "blockMfaStateStore")).isSameAs(store);
    }

    @Test
    @DisplayName("the block list's service reads the verification of the acting administrator")
    void theService() {
        BlockedUserService service = new IamAdminBlacklistAutoConfiguration().blockedUserService(
                mock(BlockedUserJpaRepository.class), mock(AdminOverrideService.class),
                mock(ZeroTrustActionRepository.class), mock(ApplicationEventPublisher.class), mock(CentralAuditFacade.class),
                mock(BlockingSignalBroadcaster.class), mock(MessageSource.class), provider(null), provider(store));

        assertThat(ReflectionTestUtils.getField(service, "blockMfaStateStore")).isSameAs(store);
    }

    private ZeroTrustPageController screenUnder(BridgeProperties bridge) {
        return new IamAiamWebAutoConfiguration().zeroTrustPageController(store, mock(BlockedUserService.class),
                new SecurityZeroTrustProperties(), provider(bridge));
    }

    @Test
    @DisplayName("the screen of a BLOCK offers the block list where the console and the application share an account")
    void theScreenUnderContexaOwned() {
        BridgeProperties bridge = new BridgeProperties();
        bridge.setOwnership(SecurityOwnershipMode.CONTEXA_OWNED);

        assertThat(ReflectionTestUtils.getField(screenUnder(bridge), "blockListOffered")).isEqualTo(true);
        assertThat(ReflectionTestUtils.getField(screenUnder(null), "blockListOffered")).isEqualTo(true);
    }

    @Test
    @DisplayName("and not where the console has a sign-in of its own")
    void theScreenUnderHostOwned() {
        BridgeProperties bridge = new BridgeProperties();
        bridge.setOwnership(SecurityOwnershipMode.HOST_OWNED);

        assertThat(ReflectionTestUtils.getField(screenUnder(bridge), "blockListOffered")).isEqualTo(false);
    }
}
