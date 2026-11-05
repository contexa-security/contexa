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
import io.contexa.autoconfigure.iam.admin.IamAgentRegistryAutoConfiguration;
import io.contexa.contexacore.autonomous.agent.AgentNoticeStore;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** What reads a verification is handed the store: without it no session lifts its own BLOCK, verified or not. */
class BlockVerificationWiringTest {

    private final BlockMfaStateStore store = mock(BlockMfaStateStore.class);
    private final SecurityZeroTrustProperties zeroTrust = new SecurityZeroTrustProperties();

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> provider(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        when(provider.getIfAvailable(any())).thenReturn(value);
        return provider;
    }

    @Test
    @DisplayName("the agents' stops know a session under its own BLOCK from the block list's service")
    void theAgentStops() {
        BlockedUserService blockedUsers = mock(BlockedUserService.class);

        AgentContainmentAdminService stops = new IamAgentRegistryAutoConfiguration().agentContainmentAdminService(
                provider(null), mock(AgentRegistry.class), provider(null), mock(AgentNoticeStore.class), provider(null),
                provider(blockedUsers));

        assertThat(ReflectionTestUtils.getField(stops, "blockedUsers")).isSameAs(blockedUsers);
    }

    @Test
    @DisplayName("the block list's service reads the verification of the acting administrator")
    void theService() {
        BlockedUserService service = new IamAdminBlacklistAutoConfiguration().blockedUserService(
                mock(BlockedUserJpaRepository.class), mock(AdminOverrideService.class),
                mock(ZeroTrustActionRepository.class), mock(ApplicationEventPublisher.class), mock(CentralAuditFacade.class),
                mock(BlockingSignalBroadcaster.class), mock(MessageSource.class), provider(null), provider(store),
                new StaticListableBeanFactory(Map.of("zeroTrust", zeroTrust)).getBeanProvider(SecurityZeroTrustProperties.class));

        assertThat(ReflectionTestUtils.getField(service, "blockMfaStateStore")).isSameAs(store);
        zeroTrust.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
        assertThat(((BooleanSupplier) ReflectionTestUtils.getField(service, "enforcing")).getAsBoolean())
                .as("the mode of the moment decides whether a stored BLOCK stops anything").isFalse();
    }
}
