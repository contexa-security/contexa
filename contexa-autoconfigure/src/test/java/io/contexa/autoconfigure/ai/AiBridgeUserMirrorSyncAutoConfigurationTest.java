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
package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.handoff.ContexaAuthBridge;
import io.contexa.contexacommon.security.bridge.handoff.ContexaAuthBridgeHandler;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AiBridgeUserMirrorSyncAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(AiBridgeConfiguration.class)
            .withConfiguration(AutoConfigurations.of(AiBridgeUserMirrorSyncAutoConfiguration.class));

    @AfterEach
    void tearDown() {
        ContexaAuthBridge.clearHandler();
    }

    @Test
    void bridgeConsumersReceiveAutoConfiguredMirrorSyncService() {
        contextRunner.withBean(UserRepository.class, () -> mock(UserRepository.class))
                .withBean(BridgeUserProfileRepository.class, () -> mock(BridgeUserProfileRepository.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(BridgeUserMirrorSyncService.class);
                    BridgeUserMirrorSyncService syncService = context.getBean(BridgeUserMirrorSyncService.class);
                    assertThat(syncService).isInstanceOf(DefaultBridgeUserMirrorSyncService.class);

                    BridgeRuntimeSupport runtimeSupport = context.getBean(BridgeRuntimeSupport.class);
                    assertThat(ReflectionTestUtils.getField(runtimeSupport, "bridgeUserMirrorSyncService"))
                            .isSameAs(syncService);
                    BridgeResolutionFilter filter = context.getBean(BridgeResolutionFilter.class);
                    assertThat(ReflectionTestUtils.getField(filter, "bridgeRuntimeSupport"))
                            .isSameAs(runtimeSupport);
                    ContexaAuthBridgeHandler handler = context.getBean(ContexaAuthBridgeHandler.class);
                    assertThat(ReflectionTestUtils.getField(handler, "bridgeRuntimeSupport"))
                            .isSameAs(runtimeSupport);
                });
    }

    @Test
    void mirrorSyncServiceIsNotCreatedWithoutContexaRepositories() {
        contextRunner.run(context -> {
            assertThat(context).doesNotHaveBean(BridgeUserMirrorSyncService.class);
            BridgeRuntimeSupport runtimeSupport = context.getBean(BridgeRuntimeSupport.class);
            assertThat(ReflectionTestUtils.getField(runtimeSupport, "bridgeUserMirrorSyncService")).isNull();
        });
    }

    @Test
    void mirrorSyncServiceRequiresTheBridgeConfiguration() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(AiBridgeUserMirrorSyncAutoConfiguration.class))
                .withBean(UserRepository.class, () -> mock(UserRepository.class))
                .withBean(BridgeUserProfileRepository.class, () -> mock(BridgeUserProfileRepository.class))
                .run(context -> assertThat(context).doesNotHaveBean(BridgeUserMirrorSyncService.class));
    }
}
