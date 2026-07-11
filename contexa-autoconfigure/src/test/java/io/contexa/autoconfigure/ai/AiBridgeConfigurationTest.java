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

import io.contexa.contexacommon.security.bridge.AuthBridge;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.handoff.ContexaAuthBridge;
import io.contexa.contexacommon.security.bridge.handoff.ContexaAuthBridgeHandler;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.BridgeResolutionConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class AiBridgeConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(AiBridgeConfiguration.class);

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        ContexaAuthBridge.clearHandler();
    }

    @Test
    void shouldRegisterBridgeBeansWhenEnabled() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(BridgeProperties.class);
            assertThat(context).hasSingleBean(AuthBridge.class);
            assertThat(context).hasSingleBean(BridgeRuntimeSupport.class);
            assertThat(context).hasSingleBean(ContexaAuthBridgeHandler.class);
            assertThat(context).hasSingleBean(BridgeResolutionFilter.class);
            assertThat(ContexaAuthBridge.isInitialized()).isTrue();
        });
    }

    @Test
    void shouldRegisterBridgeFilterButKeepDisabledPropertyWhenDisabledPropertyIsSet() {
        contextRunner.withPropertyValues("contexa.bridge.enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(BridgeResolutionFilter.class);
                    assertThat(context.getBean(BridgeProperties.class).isEnabled()).isFalse();
                });
    }

    @Test
    void shouldRegisterBridgeResolutionConfigurerWhenUserProvidesPlatformConfig() {
        new ApplicationContextRunner()
                .withUserConfiguration(AiSecurityConfiguration.class)
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
                .run(context -> {
                    assertThat(context).hasSingleBean(BridgeResolutionFilter.class);
                    assertThat(context).hasSingleBean(BridgeResolutionConfigurer.class);
                    assertThat(context).hasSingleBean(PlatformConfig.class);
                });
    }

    @Test
    void shouldUseProvidedBridgeRuntimeSupportForFilterResolution() {
        CountingBridgeRuntimeSupport runtimeSupport = new CountingBridgeRuntimeSupport();

        contextRunner.withBean(BridgeRuntimeSupport.class, () -> runtimeSupport)
                .run(context -> {
                    SecurityContextHolder.getContext().setAuthentication(
                            UsernamePasswordAuthenticationToken.authenticated("host-user", "n/a", List.of()));
                    BridgeResolutionFilter filter = context.getBean(BridgeResolutionFilter.class);
                    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
                    request.addHeader("X-Contexa-Principal-Id", "alice");
                    request.addHeader("X-Contexa-Authenticated", "true");
                    request.addHeader("X-Contexa-Authorities", "ROLE_USER");

                    filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

                    assertThat(runtimeSupport.synchronizeUserCalls()).isEqualTo(1);
                });
    }

    @Test
    void shouldApplyBridgeNetworkTrustedProxyConfigToRequestContextCollector() {
        contextRunner.withPropertyValues("contexa.bridge.network.trusted-proxies[0]=10.0.0.0/24")
                .run(context -> {
                    RequestContextCollector collector = context.getBean(RequestContextCollector.class);
                    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
                    request.setRemoteAddr("10.0.0.10");
                    request.addHeader("X-Forwarded-For", "203.0.113.10, 10.0.0.10");

                    RequestContextSnapshot snapshot = collector.collect(request);

                    assertThat(snapshot.clientIp()).isEqualTo("203.0.113.10");
                });
    }

    private static class CountingBridgeRuntimeSupport extends BridgeRuntimeSupport {
        private final AtomicInteger synchronizeUserCalls = new AtomicInteger();

        CountingBridgeRuntimeSupport() {
            super(new BridgeProperties(), null);
        }

        @Override
        public BridgeUserMirrorSyncResult synchronizeUser(
                AuthenticationStamp authenticationStamp,
                AuthorizationStamp authorizationStamp,
                RequestContextSnapshot requestContext) {
            synchronizeUserCalls.incrementAndGet();
            return super.synchronizeUser(authenticationStamp, authorizationStamp, requestContext);
        }

        int synchronizeUserCalls() {
            return synchronizeUserCalls.get();
        }
    }
}
