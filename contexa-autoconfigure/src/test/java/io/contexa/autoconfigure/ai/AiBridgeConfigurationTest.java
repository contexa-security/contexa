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

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.resolver.AgentAccountDelegationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.AuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.AuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.DelegationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.TokenDelegationStampResolver;
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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class AiBridgeConfigurationTest {

    /** The message of the start report on the settings Contexa no longer reads. */
    private static final String REMOVED_SETTINGS_REPORT = "Contexa no longer reads the settings";

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(AiBridgeConfiguration.class);

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /** bridge v2 B6: the stamps of a request come from the Spring Security user only; no other channel is registered. */
    @Test
    @DisplayName("bridge v2: 인증·인가 도장 해석기는 Spring Security 것 하나씩만 등록된다")
    void shouldRegisterBridgeBeansWhenEnabled() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(BridgeProperties.class);
            assertThat(context).hasSingleBean(BridgeRuntimeSupport.class);
            assertThat(context).hasSingleBean(BridgeResolutionFilter.class);
            assertThat(context.getBeanProvider(AuthenticationStampResolver.class).orderedStream().toList())
                    .singleElement().isInstanceOf(SecurityContextAuthenticationStampResolver.class);
            assertThat(context.getBeanProvider(AuthorizationStampResolver.class).orderedStream().toList())
                    .singleElement().isInstanceOf(SecurityContextAuthorizationStampResolver.class);
        });
    }

    /** A1-1: the access token's delegation is read first; A1-13: an approved agent's own account is asked last. */
    @Test
    @DisplayName("위임 해석기는 토큰 위임이 먼저, 승인된 에이전트 계정이 마지막이고 그 밖의 통로는 없다")
    void shouldRegisterTheTokenDelegationResolverFirstAndTheAgentAccountLast() {
        contextRunner.run(context -> {
            List<DelegationStampResolver> resolvers =
                    context.getBeanProvider(DelegationStampResolver.class).orderedStream().toList();

            assertThat(resolvers).hasSize(2);
            assertThat(resolvers.get(0)).isInstanceOf(TokenDelegationStampResolver.class);
            assertThat(resolvers.get(1)).isInstanceOf(AgentAccountDelegationStampResolver.class);
            assertThat(context.getBean(BridgeProperties.class).getDelegation().getToken().isEnabled()).isTrue();
        });
    }

    /**
     * bridge v2 B6 (plan 3.5): an installation that still sets the old channels is told at start, once, which keys are no
     * longer read and what replaces them; the values it set are never written.
     */
    @Test
    @ExtendWith(OutputCaptureExtension.class)
    @DisplayName("없어진 옛 bridge 설정 키를 쓰면 기동 때 키 이름과 바꿀 방법을 error로 한 번 알리고, 값은 쓰지 않는다")
    void aRemovedSettingIsReportedOnceByItsNameAtStart(CapturedOutput output) {
        contextRunner.withPropertyValues(
                        "contexa.bridge.authentication.session.attribute=LEGACY_LOGIN_VO_VALUE",
                        "contexa.bridge.authorization.request-attributes.attribute=AUTHZ_VALUE_7",
                        "contexa.bridge.delegation.headers.enabled=true",
                        "contexa.ai.security.auth-object.attribute=LEGACY_HINT_VALUE")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    String printed = output.toString();
                    assertThat(printed).contains(REMOVED_SETTINGS_REPORT)
                            .contains("contexa.ai.security.auth-object.attribute")
                            .doesNotContain("LEGACY_HINT_VALUE")
                            .contains("contexa.bridge.authentication.session.attribute")
                            .contains("contexa.bridge.authorization.request-attributes.attribute")
                            .contains("contexa.bridge.delegation.headers.enabled")
                            .contains("ContexaSubjectResolver")
                            .contains("ctxa.subject")
                            .contains("ERROR")
                            .doesNotContain("LEGACY_LOGIN_VO_VALUE")
                            .doesNotContain("AUTHZ_VALUE_7");
                    assertThat(printed.split(REMOVED_SETTINGS_REPORT, -1)).hasSize(2);
                });
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    @DisplayName("남는 bridge 설정(security-context 키, 토큰 위임, 네트워크)만 쓰면 옛 설정 안내를 하지 않는다")
    void theSettingsStillReadAreNotReported(CapturedOutput output) {
        contextRunner.withPropertyValues(
                        "contexa.bridge.authentication.security-context.mfa-keys[0]=mfa",
                        "contexa.bridge.authorization.security-context.role-keys[0]=roles",
                        "contexa.bridge.delegation.token.enabled=true",
                        "contexa.bridge.network.trusted-proxies[0]=10.0.0.0/24")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(output.toString()).doesNotContain(REMOVED_SETTINGS_REPORT);
                });
    }

    @Test
    @DisplayName("환경 변수로 준 옛 설정도 같은 키 이름으로 찾는다")
    void aRemovedSettingGivenAsAnEnvironmentVariableIsFound() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().replace(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                new SystemEnvironmentPropertySource(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                        Map.of("CONTEXA_BRIDGE_AUTHENTICATION_HEADERS_ENABLED", "true",
                                "CONTEXA_BRIDGE_DELEGATION_TOKEN_ENABLED", "true")));

        assertThat(AiBridgeConfiguration.removedBridgeSettings(environment))
                .containsExactly("contexa.bridge.authentication.headers.enabled");
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
                .withUserConfiguration(AiSecurityConfiguration.class, ContexaAdminFlowBeans.class)
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
                Authentication authentication,
                AuthenticationStamp authenticationStamp,
                AuthorizationStamp authorizationStamp,
                RequestContextSnapshot requestContext,
                boolean waitForTheDatabase) {
            synchronizeUserCalls.incrementAndGet();
            return super.synchronizeUser(authentication, authenticationStamp, authorizationStamp, requestContext,
                    waitForTheDatabase);
        }

        int synchronizeUserCalls() {
            return synchronizeUserCalls.get();
        }
    }
}
