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
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.BridgeResolutionConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
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
    void shouldStillRegisterBridgeFilterWhenDisabledPropertyIsSet() {
        contextRunner.withPropertyValues("contexa.bridge.enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(BridgeResolutionFilter.class);
                    assertThat(context.getBean(BridgeProperties.class).isEnabled()).isTrue();
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
                    BridgeResolutionFilter filter = context.getBean(BridgeResolutionFilter.class);
                    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
                    request.addHeader("X-Contexa-Principal-Id", "alice");
                    request.addHeader("X-Contexa-Authenticated", "true");
                    request.addHeader("X-Contexa-Authorities", "ROLE_USER");

                    filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

                    assertThat(runtimeSupport.deriveAuthorizationCalls()).isEqualTo(1);
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
        private final AtomicInteger deriveAuthorizationCalls = new AtomicInteger();

        CountingBridgeRuntimeSupport() {
            super(new BridgeProperties(), null);
        }

        @Override
        public Optional<AuthorizationStamp> deriveAuthorizationStamp(
                AuthenticationStamp authenticationStamp,
                String resourceId,
                String action) {
            deriveAuthorizationCalls.incrementAndGet();
            return super.deriveAuthorizationStamp(authenticationStamp, resourceId, action);
        }

        int deriveAuthorizationCalls() {
            return deriveAuthorizationCalls.get();
        }
    }
}
