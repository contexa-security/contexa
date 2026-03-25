package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.security.bridge.AuthBridge;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.handoff.ContexaAuthBridge;
import io.contexa.contexacommon.security.bridge.handoff.ContexaAuthBridgeHandler;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class AiBridgeConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(AiBridgeConfiguration.class);

    @AfterEach
    void tearDown() {
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
    void shouldNotRegisterBridgeFilterWhenDisabled() {
        contextRunner.withPropertyValues("contexa.bridge.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(BridgeResolutionFilter.class));
    }
}