package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.junit.jupiter.api.Test;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.context.SecurityContextHolderFilter;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BridgeResolutionConfigurerTest {

    @Test
    void configureShouldRegisterBridgeResolutionFilterAfterSecurityContextHolderFilter() throws Exception {
        BridgeResolutionFilter bridgeResolutionFilter = mock(BridgeResolutionFilter.class);
        BridgeResolutionConfigurer configurer = new BridgeResolutionConfigurer(bridgeResolutionFilter);
        AuthenticationFlowConfig flowConfig = mock(AuthenticationFlowConfig.class);
        HttpSecurity httpSecurity = mock(HttpSecurity.class);
        PlatformContext platformContext = mock(PlatformContext.class);
        PlatformConfig platformConfig = PlatformConfig.builder().build();
        when(flowConfig.getTypeName()).thenReturn("form");

        FlowContext flowContext = new FlowContext(flowConfig, httpSecurity, platformContext, platformConfig);

        configurer.configure(flowContext);

        verify(httpSecurity).addFilterAfter(bridgeResolutionFilter, SecurityContextHolderFilter.class);
    }
}
