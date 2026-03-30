package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.junit.jupiter.api.Test;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.context.SecurityContextRepository;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionSecurityContextRepositoryConfigurerTest {

    @Test
    void configureShouldRegisterAiSessionSecurityContextRepositoryAsSharedObject() throws Exception {
        AISessionSecurityContextRepository repository = mock(AISessionSecurityContextRepository.class);
        SessionSecurityContextRepositoryConfigurer configurer =
                new SessionSecurityContextRepositoryConfigurer(repository);
        AuthenticationFlowConfig flowConfig = mock(AuthenticationFlowConfig.class);
        HttpSecurity httpSecurity = mock(HttpSecurity.class);
        PlatformContext platformContext = mock(PlatformContext.class);
        PlatformConfig platformConfig = PlatformConfig.builder().build();
        when(flowConfig.getTypeName()).thenReturn("form");

        FlowContext flowContext = new FlowContext(flowConfig, httpSecurity, platformContext, platformConfig);

        configurer.configure(flowContext);

        verify(httpSecurity).setSharedObject(SecurityContextRepository.class, repository);
        verify(httpSecurity).securityContext(any());
    }
}