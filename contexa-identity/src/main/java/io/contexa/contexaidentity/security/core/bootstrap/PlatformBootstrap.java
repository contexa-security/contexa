package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.validator.DslValidatorService;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class PlatformBootstrap implements InitializingBean {

    private final SecurityPlatform platform;
    private final PlatformConfig config;
    private final AdapterRegistry registry;
    private final DslValidatorService dslValidatorService;

    @Override
    public void afterPropertiesSet() throws Exception {

        List<AuthenticationFlowConfig> flows = config.getFlows();
        List<AuthenticationAdapter> adapters = registry.getAuthAdaptersFor(flows);
        platform.prepareGlobal(config, adapters);

        platform.initialize();

        try {
            dslValidatorService.validate(config, "PlatformSecurityConfig.java (DSL)");

        } catch (DslConfigurationException e) {
            log.error("Server startup aborted due to DSL validation failure.", e);
            throw e;
        }
    }
}
