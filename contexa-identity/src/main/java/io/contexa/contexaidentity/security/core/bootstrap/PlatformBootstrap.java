package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.validator.DslValidator;
import io.contexa.contexaidentity.security.core.validator.ValidationReportReporter;
import io.contexa.contexaidentity.security.core.validator.ValidationResult;
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
    private final DslValidator dslValidator;

    @Override
    public void afterPropertiesSet() throws Exception {

        List<AuthenticationFlowConfig> flows = config.getFlows();
        List<AuthenticationAdapter> adapters = registry.getAuthAdaptersFor(flows);
        platform.prepareGlobal(config, adapters);

        platform.initialize();

        try {
//            ValidationResult result = dslValidator.validate(config);
//            ValidationReportReporter.reportAndThrowOnError(result, "PlatformSecurityConfig.java (DSL)");
        } catch (DslConfigurationException e) {
            log.error("Server startup aborted due to DSL validation failure.", e);
            throw e;
        }
    }
}
