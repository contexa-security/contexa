package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.bootstrap.configurer.SecurityConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

public interface SecurityConfigurerProvider {

    List<SecurityConfigurer> getGlobalConfigurers(PlatformContext platformContext, PlatformConfig platformConfig);

    List<SecurityConfigurer>getFlowSpecificConfigurers(
            PlatformContext platformContext,
            PlatformConfig platformConfig,
            HttpSecurity httpForScope
    );
}