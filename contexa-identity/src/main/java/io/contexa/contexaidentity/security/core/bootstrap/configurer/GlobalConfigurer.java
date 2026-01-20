package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;


@Slf4j
public class GlobalConfigurer implements SecurityConfigurer {
    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        log.info("GlobalConfigurer initialized by Platform.");
    }

    @Override
    public void configure(FlowContext ctx) {
        SafeHttpCustomizer<HttpSecurity> customizer = ctx.config().getGlobalCustomizer();
        if (customizer == null) {
            log.debug("No global customizer found for flow: {}", ctx.flow().getTypeName());
            return;
        }
        try {
            log.debug("Applying platform's global customizer for flow: {}", ctx.flow().getTypeName());
            customizer.customize(ctx.http());
        } catch (Exception ex) {
            log.warn("Platform's global customizer failed for flow: {}", ctx.flow().getTypeName(), ex);
        }
    }

    @Override
    public int getOrder() {
        return SecurityConfigurer.HIGHEST_PRECEDENCE + 100;
    }
}

