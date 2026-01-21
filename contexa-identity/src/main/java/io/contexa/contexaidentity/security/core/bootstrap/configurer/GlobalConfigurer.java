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
            }

    @Override
    public void configure(FlowContext ctx) {
        SafeHttpCustomizer<HttpSecurity> customizer = ctx.config().getGlobalCustomizer();
        if (customizer == null) {
                        return;
        }
        try {
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

