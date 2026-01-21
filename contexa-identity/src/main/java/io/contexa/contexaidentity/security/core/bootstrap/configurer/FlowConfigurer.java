package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class FlowConfigurer implements SecurityConfigurer {
    @Override
    public void init(PlatformContext ctx, PlatformConfig config) { }

    @Override
    public void configure(FlowContext ctx) {
        Customizer<HttpSecurity> flowCustomizer = ctx.flow().getRawHttpCustomizer();
        if (flowCustomizer == null) {
            return;
        }
        flowCustomizer.customize(ctx.http());
    }

    @Override
    public int getOrder() { return 100; }
}

