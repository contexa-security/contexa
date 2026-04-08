package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacore.hcad.filter.HCADFilter;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

public class HCADFilterConfigurer implements SecurityConfigurer {

    private static final int ORDER = SecurityConfigurer.HIGHEST_PRECEDENCE + 115;

    private final HCADFilter hcadFilter;

    public HCADFilterConfigurer(HCADFilter hcadFilter) {
        this.hcadFilter = hcadFilter;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        // no-op
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (hcadFilter == null) {
            return;
        }
        fc.http().addFilterBefore(hcadFilter, AuthorizationFilter.class);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}