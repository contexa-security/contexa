package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacore.hcad.filter.HCADFilter;
import io.contexa.contexacore.hcad.trigger.AuthenticatedPendingAnomalyTriggerFilter;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;

public class PendingAnomalyTriggerConfigurer implements SecurityConfigurer {

    private static final int ORDER = SecurityConfigurer.HIGHEST_PRECEDENCE + 116;

    private final AuthenticatedPendingAnomalyTriggerFilter authenticatedPendingAnomalyTriggerFilter;

    public PendingAnomalyTriggerConfigurer(AuthenticatedPendingAnomalyTriggerFilter authenticatedPendingAnomalyTriggerFilter) {
        this.authenticatedPendingAnomalyTriggerFilter = authenticatedPendingAnomalyTriggerFilter;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        // no-op
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (authenticatedPendingAnomalyTriggerFilter == null) {
            return;
        }
        fc.http().addFilterAfter(authenticatedPendingAnomalyTriggerFilter, HCADFilter.class);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}