package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.adapter.StateAdapter;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;

public class StateConfigurerAdapter implements SecurityConfigurer {
    private final StateAdapter stateAdapter;
    private final PlatformContext ctx;

    public StateConfigurerAdapter(StateAdapter stateAdapter, PlatformContext ctx) {
        this.stateAdapter = stateAdapter;
        this.ctx = ctx;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        StateConfig state = fc.flow().getStateConfig();
        if (state != null && stateAdapter.getId().equalsIgnoreCase(state.state())) {
            stateAdapter.apply(fc.http(), ctx);
        }
    }

    @Override
    public int getOrder() {
        return 400;
    }
}
