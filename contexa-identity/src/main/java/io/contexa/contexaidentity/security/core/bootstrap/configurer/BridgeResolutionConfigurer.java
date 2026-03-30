package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.security.web.context.SecurityContextHolderFilter;

public class BridgeResolutionConfigurer implements SecurityConfigurer {

    private static final int ORDER = SecurityConfigurer.HIGHEST_PRECEDENCE + 110;

    private final BridgeResolutionFilter bridgeResolutionFilter;

    public BridgeResolutionConfigurer(BridgeResolutionFilter bridgeResolutionFilter) {
        this.bridgeResolutionFilter = bridgeResolutionFilter;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        // no-op
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (bridgeResolutionFilter == null) {
            return;
        }
        fc.http().addFilterAfter(bridgeResolutionFilter, SecurityContextHolderFilter.class);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
