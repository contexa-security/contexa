package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustAccessControlFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Slf4j
public class ZeroTrustAccessControlConfigurer implements SecurityConfigurer {

    private static final int ORDER = 45;

    private final ZeroTrustAccessControlFilter zeroTrustAccessControlFilter;

    public ZeroTrustAccessControlConfigurer(ZeroTrustAccessControlFilter zeroTrustAccessControlFilter) {
        this.zeroTrustAccessControlFilter = zeroTrustAccessControlFilter;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        // No initialization needed
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (zeroTrustAccessControlFilter == null) {
            return;
        }

        fc.http().addFilterBefore(zeroTrustAccessControlFilter, AuthorizationFilter.class);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
