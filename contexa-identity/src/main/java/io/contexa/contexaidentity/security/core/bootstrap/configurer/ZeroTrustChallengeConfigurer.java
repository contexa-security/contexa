package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.filter.DefaultMfaPageGeneratingFilter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustChallengeFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Slf4j
public class ZeroTrustChallengeConfigurer implements SecurityConfigurer {

    private static final int ORDER = 50;

    private final ZeroTrustChallengeFilter zeroTrustChallengeFilter;

    public ZeroTrustChallengeConfigurer(ZeroTrustChallengeFilter zeroTrustChallengeFilter) {
        this.zeroTrustChallengeFilter = zeroTrustChallengeFilter;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        log.debug("ZeroTrustChallengeConfigurer initialized");
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (zeroTrustChallengeFilter == null) {
            log.warn("ZeroTrustChallengeFilter is not available, skipping registration");
            return;
        }

        AuthenticationFlowConfig flowConfig = fc.flow();

        if (!AuthType.MFA.name().equalsIgnoreCase(flowConfig.getTypeName())) {
            log.debug("Skipping MfaPageGeneratingFilter for non-MFA flow: {}", flowConfig.getTypeName());
            return;
        }

        fc.http().addFilterAfter(zeroTrustChallengeFilter, DefaultMfaPageGeneratingFilter.class);
        log.debug("ZeroTrustChallengeFilter registered before LogoutFilter for flow: {}",
                fc.flow().getTypeName());
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
