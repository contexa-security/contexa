package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustChallengeFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.logout.LogoutFilter;

/**
 * SecurityConfigurer that registers ZeroTrustChallengeFilter in all SecurityFilterChains.
 * This configurer ensures that Zero Trust CHALLENGE actions trigger MFA flows
 * by detecting ROLE_MFA_REQUIRED authority and initializing the MFA infrastructure.
 *
 * Filter chain order:
 * - ZeroTrustChallengeFilter (before MfaContinuationFilter)
 * - MfaContinuationFilter (handles ongoing MFA flows)
 * - Other authentication filters
 */
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

        fc.http().addFilterBefore(zeroTrustChallengeFilter, LogoutFilter.class);
        log.debug("ZeroTrustChallengeFilter registered before LogoutFilter for flow: {}",
                fc.flow().getTypeName());
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
