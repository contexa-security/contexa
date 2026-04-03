package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.filter.AccountLockoutFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Registers AccountLockoutFilter before UsernamePasswordAuthenticationFilter
 * in every authentication flow. Ensures lockout protection works
 * regardless of which AuthenticationProvider is used.
 */
@Slf4j
public class AccountLockoutConfigurer implements SecurityConfigurer {

    private static final int ORDER = 35;

    private final AccountLockoutFilter accountLockoutFilter;

    public AccountLockoutConfigurer(AccountLockoutFilter accountLockoutFilter) {
        this.accountLockoutFilter = accountLockoutFilter;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        // No initialization needed
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (accountLockoutFilter == null) {
            return;
        }
        fc.http().addFilterBefore(accountLockoutFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
