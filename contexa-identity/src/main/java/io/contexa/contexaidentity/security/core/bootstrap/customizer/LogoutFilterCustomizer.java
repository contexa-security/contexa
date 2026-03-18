package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.Filter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;

/**
 * Applies per-flow URL prefix to LogoutFilter's RequestMatcher.
 * Only activates when urlPrefix is set, ensuring the LogoutFilter
 * matches the prefixed logout URL (e.g., /admin/logout).
 */
public class LogoutFilterCustomizer extends AbstractFilterCustomizer {

    @Override
    public void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider, Object context) {
        String urlPrefix = flowUrlProvider.getUrlPrefix();
        if (urlPrefix == null) {
            return;
        }

        String logoutUrl = urlPrefix + "/logout";
        for (Filter filter : getFilters(builtChain)) {
            if (filter instanceof LogoutFilter logoutFilter) {
                logoutFilter.setLogoutRequestMatcher(createPostMatcher(logoutUrl));
            }
        }
    }
}
