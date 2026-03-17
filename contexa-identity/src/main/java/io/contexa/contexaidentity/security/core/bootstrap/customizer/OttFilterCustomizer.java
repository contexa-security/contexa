package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.Filter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter;
import org.springframework.util.StringUtils;

/**
 * Applies per-flow URL prefix to OTT (One-Time Token) filters.
 * Targets: OneTimeTokenAuthenticationFilter, GenerateOneTimeTokenFilter
 */
public class OttFilterCustomizer extends AbstractFilterCustomizer {

    @Override
    public void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider, Object context) {
        String loginProcessingUrl = flowUrlProvider.getOttLoginProcessing();
        String tokenGeneratingUrl = flowUrlProvider.getOttCodeGeneration();

        for (Filter filter : getFilters(builtChain)) {

            // OneTimeTokenAuthenticationFilter - loginProcessingUrl
            if (filter instanceof AbstractAuthenticationProcessingFilter authFilter && isOttAuth(filter)) {
                setMatcherIfPresent(authFilter, loginProcessingUrl);
            }

            // GenerateOneTimeTokenFilter - tokenGeneratingUrl
            if (filter instanceof GenerateOneTimeTokenFilter genFilter && StringUtils.hasText(tokenGeneratingUrl)) {
                genFilter.setRequestMatcher(createPostMatcher(tokenGeneratingUrl));
            }
        }
    }

    private boolean isOttAuth(Filter filter) {
        String name = filter.getClass().getSimpleName();
        return name.contains("OneTimeToken") && name.contains("Authentication");
    }
}
