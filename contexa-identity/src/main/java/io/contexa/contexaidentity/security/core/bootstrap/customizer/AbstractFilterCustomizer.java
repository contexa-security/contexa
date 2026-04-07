package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.Filter;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * Base class for filter chain customizers that apply per-flow URLs after http.build().
 */
public abstract class AbstractFilterCustomizer {

    protected RequestMatcher createPostMatcher(String url) {
        return PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, url);
    }

    protected RequestMatcher createGetMatcher(String url) {
        return PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, url);
    }

    protected void setMatcherIfPresent(AbstractAuthenticationProcessingFilter filter, String url) {
        if (StringUtils.hasText(url)) {
            filter.setRequiresAuthenticationRequestMatcher(createPostMatcher(url));
        }
    }

    protected List<Filter> getFilters(DefaultSecurityFilterChain builtChain) {
        return builtChain.getFilters();
    }

    /**
     * Apply per-flow customizations to the filter chain.
     */
    public abstract void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider,
                                    Object context);
}
