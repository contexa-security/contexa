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
import java.util.function.Consumer;

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
     * Find and apply an action to each filter of the specified type in the chain.
     */
    protected <T extends Filter> void forEachFilterOfType(DefaultSecurityFilterChain chain, Class<T> type, Consumer<T> action) {
        for (Filter filter : getFilters(chain)) {
            if (type.isInstance(filter)) {
                action.accept(type.cast(filter));
            }
        }
    }

    /**
     * Find the first filter of the specified type, or null if not found.
     */
    @SuppressWarnings("unchecked")
    protected <T extends Filter> T findFilter(DefaultSecurityFilterChain chain, Class<T> type) {
        for (Filter filter : getFilters(chain)) {
            if (type.isInstance(filter)) {
                return (T) filter;
            }
        }
        return null;
    }

    /**
     * Apply per-flow customizations to the filter chain.
     */
    public abstract void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider,
                                    Object context);
}
