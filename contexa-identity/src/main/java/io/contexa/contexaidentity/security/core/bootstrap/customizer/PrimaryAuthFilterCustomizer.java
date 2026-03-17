package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import io.contexa.contexaidentity.security.filter.MfaFormAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.MfaRestAuthenticationFilter;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.Filter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.util.StringUtils;

/**
 * Applies per-flow URL prefix to MFA primary authentication filters.
 * Targets: MfaFormAuthenticationFilter, MfaRestAuthenticationFilter
 */
public class PrimaryAuthFilterCustomizer extends AbstractFilterCustomizer {

    @Override
    public void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider, Object context) {
        String formUrl = flowUrlProvider.getPrimaryFormLoginProcessing();
        String restUrl = flowUrlProvider.getPrimaryRestLoginProcessing();

        for (Filter filter : getFilters(builtChain)) {
            if (filter instanceof MfaFormAuthenticationFilter formFilter && StringUtils.hasText(formUrl)) {
                formFilter.setRequestMatcher(createPostMatcher(formUrl));
            }

            if (filter instanceof MfaRestAuthenticationFilter restFilter && StringUtils.hasText(restUrl)) {
                restFilter.setRequestMatcher(createPostMatcher(restUrl));
            }
        }
    }
}
