package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import io.contexa.contexaidentity.security.filter.DefaultMfaPageGeneratingFilter;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.Filter;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * Injects per-flow AuthUrlProvider into DefaultMfaPageGeneratingFilter.
 * This ensures MFA page generation uses flow-specific URLs with urlPrefix applied.
 */
public class MfaPageFilterCustomizer extends AbstractFilterCustomizer {

    @Override
    public void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider, Object context) {
        for (Filter filter : getFilters(builtChain)) {
            if (filter instanceof DefaultMfaPageGeneratingFilter pageFilter) {
                pageFilter.setAuthUrlProvider(flowUrlProvider);
                return;
            }
        }
    }
}
