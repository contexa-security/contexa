package io.contexa.demo.security.policy;

import io.contexa.demo.security.policy.dto.PolicyRule;
import jakarta.servlet.Filter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SharedLabSecurityPolicy implements LabSecurityPolicy {

    private final ObjectProvider<Filter> comparisonFilter;

    public SharedLabSecurityPolicy(@Qualifier("comparisonDispatchFilter") ObjectProvider<Filter> comparisonFilter) {
        this.comparisonFilter = comparisonFilter;
    }

    public List<PolicyRule> rules() {
        return List.of(new PolicyRule("/api/auth/csrf", "PUBLIC"), new PolicyRule("/api/lab/entry/**", "PUBLIC"),
                new PolicyRule("/api/lab/workspaces/**", "PUBLIC"), new PolicyRule("/api/lab/identity", "PUBLIC"),
                new PolicyRule("/api/lab/scenarios/**", "PUBLIC"),
                new PolicyRule("/api/lab/comparisons/preparations/**", "PUBLIC"),
                new PolicyRule("/api/lab/runs/**", "PUBLIC"),
                new PolicyRule("/api/lab/reports/**", "PUBLIC"),
                new PolicyRule("/api/lab/journeys/**", "PUBLIC"),
                new PolicyRule("/api/lab/factors", "PUBLIC"),
                new PolicyRule("/api/lab/readiness", "PUBLIC"), new PolicyRule("/api/lab/readiness/local", "PUBLIC"),
                new PolicyRule("/api/lab/readiness/**", "ADMIN"), new PolicyRule("/api/lab/access/admin", "ADMIN"),
                new PolicyRule("/api/work/admin/**", "ADMIN"), new PolicyRule("/api/**", "AUTHENTICATED"),
                new PolicyRule("/**", "PUBLIC"));
    }

    public void apply(HttpSecurity http, AuthorizationManager<RequestAuthorizationContext> platform) throws Exception {
        http.authorizeHttpRequests(auth -> rules().forEach(rule -> {
            var match = auth.requestMatchers(rule.pattern());
            if ("PUBLIC".equals(rule.requirement())) {
                match.permitAll();
                return;
            }
            AuthorizationManager<RequestAuthorizationContext> requirement = "ADMIN".equals(rule.requirement())
                    ? AuthorityAuthorizationManager.hasRole("ADMIN") :
                    AuthenticatedAuthorizationManager.authenticated();
            match.access(platform == null ? requirement : AuthorizationManagers.allOf(requirement, platform));
        }));
        http.exceptionHandling(errors -> errors.defaultAuthenticationEntryPointFor(
                (request, response, failure) -> response.sendError(401),
                request -> request.getServletPath().startsWith("/api/")));
        comparisonFilter.ifAvailable(filter -> http.addFilterAfter(filter, CsrfFilter.class));
        http.cors(Customizer.withDefaults());
    }
}
