package io.contexa.contexacommon.security.bridge.web;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.resolver.AuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.AuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.DelegationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

public class BridgeResolutionFilter extends OncePerRequestFilter {

    private final BridgeProperties properties;
    private final RequestContextCollector requestContextCollector;
    private final List<AuthenticationStampResolver> authenticationStampResolvers;
    private final List<AuthorizationStampResolver> authorizationStampResolvers;
    private final List<DelegationStampResolver> delegationStampResolvers;
    private final BridgeCoverageEvaluator bridgeCoverageEvaluator;

    public BridgeResolutionFilter(
            BridgeProperties properties,
            RequestContextCollector requestContextCollector,
            List<AuthenticationStampResolver> authenticationStampResolvers,
            List<AuthorizationStampResolver> authorizationStampResolvers,
            List<DelegationStampResolver> delegationStampResolvers,
            BridgeCoverageEvaluator bridgeCoverageEvaluator) {
        this.properties = properties != null ? properties : new BridgeProperties();
        this.requestContextCollector = requestContextCollector;
        this.authenticationStampResolvers = authenticationStampResolvers != null ? List.copyOf(authenticationStampResolvers) : List.of();
        this.authorizationStampResolvers = authorizationStampResolvers != null ? List.copyOf(authorizationStampResolvers) : List.of();
        this.delegationStampResolvers = delegationStampResolvers != null ? List.copyOf(delegationStampResolvers) : List.of();
        this.bridgeCoverageEvaluator = bridgeCoverageEvaluator;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !properties.isEnabled();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        RequestContextSnapshot requestContext = requestContextCollector.collect(request);
        AuthenticationStamp authenticationStamp = resolveAuthenticationStamp(request, requestContext).orElse(null);
        AuthorizationStamp authorizationStamp = resolveAuthorizationStamp(request, requestContext).orElse(null);
        DelegationStamp delegationStamp = resolveDelegationStamp(request, requestContext).orElse(null);

        BridgeResolutionResult result = new BridgeResolutionResult(
                requestContext,
                authenticationStamp,
                authorizationStamp,
                delegationStamp,
                bridgeCoverageEvaluator.evaluate(authenticationStamp, authorizationStamp, delegationStamp)
        );

        request.setAttribute(BridgeRequestAttributes.RESOLUTION_RESULT, result);
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, authenticationStamp);
        request.setAttribute(BridgeRequestAttributes.AUTHORIZATION_STAMP, authorizationStamp);
        request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, delegationStamp);
        request.setAttribute(BridgeRequestAttributes.COVERAGE_REPORT, result.coverageReport());

        populateSecurityContext(authenticationStamp, result);
        filterChain.doFilter(request, response);
    }

    private Optional<AuthenticationStamp> resolveAuthenticationStamp(HttpServletRequest request, RequestContextSnapshot requestContext) {
        for (AuthenticationStampResolver resolver : authenticationStampResolvers) {
            Optional<AuthenticationStamp> resolved = resolver.resolve(request, requestContext, properties);
            if (resolved.isPresent() && resolved.get().principalId() != null && !resolved.get().principalId().isBlank()) {
                return resolved;
            }
        }
        return Optional.empty();
    }

    private Optional<AuthorizationStamp> resolveAuthorizationStamp(HttpServletRequest request, RequestContextSnapshot requestContext) {
        for (AuthorizationStampResolver resolver : authorizationStampResolvers) {
            Optional<AuthorizationStamp> resolved = resolver.resolve(request, requestContext, properties);
            if (resolved.isPresent()) {
                return resolved;
            }
        }
        return Optional.empty();
    }

    private Optional<DelegationStamp> resolveDelegationStamp(HttpServletRequest request, RequestContextSnapshot requestContext) {
        for (DelegationStampResolver resolver : delegationStampResolvers) {
            Optional<DelegationStamp> resolved = resolver.resolve(request, requestContext, properties);
            if (resolved.isPresent()) {
                return resolved;
            }
        }
        return Optional.empty();
    }

    private void populateSecurityContext(AuthenticationStamp authenticationStamp, BridgeResolutionResult result) {
        if (!properties.isPopulateSecurityContext()) {
            return;
        }
        if (authenticationStamp == null || !authenticationStamp.authenticated()) {
            return;
        }
        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (currentAuthentication != null && !(currentAuthentication instanceof AnonymousAuthenticationToken)) {
            return;
        }
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                authenticationStamp.principalId(),
                null,
                authenticationStamp.authorities().stream().map(SimpleGrantedAuthority::new).toList()
        );
        LinkedHashMap<String, Object> details = new LinkedHashMap<>();
        details.put("bridgeSource", authenticationStamp.authenticationSource());
        details.put("bridgeCoverageLevel", result.coverageReport().level().name());
        details.put("bridgeCoverageScore", result.coverageReport().score());
        details.put("bridgeAuthenticationType", authenticationStamp.authenticationType());
        details.put("bridgeAuthenticationAssurance", authenticationStamp.authenticationAssurance());
        authenticationToken.setDetails(details);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }
}
