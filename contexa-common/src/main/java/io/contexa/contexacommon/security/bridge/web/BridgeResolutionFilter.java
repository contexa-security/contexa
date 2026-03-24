package io.contexa.contexacommon.security.bridge.web;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationDetails;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationToken;
import io.contexa.contexacommon.security.bridge.authentication.BridgePrincipal;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.resolver.AuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.AuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.DelegationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

@Slf4j
public class BridgeResolutionFilter extends OncePerRequestFilter {

    private final BridgeProperties properties;
    private final RequestContextCollector requestContextCollector;
    private final List<AuthenticationStampResolver> authenticationStampResolvers;
    private final List<AuthorizationStampResolver> authorizationStampResolvers;
    private final List<DelegationStampResolver> delegationStampResolvers;
    private final BridgeCoverageEvaluator bridgeCoverageEvaluator;
    @Nullable
    private final BridgeUserMirrorSyncService bridgeUserMirrorSyncService;

    public BridgeResolutionFilter(
            BridgeProperties properties,
            RequestContextCollector requestContextCollector,
            List<AuthenticationStampResolver> authenticationStampResolvers,
            List<AuthorizationStampResolver> authorizationStampResolvers,
            List<DelegationStampResolver> delegationStampResolvers,
            BridgeCoverageEvaluator bridgeCoverageEvaluator) {
        this(
                properties,
                requestContextCollector,
                authenticationStampResolvers,
                authorizationStampResolvers,
                delegationStampResolvers,
                bridgeCoverageEvaluator,
                null
        );
    }

    public BridgeResolutionFilter(
            BridgeProperties properties,
            RequestContextCollector requestContextCollector,
            List<AuthenticationStampResolver> authenticationStampResolvers,
            List<AuthorizationStampResolver> authorizationStampResolvers,
            List<DelegationStampResolver> delegationStampResolvers,
            BridgeCoverageEvaluator bridgeCoverageEvaluator,
            @Nullable BridgeUserMirrorSyncService bridgeUserMirrorSyncService) {
        this.properties = properties != null ? properties : new BridgeProperties();
        this.requestContextCollector = requestContextCollector;
        this.authenticationStampResolvers = authenticationStampResolvers != null ? List.copyOf(authenticationStampResolvers) : List.of();
        this.authorizationStampResolvers = authorizationStampResolvers != null ? List.copyOf(authorizationStampResolvers) : List.of();
        this.delegationStampResolvers = delegationStampResolvers != null ? List.copyOf(delegationStampResolvers) : List.of();
        this.bridgeCoverageEvaluator = bridgeCoverageEvaluator;
        this.bridgeUserMirrorSyncService = bridgeUserMirrorSyncService;
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
        AuthorizationStamp authorizationStamp = resolveAuthorizationStamp(request, requestContext)
                .or(() -> deriveAuthorizationStamp(authenticationStamp, requestContext))
                .orElse(null);
        DelegationStamp delegationStamp = resolveDelegationStamp(request, requestContext).orElse(null);
        BridgeUserMirrorSyncResult userSyncResult = synchronizeUser(authenticationStamp, authorizationStamp, requestContext);

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
        request.setAttribute(BridgeRequestAttributes.USER_SYNC_RESULT, userSyncResult);

        populateSecurityContext(authenticationStamp, result, userSyncResult);
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

    private Optional<AuthorizationStamp> deriveAuthorizationStamp(AuthenticationStamp authenticationStamp, RequestContextSnapshot requestContext) {
        if (authenticationStamp == null || authenticationStamp.authorities().isEmpty()) {
            return Optional.empty();
        }

        LinkedHashSet<String> effectiveRoles = new LinkedHashSet<>();
        LinkedHashSet<String> effectiveAuthorities = new LinkedHashSet<>();
        for (String authority : authenticationStamp.authorities()) {
            if (authority == null || authority.isBlank()) {
                continue;
            }
            effectiveAuthorities.add(authority);
            if (authority.startsWith("ROLE_")) {
                effectiveRoles.add(authority);
            }
        }
        if (effectiveRoles.isEmpty() && effectiveAuthorities.isEmpty()) {
            return Optional.empty();
        }

        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("authorizationResolver", "AUTHENTICATION_DERIVED");
        attributes.put("derivedFromAuthenticationSource", authenticationStamp.authenticationSource());

        return Optional.of(new AuthorizationStamp(
                authenticationStamp.principalId(),
                requestContext.requestUri(),
                requestContext.method(),
                AuthorizationEffect.UNKNOWN,
                effectiveAuthorities.stream().anyMatch(this::isPrivilegedAuthority),
                List.of(),
                null,
                null,
                "AUTHENTICATION_DERIVED",
                Instant.now(),
                List.copyOf(effectiveRoles),
                List.copyOf(effectiveAuthorities),
                attributes
        ));
    }

    private BridgeUserMirrorSyncResult synchronizeUser(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            RequestContextSnapshot requestContext
    ) {
        if (bridgeUserMirrorSyncService == null || authenticationStamp == null || !authenticationStamp.authenticated()) {
            return null;
        }
        try {
            return bridgeUserMirrorSyncService.sync(authenticationStamp, authorizationStamp, requestContext);
        } catch (Exception ex) {
            String principalId = authenticationStamp.principalId() != null ? authenticationStamp.principalId() : "unknown";
            log.error("[Bridge] Failed to synchronize bridge user mirror for principalId: {}", principalId, ex);
            return null;
        }
    }

    private void populateSecurityContext(
            AuthenticationStamp authenticationStamp,
            BridgeResolutionResult result,
            BridgeUserMirrorSyncResult userSyncResult
    ) {
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

        String internalUsername = userSyncResult != null && text(userSyncResult.internalUsername()) != null
                ? text(userSyncResult.internalUsername())
                : authenticationStamp.principalId();
        String bridgeSubjectKey = userSyncResult != null ? text(userSyncResult.bridgeSubjectKey()) : null;
        Long internalUserId = userSyncResult != null ? userSyncResult.internalUserId() : null;
        String externalSubjectId = authenticationStamp.principalId();

        BridgeAuthenticationDetails details = new BridgeAuthenticationDetails(
                authenticationStamp.authenticationSource(),
                result.authorizationStamp() != null ? result.authorizationStamp().decisionSource() : null,
                result.delegationStamp() != null ? text(result.delegationStamp().attributes().get("delegationResolver")) : null,
                result.coverageReport().level().name(),
                result.coverageReport().score(),
                result.coverageReport().missingContexts().stream().map(Enum::name).toList(),
                result.coverageReport().summary(),
                result.coverageReport().remediationHints(),
                authenticationStamp.authenticationType(),
                authenticationStamp.authenticationAssurance(),
                authenticationStamp.mfaCompleted(),
                text(authenticationStamp.attributes().get("organizationId")),
                text(authenticationStamp.attributes().get("orgId")),
                text(authenticationStamp.attributes().get("department")),
                result.authorizationStamp() != null ? result.authorizationStamp().effect().name() : null,
                result.authorizationStamp() != null ? result.authorizationStamp().privileged() : null,
                result.authorizationStamp() != null ? result.authorizationStamp().policyId() : null,
                result.authorizationStamp() != null ? result.authorizationStamp().policyVersion() : null,
                result.authorizationStamp() != null ? result.authorizationStamp().scopeTags() : List.of(),
                result.authorizationStamp() != null ? result.authorizationStamp().effectiveRoles() : List.of(),
                result.authorizationStamp() != null ? result.authorizationStamp().effectiveAuthorities() : List.of(),
                result.delegationStamp() != null ? result.delegationStamp().delegated() : null,
                result.delegationStamp() != null ? result.delegationStamp().agentId() : null,
                result.delegationStamp() != null ? result.delegationStamp().objectiveId() : null,
                result.delegationStamp() != null ? result.delegationStamp().objectiveSummary() : null,
                result.delegationStamp() != null ? result.delegationStamp().allowedOperations() : List.of(),
                result.delegationStamp() != null ? result.delegationStamp().allowedResources() : List.of(),
                result.delegationStamp() != null ? result.delegationStamp().approvalRequired() : null,
                result.delegationStamp() != null ? result.delegationStamp().containmentOnly() : null,
                internalUserId,
                internalUsername,
                bridgeSubjectKey,
                externalSubjectId,
                userSyncResult != null ? userSyncResult.bridgeManaged() : null,
                userSyncResult != null ? userSyncResult.externalAuthOnly() : null
        );
        BridgePrincipal principal = new BridgePrincipal(
                internalUsername,
                externalSubjectId,
                authenticationStamp.displayName(),
                authenticationStamp.principalType(),
                text(authenticationStamp.attributes().get("organizationId")),
                text(authenticationStamp.attributes().get("orgId")),
                text(authenticationStamp.attributes().get("department")),
                internalUserId,
                bridgeSubjectKey,
                userSyncResult != null && userSyncResult.bridgeManaged(),
                userSyncResult != null && userSyncResult.externalAuthOnly()
        );
        BridgeAuthenticationToken authenticationToken = new BridgeAuthenticationToken(
                principal,
                authenticationStamp.authorities().stream().map(SimpleGrantedAuthority::new).toList(),
                details
        );
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }

    private boolean isPrivilegedAuthority(String authority) {
        String normalized = authority != null ? authority.toUpperCase() : "";
        return normalized.contains("ADMIN") || normalized.contains("ROOT") || normalized.contains("SUPER") || normalized.contains("PRIVILEGED");
    }

    private String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }
}

