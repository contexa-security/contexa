package io.contexa.contexacommon.security.bridge.runtime;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationDetails;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationToken;
import io.contexa.contexacommon.security.bridge.authentication.BridgePrincipal;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

@Slf4j
public class BridgeRuntimeSupport {

    private final BridgeProperties properties;
    @Nullable
    private final BridgeUserMirrorSyncService bridgeUserMirrorSyncService;

    public BridgeRuntimeSupport(
            BridgeProperties properties,
            @Nullable BridgeUserMirrorSyncService bridgeUserMirrorSyncService) {
        this.properties = properties != null ? properties : new BridgeProperties();
        this.bridgeUserMirrorSyncService = bridgeUserMirrorSyncService;
    }

    public Optional<AuthorizationStamp> deriveAuthorizationStamp(
            AuthenticationStamp authenticationStamp,
            String resourceId,
            String action) {
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
                resourceId,
                action,
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

    @Nullable
    public BridgeUserMirrorSyncResult synchronizeUser(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            RequestContextSnapshot requestContext) {
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

    public void writeResolutionAttributes(
            HttpServletRequest request,
            BridgeResolutionResult result,
            @Nullable BridgeUserMirrorSyncResult userSyncResult) {
        if (request == null || result == null) {
            return;
        }

        request.setAttribute(BridgeRequestAttributes.RESOLUTION_RESULT, result);
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, result.authenticationStamp());
        request.setAttribute(BridgeRequestAttributes.AUTHORIZATION_STAMP, result.authorizationStamp());
        request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, result.delegationStamp());
        request.setAttribute(BridgeRequestAttributes.COVERAGE_REPORT, result.coverageReport());
        request.setAttribute(BridgeRequestAttributes.USER_SYNC_RESULT, userSyncResult);

        BridgeProperties.RequestAttributes requestAttributes = properties.getAuthentication().getRequestAttributes();
        AuthenticationStamp authenticationStamp = result.authenticationStamp();
        AuthorizationStamp authorizationStamp = result.authorizationStamp();
        DelegationStamp delegationStamp = result.delegationStamp();

        if (authenticationStamp != null) {
            request.setAttribute(requestAttributes.getFlatPrincipalId(), authenticationStamp.principalId());
            request.setAttribute(requestAttributes.getFlatDisplayName(), authenticationStamp.displayName());
            request.setAttribute(requestAttributes.getFlatAuthenticated(), authenticationStamp.authenticated());
            request.setAttribute(requestAttributes.getFlatAuthorities(), String.join(",", authenticationStamp.authorities()));
            request.setAttribute(requestAttributes.getFlatAuthenticationType(), authenticationStamp.authenticationType());
            request.setAttribute(requestAttributes.getFlatAuthenticationAssurance(), authenticationStamp.authenticationAssurance());
            request.setAttribute(requestAttributes.getFlatMfaCompleted(), authenticationStamp.mfaCompleted());
            request.setAttribute(requestAttributes.getFlatAuthenticationTime(), authenticationStamp.authenticationTime());
        }

        if (authorizationStamp != null) {
            request.setAttribute(requestAttributes.getAuthorizationEffect(), authorizationStamp.effect().name());
            request.setAttribute(requestAttributes.getPrivileged(), authorizationStamp.privileged());
            request.setAttribute(requestAttributes.getPolicyId(), authorizationStamp.policyId());
            request.setAttribute(requestAttributes.getPolicyVersion(), authorizationStamp.policyVersion());
            request.setAttribute(requestAttributes.getScopeTags(), authorizationStamp.scopeTags());
            request.setAttribute(requestAttributes.getEffectiveRoles(), authorizationStamp.effectiveRoles());
            request.setAttribute(requestAttributes.getEffectiveAuthorities(), authorizationStamp.effectiveAuthorities());
        }

        if (delegationStamp != null) {
            request.setAttribute(requestAttributes.getDelegated(), delegationStamp.delegated());
            request.setAttribute(requestAttributes.getAgentId(), delegationStamp.agentId());
            request.setAttribute(requestAttributes.getObjectiveId(), delegationStamp.objectiveId());
            request.setAttribute(requestAttributes.getObjectiveFamily(), delegationStamp.objectiveFamily());
            request.setAttribute(requestAttributes.getObjectiveSummary(), delegationStamp.objectiveSummary());
            request.setAttribute(requestAttributes.getAllowedOperations(), delegationStamp.allowedOperations());
            request.setAttribute(requestAttributes.getAllowedResources(), delegationStamp.allowedResources());
            request.setAttribute(requestAttributes.getApprovalRequired(), delegationStamp.approvalRequired());
            request.setAttribute(requestAttributes.getPrivilegedExportAllowed(), delegationStamp.privilegedExportAllowed());
            request.setAttribute(requestAttributes.getContainmentOnly(), delegationStamp.containmentOnly());
            request.setAttribute(requestAttributes.getExpiresAt(), delegationStamp.expiresAt());
        }
    }

    public void persistSecurityContext(
            @Nullable SecurityContextRepository securityContextRepository,
            @Nullable HttpServletRequest request,
            @Nullable HttpServletResponse response) {
        if (securityContextRepository == null || request == null || response == null) {
            return;
        }
        try {
            SecurityContext context = SecurityContextHolder.getContext();
            securityContextRepository.saveContext(context, request, response);
        } catch (Exception ex) {
            log.error("[Bridge] Failed to persist bridge security context.", ex);
        }
    }

    @Nullable
    public BridgeAuthenticationToken populateSecurityContext(
            AuthenticationStamp authenticationStamp,
            BridgeResolutionResult result,
            @Nullable BridgeUserMirrorSyncResult userSyncResult,
            boolean allowOverride) {
        if (!properties.isPopulateSecurityContext()) {
            return null;
        }
        if (authenticationStamp == null || !authenticationStamp.authenticated()) {
            return null;
        }
        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (!allowOverride && currentAuthentication != null && !(currentAuthentication instanceof AnonymousAuthenticationToken)) {
            return null;
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
                result.delegationStamp() != null ? result.delegationStamp().objectiveFamily() : null,
                result.delegationStamp() != null ? result.delegationStamp().objectiveSummary() : null,
                result.delegationStamp() != null ? result.delegationStamp().allowedOperations() : List.of(),
                result.delegationStamp() != null ? result.delegationStamp().allowedResources() : List.of(),
                result.delegationStamp() != null ? result.delegationStamp().approvalRequired() : null,
                result.delegationStamp() != null ? result.delegationStamp().privilegedExportAllowed() : null,
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
        return authenticationToken;
    }

    private boolean isPrivilegedAuthority(String authority) {
        String normalized = authority != null ? authority.toUpperCase() : "";
        return normalized.contains("ADMIN") || normalized.contains("ROOT") || normalized.contains("SUPER") || normalized.contains("PRIVILEGED");
    }

    @Nullable
    private String text(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }
}
