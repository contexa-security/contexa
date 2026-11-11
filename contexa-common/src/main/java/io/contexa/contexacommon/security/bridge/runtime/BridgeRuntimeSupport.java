/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacommon.security.bridge.runtime;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.ContexaAccountAuthentication;
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
import io.contexa.contexacommon.security.subject.SubjectClassifier;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.function.BooleanSupplier;

@Slf4j
public class BridgeRuntimeSupport implements DisposableBean {

    private final BridgeProperties properties;
    @Nullable
    private final BridgeUserMirrorSyncService bridgeUserMirrorSyncService;
    private final RequestPathDatabaseGuard requestPathDatabaseGuard;
    private final BooleanSupplier contexaAccountsSignIn;
    private final UserCopyMemory userCopies;

    public BridgeRuntimeSupport(
            BridgeProperties properties,
            @Nullable BridgeUserMirrorSyncService bridgeUserMirrorSyncService) {
        this(properties, bridgeUserMirrorSyncService, new RequestPathDatabaseGuard());
    }

    public BridgeRuntimeSupport(
            BridgeProperties properties,
            @Nullable BridgeUserMirrorSyncService bridgeUserMirrorSyncService,
            RequestPathDatabaseGuard requestPathDatabaseGuard) {
        this(properties, bridgeUserMirrorSyncService, requestPathDatabaseGuard, () -> false);
    }

    /**
     * @param contexaAccountsSignIn whether Contexa's user store is the one that signs the users in, where Contexa owns the
     *                              sign-in: an access token naming a user is then one of Contexa's accounts
     */
    public BridgeRuntimeSupport(
            BridgeProperties properties,
            @Nullable BridgeUserMirrorSyncService bridgeUserMirrorSyncService,
            RequestPathDatabaseGuard requestPathDatabaseGuard,
            BooleanSupplier contexaAccountsSignIn) {
        this.properties = properties != null ? properties : new BridgeProperties();
        this.bridgeUserMirrorSyncService = bridgeUserMirrorSyncService;
        this.requestPathDatabaseGuard = requestPathDatabaseGuard;
        this.contexaAccountsSignIn = contexaAccountsSignIn != null ? contexaAccountsSignIn : () -> false;
        this.userCopies = new UserCopyMemory(Duration.ofSeconds(Math.max(0L,
                this.properties.getSync().getMinRefreshIntervalSeconds())));
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
        attributes.put("authorizationEvidenceState", BridgeSemanticBoundaryPolicy.DERIVED_RUNTIME_FALLBACK);
        List<String> privilegedAuthoritySignals = BridgeSemanticBoundaryPolicy.privilegedAuthoritySignals(effectiveAuthorities);
        if (!privilegedAuthoritySignals.isEmpty()) {
            attributes.put("privilegedAuthoritySignals", privilegedAuthoritySignals);
            attributes.put("privilegedAuthoritySignalPurpose", BridgeSemanticBoundaryPolicy.HEURISTIC_HINT_ONLY);
        }

        return Optional.of(new AuthorizationStamp(
                authenticationStamp.principalId(),
                resourceId,
                action,
                AuthorizationEffect.UNKNOWN,
                null,
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

    /** The copy of the user, waited for (within the guard's bound) when nothing is kept for these facts. */
    @Nullable
    public BridgeUserMirrorSyncResult synchronizeUser(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            RequestContextSnapshot requestContext) {
        return synchronizeUser(null, authenticationStamp, authorizationStamp, requestContext, true);
    }

    /**
     * The copy of the application's user for a request. One of Contexa's own accounts, where Contexa owns the sign-in, is
     * the account itself and has no copy: nothing is looked up for it. Otherwise the copy kept for the very same facts is
     * given back without asking the database. When nothing is kept, a sign-in waits for the synchronisation as it always
     * did (within the guard's bound); any other request is never held by it: the synchronisation runs away from the
     * request, and the request goes on without the copy.
     *
     * @param authentication       the authentication of the request, which tells one of Contexa's own accounts
     * @param waitForTheDatabase   whether this request may wait for Contexa's database (a sign-in, an explicit handoff)
     */
    @Nullable
    public BridgeUserMirrorSyncResult synchronizeUser(
            @Nullable Authentication authentication,
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            RequestContextSnapshot requestContext,
            boolean waitForTheDatabase) {
        if (bridgeUserMirrorSyncService == null || authenticationStamp == null || !authenticationStamp.authenticated()
                || !properties.getSync().isEnabled()) {
            return null;
        }
        if (isContexaAccount(authentication, authenticationStamp)) {
            return null;
        }
        UserCopyMemory.Facts facts = UserCopyMemory.Facts.of(authenticationStamp, authorizationStamp, requestContext);
        if (facts == null) {
            return null;
        }
        UserCopyMemory.Kept kept = userCopies.recall(facts);
        if (kept != null) {
            return kept.result();
        }
        if (!waitForTheDatabase) {
            userCopies.synchroniseAway(facts, () -> synchronise(authenticationStamp, authorizationStamp, requestContext));
            return null;
        }
        Optional<BridgeUserMirrorSyncResult> answer = synchronise(authenticationStamp, authorizationStamp, requestContext);
        if (answer == null) {
            return null;
        }
        userCopies.remember(facts, answer.orElse(null));
        return answer.orElse(null);
    }

    /** One of Contexa's own accounts, the very subject the stamp names. */
    private boolean isContexaAccount(@Nullable Authentication authentication, AuthenticationStamp authenticationStamp) {
        String account = ContexaAccountAuthentication.accountName(authentication, properties, contexaAccountsSignIn);
        return account != null && authenticationStamp.principalId() != null
                && account.equals(authenticationStamp.principalId().trim());
    }

    /**
     * What the synchronisation answers, through the guard: empty when it keeps no copy for the facts, {@code null} when no
     * answer came (the database did not answer in time, or the synchronisation failed).
     */
    @Nullable
    private Optional<BridgeUserMirrorSyncResult> synchronise(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            RequestContextSnapshot requestContext) {
        try {
            return requestPathDatabaseGuard.call(() -> Optional.ofNullable(
                    bridgeUserMirrorSyncService.sync(authenticationStamp, authorizationStamp, requestContext)), null);
        } catch (Exception ex) {
            String principalId = authenticationStamp.principalId() != null ? authenticationStamp.principalId() : "unknown";
            log.error("[Bridge] Failed to synchronize bridge user mirror for principalId: {}", principalId, ex);
            return null;
        }
    }

    @Override
    public void destroy() {
        userCopies.close();
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
            setAttributeIfPresent(request, requestAttributes.getFlatTenantId(), authenticationStamp.attributes().get("tenantId"));
            setAttributeIfPresent(request, requestAttributes.getFlatOrganizationId(), authenticationStamp.attributes().get("organizationId"));
            setAttributeIfPresent(request, requestAttributes.getFlatOrgId(), authenticationStamp.attributes().get("orgId"));
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
        if (!properties.ownershipBehaviour().writesSecurityContext()) {
            return;
        }
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
        if (!properties.ownershipBehaviour().writesSecurityContext() || !properties.isPopulateSecurityContext()) {
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
        SubjectClassifier.Result subjectKind = classifySubject(authenticationStamp, result.delegationStamp());
        String canonicalSubjectType = subjectKind.subjectType();
        String canonicalExecutionMode = subjectKind.executionMode();
        String canonicalLineageState = subjectKind.lineageState();
        String canonicalExecutionId = result.delegationStamp() != null
                ? firstBridgeAttribute(result.delegationStamp(), "executionId", "execution_id", "requestId", "request_id")
                : null;
        String canonicalDelegationId = result.delegationStamp() != null
                ? firstBridgeAttribute(result.delegationStamp(), "delegationId", "delegation_id")
                : null;
        String canonicalProtocolType = firstNonBlank(
                result.delegationStamp() != null
                        ? firstBridgeAttribute(result.delegationStamp(), "protocolType", "protocol_type", "sourceProtocol")
                        : null,
                "HUMAN_SESSION");
        List<String> canonicalApprovedScopes = result.authorizationStamp() != null ? result.authorizationStamp().scopeTags() : List.of();

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
                text(authenticationStamp.attributes().get("tenantId")),
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
                canonicalSubjectType,
                canonicalExecutionMode,
                canonicalLineageState,
                canonicalExecutionId,
                canonicalDelegationId,
                canonicalProtocolType,
                canonicalApprovedScopes,
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
                text(authenticationStamp.attributes().get("tenantId")),
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
    /**
     * A1-3: the same decision the event publisher and the canonical context make. A principal type the bridge only
     * took from a class name states no subject, as the publisher treats it.
     */
    private SubjectClassifier.Result classifySubject(AuthenticationStamp authenticationStamp,
                                                     @Nullable DelegationStamp delegationStamp) {
        String principalType = authenticationStamp != null
                && !BridgeSemanticBoundaryPolicy.CLASS_NAME_FALLBACK.equals(
                        authenticationStamp.attributes().get("principalTypeEvidenceState"))
                ? text(authenticationStamp.principalType())
                : null;
        return SubjectClassifier.classify(SubjectClassifier.Facts.builder()
                .delegated(delegationStamp != null ? delegationStamp.delegated() : null)
                .agentId(delegationStamp != null ? text(delegationStamp.agentId()) : null)
                .delegationId(firstBridgeAttribute(delegationStamp, "delegationId", "delegation_id"))
                .principalType(principalType)
                .build());
    }

    @Nullable
    private String firstBridgeAttribute(@Nullable DelegationStamp delegationStamp, String... keys) {
        if (delegationStamp == null || delegationStamp.attributes() == null) {
            return null;
        }
        for (String key : keys) {
            String value = text(delegationStamp.attributes().get(key));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private void setAttributeIfPresent(HttpServletRequest request, String attributeName, Object value) {
        if (request != null && attributeName != null && !attributeName.isBlank() && value != null) {
            request.setAttribute(attributeName, value);
        }
    }

    @Nullable
    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
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
