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
package io.contexa.contexacommon.security.bridge.identity;

import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.subject.ContexaAuthentication;
import io.contexa.contexacommon.security.bridge.subject.ContexaDelegation;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import org.springframework.lang.Nullable;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The stamps the readers of a request's identity read today, made from an identity an application named for Contexa
 * alone (a resolver or the request attribute). Until those readers move to {@link ContexaIdentity} (bridge v2 step B4),
 * this is how the decision, the enforcement, the step-up and the copy of the user see such a user: the copy reads the
 * stamp's {@code email} attribute, as it reads a mail address the application stated.
 */
public final class SubjectStamps {

    /** The {@code authenticationSource} of a user a resolver named. */
    public static final String RESOLVER_SOURCE = "RESOLVER";
    /** The {@code authenticationSource} of a user the application put in the request attribute. */
    public static final String REQUEST_ATTRIBUTE_SOURCE = "REQUEST_ATTRIBUTE";

    private static final String SUBJECT_TYPE = "ContexaSubject";

    private SubjectStamps() {
    }

    /** The authentication stamp of a resolved identity. */
    public static AuthenticationStamp authenticationStamp(ContexaIdentity identity, RequestContextSnapshot requestContext) {
        ContexaSubject subject = subject(identity);
        String source = source(identity);
        ContexaAuthentication facts = subject.getAuthentication();
        String method = facts != null ? facts.getMethod() : null;
        String assurance = facts != null ? facts.getAssurance() : null;
        Boolean mfa = facts != null ? facts.getMfa() : null;

        Map<String, Object> attributes = new LinkedHashMap<>();
        put(attributes, "email", subject.getEmail());
        put(attributes, "tenantId", subject.getTenantId());
        put(attributes, "organizationId", subject.getOrganizationId());
        attributes.put("identitySource", IdentityResolution.name(identity.getSource()));
        attributes.put("principalTypeEvidenceState", BridgeSemanticBoundaryPolicy.CLASS_NAME_FALLBACK);
        attributes.put("authenticationTypeEvidenceState", method != null
                ? BridgeSemanticBoundaryPolicy.EXPLICIT_CUSTOMER_SIGNAL
                : BridgeSemanticBoundaryPolicy.CLASS_NAME_FALLBACK);
        attributes.put("authenticationAssuranceEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(assurance));
        attributes.put("mfaCompletedEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(mfa));
        attributes.put("authenticationTimeEvidenceState",
                BridgeSemanticBoundaryPolicy.explicitOrUnavailable(facts != null ? facts.getAuthenticatedAt() : null));

        String sessionId = subject.getSessionKey() != null ? subject.getSessionKey() : requestContext.sessionId();
        return new AuthenticationStamp(
                subject.getUserId(),
                subject.getDisplayName() != null ? subject.getDisplayName() : subject.getUserId(),
                SUBJECT_TYPE,
                true,
                method != null ? method : source,
                source,
                assurance,
                mfa,
                facts != null ? facts.getAuthenticatedAt() : null,
                sessionId,
                List.copyOf(subject.getAuthorities()),
                attributes
        );
    }

    /** The delegation stamp of a resolved identity whose subject states one. */
    public static Optional<DelegationStamp> delegationStamp(ContexaIdentity identity) {
        ContexaSubject subject = subject(identity);
        ContexaDelegation delegation = subject.getDelegation();
        if (delegation == null) {
            return Optional.empty();
        }
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("delegationResolver", source(identity));
        return Optional.of(new DelegationStamp(
                subject.getUserId(),
                delegation.getAgentId(),
                true,
                null,
                null,
                delegation.getObjective(),
                List.copyOf(delegation.getAllowedOperations()),
                List.copyOf(delegation.getAllowedResources()),
                delegation.getApprovalRequired(),
                null,
                null,
                delegation.getExpiresAt(),
                attributes
        ));
    }

    private static ContexaSubject subject(ContexaIdentity identity) {
        if (!identity.isResolved() || identity.getSubject() == null) {
            throw new IllegalArgumentException("An unresolved identity has no stamp");
        }
        return identity.getSubject();
    }

    private static String source(ContexaIdentity identity) {
        return identity.getSource() == ContexaIdentity.Source.REQUEST_ATTRIBUTE ? REQUEST_ATTRIBUTE_SOURCE : RESOLVER_SOURCE;
    }

    private static void put(Map<String, Object> attributes, String key, @Nullable String value) {
        if (value != null) {
            attributes.put(key, value);
        }
    }
}
