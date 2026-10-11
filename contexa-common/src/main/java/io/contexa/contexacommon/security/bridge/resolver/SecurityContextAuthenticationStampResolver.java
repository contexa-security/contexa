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
package io.contexa.contexacommon.security.bridge.resolver;

import java.time.ZoneId;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.security.bridge.AuthenticationMethodReferences;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class SecurityContextAuthenticationStampResolver implements AuthenticationStampResolver {

    @Override
    public Optional<AuthenticationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        if (properties != null && !properties.getAuthentication().isPreferSecurityContext()) {
            return Optional.empty();
        }
        BridgeProperties.Authentication.SecurityContext config = resolveConfig(properties);
        if (!config.isEnabled()) {
            return Optional.empty();
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }
        String principalId = SecurityContextStampSupport.extractPrincipalId(authentication);
        if (principalId == null) {
            return Optional.empty();
        }
        List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(SecurityContextStampSupport.mergeAttributes(
                authentication.getPrincipal(),
                authentication.getDetails(),
                config.getAttributeKeys()));
        attributes.put("securityContextAuthenticationClass", authentication.getClass().getSimpleName());
        // The signed-in account's creation time, as the user store keeps it (a wall-clock time of this JVM's zone).
        if (authentication.getPrincipal() instanceof UnifiedCustomUserDetails userDetails
                && userDetails.getAccount() != null && userDetails.getAccount().getCreatedAt() != null) {
            attributes.put("accountCreatedAt",
                    userDetails.getAccount().getCreatedAt().atZone(ZoneId.systemDefault()).toInstant().toString());
        }

        List<String> methodReferences = SecurityContextStampSupport.extractStringList(authentication, config.getAmrKeys());
        Boolean mfaCompleted = SecurityContextStampSupport.extractBoolean(authentication, config.getMfaKeys());
        String mfaCompletedEvidenceState = BridgeSemanticBoundaryPolicy.explicitOrUnavailable(mfaCompleted);
        if (mfaCompleted == null && !methodReferences.isEmpty()) {
            mfaCompleted = AuthenticationMethodReferences.multiFactor(methodReferences);
            mfaCompletedEvidenceState = BridgeSemanticBoundaryPolicy.DERIVED_FROM_AMR;
        }
        Instant authenticationTime = SecurityContextStampSupport.extractInstant(authentication, config.getAuthTimeKeys());
        String authenticationType = SecurityContextStampSupport.extractString(authentication, config.getAuthenticationTypeKeys());
        String authenticationTypeEvidenceState = BridgeSemanticBoundaryPolicy.EXPLICIT_CUSTOMER_SIGNAL;
        if (authenticationType == null) {
            authenticationType = AuthenticationMethodReferences.methodName(
                    AuthenticationMethodReferences.methodsOf(methodReferences));
            authenticationTypeEvidenceState = BridgeSemanticBoundaryPolicy.DERIVED_FROM_AMR;
        }
        if (authenticationType == null) {
            // Only the class is known; it names no login method, so the stamp says where the value came from.
            authenticationType = authentication.getClass().getSimpleName();
            authenticationTypeEvidenceState = BridgeSemanticBoundaryPolicy.CLASS_NAME_FALLBACK;
        }
        String authenticationAssurance = SecurityContextStampSupport.extractString(authentication, config.getAuthenticationAssuranceKeys());
        String principalType = SecurityContextStampSupport.extractString(authentication, config.getPrincipalTypeKeys());
        String principalTypeEvidenceState = BridgeSemanticBoundaryPolicy.EXPLICIT_CUSTOMER_SIGNAL;
        if (principalType == null) {
            Object principal = authentication.getPrincipal();
            principalType = principal != null ? principal.getClass().getSimpleName() : "AuthenticationPrincipal";
            principalTypeEvidenceState = BridgeSemanticBoundaryPolicy.CLASS_NAME_FALLBACK;
        }
        attributes.put("authenticationTypeEvidenceState", authenticationTypeEvidenceState);
        attributes.put("principalTypeEvidenceState", principalTypeEvidenceState);
        attributes.put("authenticationAssuranceEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(authenticationAssurance));
        attributes.put("mfaCompletedEvidenceState", mfaCompletedEvidenceState);
        attributes.put("authenticationTimeEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(authenticationTime));

        return Optional.of(new AuthenticationStamp(
                principalId,
                resolveDisplayName(authentication, config),
                principalType,
                true,
                authenticationType,
                "SECURITY_CONTEXT",
                authenticationAssurance,
                mfaCompleted,
                authenticationTime,
                requestContext.sessionId(),
                List.copyOf(new LinkedHashSet<>(authorities)),
                Map.copyOf(attributes)
        ));
    }

    private BridgeProperties.Authentication.SecurityContext resolveConfig(BridgeProperties properties) {
        if (properties == null || properties.getAuthentication() == null || properties.getAuthentication().getSecurityContext() == null) {
            return new BridgeProperties.Authentication.SecurityContext();
        }
        return properties.getAuthentication().getSecurityContext();
    }

    private String resolveDisplayName(Authentication authentication, BridgeProperties.Authentication.SecurityContext config) {
        String extracted = SecurityContextStampSupport.extractString(authentication, config.getDisplayNameKeys());
        if (extracted != null) {
            return extracted;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails userDetails) {
            return userDetails.getUsername();
        }
        String principalId = SecurityContextStampSupport.extractPrincipalId(authentication);
        return principalId != null ? principalId : authentication.getName();
    }
}
