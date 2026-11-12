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

import io.contexa.contexacommon.security.bridge.AgentTokenClaims;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacommon.store.RepeatedFailure;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An approved agent signed in with its own account, as a session login does (A1-13, AG-12e). When no token, session,
 * request attribute or header states an agent, the authenticated principal that the {@link AgentClientDirectory} names
 * as an approved agent in service is that agent, acting on its own; a delegation its records state is applied later by
 * the delegation record lookup (A1-4). Every other principal yields no stamp, so a person's request is unchanged.
 */
@Slf4j
public class AgentAccountDelegationStampResolver implements DelegationStampResolver {

    public static final String RESOLVER = "AGENT_ACCOUNT";

    private final AgentClientDirectory agentClientDirectory;
    private final RepeatedFailure lookupFailures = new RepeatedFailure();

    public AgentAccountDelegationStampResolver(AgentClientDirectory agentClientDirectory) {
        this.agentClientDirectory = agentClientDirectory != null ? agentClientDirectory : AgentClientDirectory.NONE;
    }

    @Override
    public Optional<DelegationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext,
                                             BridgeProperties properties) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }
        String account = AgentTokenClaims.text(authentication.getName());
        if (account == null) {
            return Optional.empty();
        }
        Optional<String> agentId;
        try {
            agentId = agentClientDirectory.requestPathActiveAgentForAccount(tenant(authentication, properties), account)
                    .map(AgentTokenClaims::text);
        } catch (RuntimeException lookupFailed) {
            long unreported = lookupFailures.count();
            if (unreported > 0) {
                log.error("The agent registry could not be asked whether account {} is an agent; it is read as a person. "
                        + "{} requests were read that way since this was last said.", account, unreported, lookupFailed);
            }
            return Optional.empty();
        }
        if (agentId.isEmpty()) {
            return Optional.empty();
        }
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("delegationResolver", RESOLVER);
        attributes.put("delegationEvidenceState", BridgeSemanticBoundaryPolicy.AGENT_REGISTRY_RECORD);
        attributes.put("agentAccount", account);
        return Optional.of(new DelegationStamp(account, agentId.get(), false, null, null, null, List.of(), List.of(),
                null, null, null, null, attributes));
    }

    /** The tenant a token names; a session login names none, which is a single-tenant lookup. */
    private static String tenant(Authentication authentication, BridgeProperties properties) {
        Map<String, Object> claims = OAuth2AuthenticationSupport.tokenClaims(authentication);
        if (claims.isEmpty()) {
            return null;
        }
        BridgeProperties.Delegation.Token config = properties != null && properties.getDelegation() != null
                && properties.getDelegation().getToken() != null
                ? properties.getDelegation().getToken()
                : new BridgeProperties.Delegation.Token();
        return AgentTokenClaims.tenant(claims, config);
    }
}
