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
package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.util.Optional;

/**
 * Whether the person a delegated agent acts for may make the agent's request (A1-8, AG-11c). An agent acting for a
 * person never gets more than that person may do: the request's policies are evaluated a second time as the delegator,
 * and a request the delegator could not make is refused before any Contexa decision. A request that authenticated as
 * the delegator (an exchanged token whose subject is the person) was already evaluated as the delegator.
 */
@Slf4j
public class DelegatorAuthority {

    /** What the check found; recorded on the request ({@link BridgeRequestAttributes#DELEGATOR_AUTHORITY}). */
    public enum Outcome {
        /** The request authenticated as the delegator, so its own evaluation was the delegator's. */
        CARRIED,
        /** The delegator may make the request. */
        PERMITTED,
        /** The delegator may not make the request; it is refused. */
        DENIED,
        /** The delegator is not known to the source; the request is refused. */
        UNKNOWN,
        /** No source of delegators is configured, so nothing could be checked. */
        UNAVAILABLE
    }

    /**
     * The check prepared for a request.
     *
     * @param delegatorId the person the agent acts for
     * @param outcome     the outcome so far; {@code null} while the delegator's evaluation is still to run
     * @param delegator   the delegator to evaluate the request as, when known
     */
    public record Check(@Nullable String delegatorId, @Nullable Outcome outcome, @Nullable Authentication delegator) {
    }

    @Nullable
    private final DelegatorAuthoritySource source;

    public DelegatorAuthority(@Nullable DelegatorAuthoritySource source) {
        this.source = source;
    }

    /** The check for the request, or empty when the request is not a delegated agent's. */
    public Optional<Check> prepare(@Nullable HttpServletRequest request, @Nullable Authentication requester) {
        if (request == null
                || !(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP) instanceof DelegationStamp stamp)
                || !stamp.delegated() || !hasText(stamp.agentId())) {
            return Optional.empty();
        }
        String delegatorId = hasText(stamp.subjectId()) ? stamp.subjectId().trim() : null;
        if (delegatorId == null) {
            return Optional.of(new Check(null, Outcome.UNKNOWN, null));
        }
        if (requester != null && delegatorId.equals(requester.getName())) {
            return Optional.of(new Check(delegatorId, Outcome.CARRIED, null));
        }
        if (source == null) {
            return Optional.of(new Check(delegatorId, Outcome.UNAVAILABLE, null));
        }
        Optional<Authentication> delegator;
        try {
            delegator = source.authenticationOf(delegatorId);
        } catch (RuntimeException lookupFailed) {
            log.error("The authority of delegator {} could not be read; the agent's request is refused", delegatorId,
                    lookupFailed);
            delegator = Optional.empty();
        }
        return Optional.of(delegator
                .map(authentication -> new Check(delegatorId, null, authentication))
                .orElseGet(() -> new Check(delegatorId, Outcome.UNKNOWN, null)));
    }

    /** Whether the outcome refuses the request. */
    public static boolean refuses(@Nullable Outcome outcome) {
        return outcome == Outcome.DENIED || outcome == Outcome.UNKNOWN;
    }

    /** Records the outcome on the request, so the decision event carries it as a fact of the delegation. */
    public static void record(@Nullable HttpServletRequest request, @Nullable Outcome outcome) {
        if (request != null && outcome != null) {
            request.setAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY, outcome.name());
        }
    }

    private static boolean hasText(@Nullable String value) {
        return value != null && !value.isBlank();
    }
}
