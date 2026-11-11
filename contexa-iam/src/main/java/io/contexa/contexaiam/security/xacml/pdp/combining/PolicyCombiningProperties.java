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
package io.contexa.contexaiam.security.xacml.pdp.combining;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

/**
 * Configuration properties for policy combining algorithm.
 * Default: FIRST_APPLICABLE (priority-ordered, first matching policy decides).
 *
 * <p>The values are the startup defaults. The system settings screen stores operator overrides
 * in {@code ctxa_system_settings}; they are applied to this bean at startup and immediately after
 * every save, so the fields are volatile for safe publication to request threads.</p>
 *
 * <p>A URL no policy names needs a signed-in user by default ({@link NoPolicyDecision#AUTHENTICATED}),
 * as Spring Boot's default chain does; PERMIT keeps such URLs open to everyone. A method without a
 * policy is permitted by default, and AUTHENTICATED is not a decision for methods.</p>
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "contexa.policy")
public class PolicyCombiningProperties {

    private volatile CombiningAlgorithm combiningAlgorithm = CombiningAlgorithm.FIRST_APPLICABLE;

    private volatile NoPolicyDecision noMatchingUrlPolicyDecision = NoPolicyDecision.AUTHENTICATED;

    private volatile NoPolicyDecision missingMethodPolicyDecision = NoPolicyDecision.PERMIT;

    /** A decision of nobody is the default that needs a signed-in user, never PERMIT. */
    public void setNoMatchingUrlPolicyDecision(NoPolicyDecision noMatchingUrlPolicyDecision) {
        this.noMatchingUrlPolicyDecision = noMatchingUrlPolicyDecision != null
                ? noMatchingUrlPolicyDecision
                : NoPolicyDecision.AUTHENTICATED;
    }

    /**
     * The decision for a method without an applicable policy: PERMIT or DENY. A method invocation is no request a person
     * signs in for, so AUTHENTICATED is refused here as any other unknown value is.
     */
    public void setMissingMethodPolicyDecision(NoPolicyDecision missingMethodPolicyDecision) {
        if (missingMethodPolicyDecision == NoPolicyDecision.AUTHENTICATED) {
            throw new IllegalArgumentException(
                    "missingMethodPolicyDecision must be PERMIT or DENY; AUTHENTICATED applies to URL requests only");
        }
        this.missingMethodPolicyDecision = missingMethodPolicyDecision;
    }

    public enum NoPolicyDecision {
        PERMIT,
        DENY,
        /**
         * URL requests only: a signed-in user passes and a request that is not signed in is refused, so it is asked to sign
         * in by the chain's entry point. The requests of the sign-in itself stay open to everyone at the enforcement point.
         */
        AUTHENTICATED;

        private static final AuthenticationTrustResolver TRUST_RESOLVER = new AuthenticationTrustResolverImpl();

        /** Whether the decision grants a request without knowing who makes it: only PERMIT does. */
        public boolean isGranted() {
            return this == PERMIT;
        }

        /** Whether the decision grants a request of this principal, null when there is none. */
        public boolean isGrantedTo(Authentication authentication) {
            return this == PERMIT || (this == AUTHENTICATED && TRUST_RESOLVER.isAuthenticated(authentication));
        }
    }
}
