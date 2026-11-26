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
package io.contexa.contexacommon.security.bridge.subject;

import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * That a request of the user was sent by an AI agent acting for that user, as the application states it: the agent,
 * what it was asked to do, the operations and resources it may use, whether its requests need the user's approval, and
 * until when. An application that signs agents in through OAuth2 token exchange needs none of this: Contexa reads the
 * token's {@code act} claim.
 * <pre>
 * ContexaDelegation.of("report-agent").objective("monthly sales report").approvalRequired(true).build()
 * </pre>
 */
public final class ContexaDelegation {

    /** The most operations or resources Contexa keeps for one delegation. */
    public static final int MAX_ENTRIES = 64;

    private final String agentId;
    @Nullable
    private final String objective;
    private final Set<String> allowedOperations;
    private final Set<String> allowedResources;
    @Nullable
    private final Boolean approvalRequired;
    @Nullable
    private final Instant expiresAt;

    private ContexaDelegation(Builder builder) {
        this.agentId = ContexaSubject.cleanText(builder.agentId, ContexaSubject.MAX_TEXT_LENGTH);
        this.objective = ContexaSubject.cleanText(builder.objective, ContexaSubject.MAX_TEXT_LENGTH);
        this.allowedOperations = entries(builder.allowedOperations);
        this.allowedResources = entries(builder.allowedResources);
        this.approvalRequired = builder.approvalRequired;
        this.expiresAt = builder.expiresAt;
    }

    /** A delegation to the agent the application names. */
    public static Builder of(@Nullable String agentId) {
        return new Builder(agentId);
    }

    /** The agent, or {@code null} when the application named none Contexa can keep. */
    @Nullable
    public String getAgentId() {
        return agentId;
    }

    @Nullable
    public String getObjective() {
        return objective;
    }

    public Set<String> getAllowedOperations() {
        return allowedOperations;
    }

    public Set<String> getAllowedResources() {
        return allowedResources;
    }

    @Nullable
    public Boolean getApprovalRequired() {
        return approvalRequired;
    }

    @Nullable
    public Instant getExpiresAt() {
        return expiresAt;
    }

    /** Whether the delegation names an agent: one that names none is left out of the subject. */
    public boolean namesAnAgent() {
        return agentId != null;
    }

    private static Set<String> entries(Collection<String> values) {
        LinkedHashSet<String> kept = new LinkedHashSet<>();
        for (String value : values) {
            String clean = ContexaSubject.cleanText(value, ContexaSubject.MAX_TEXT_LENGTH);
            if (clean != null && kept.size() < MAX_ENTRIES) {
                kept.add(clean);
            }
        }
        return Collections.unmodifiableSet(kept);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ContexaDelegation that
                && Objects.equals(agentId, that.agentId)
                && Objects.equals(objective, that.objective)
                && allowedOperations.equals(that.allowedOperations)
                && allowedResources.equals(that.allowedResources)
                && Objects.equals(approvalRequired, that.approvalRequired)
                && Objects.equals(expiresAt, that.expiresAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(agentId, objective, allowedOperations, allowedResources, approvalRequired, expiresAt);
    }

    @Override
    public String toString() {
        return "ContexaDelegation[agentId=" + agentId + ", approvalRequired=" + approvalRequired + ", expiresAt="
                + expiresAt + "]";
    }

    /** Builds a delegation; building never throws. */
    public static final class Builder {

        @Nullable
        private final String agentId;
        @Nullable
        private String objective;
        private Collection<String> allowedOperations = Set.of();
        private Collection<String> allowedResources = Set.of();
        @Nullable
        private Boolean approvalRequired;
        @Nullable
        private Instant expiresAt;

        private Builder(@Nullable String agentId) {
            this.agentId = agentId;
        }

        public Builder objective(@Nullable String objective) {
            this.objective = objective;
            return this;
        }

        public Builder allowedOperations(@Nullable Collection<String> operations) {
            this.allowedOperations = operations != null ? operations : Set.of();
            return this;
        }

        public Builder allowedResources(@Nullable Collection<String> resources) {
            this.allowedResources = resources != null ? resources : Set.of();
            return this;
        }

        public Builder approvalRequired(boolean required) {
            this.approvalRequired = required;
            return this;
        }

        public Builder expiresAt(@Nullable Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public ContexaDelegation build() {
            return new ContexaDelegation(this);
        }
    }
}
