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
package io.contexa.contexacommon.security.subject;

import java.util.Locale;

/**
 * The one decision of who a request acts as (A1-3, AG-1d), used by the bridge, the event publisher and the canonical
 * context so every record and key names the same {@link SubjectKind}.
 *
 * <p>Agent facts come first: a stated delegation, an agent ID, a delegation ID, an agent execution mode or actor type,
 * or a declared agent subject. Any of them makes the subject an agent even when a host declared a person or a service
 * principal, so an agent's activity is never recorded as a person's. A stated delegation flag outranks a declared
 * execution mode, because the publisher writes a mode before the delegation providers run. An agent whose delegation
 * is not stated is taken as acting on its own: its activity then stays with the agent rather than with a person.
 * A service client lineage the runtime imputed is no delegation, and its client ID in the agent field names no agent.
 */
public final class SubjectClassifier {

    static final String LINEAGE_IMPUTED_SERVICE_CLIENT = "IMPUTED_SERVICE_CLIENT";

    private SubjectClassifier() {
    }

    /** The facts a subject is told from; {@code null} means the fact was not stated. */
    public record Facts(
            Boolean delegated,
            String agentId,
            String delegationId,
            String declaredSubjectType,
            String declaredExecutionMode,
            String declaredLineageState,
            String actorType,
            String principalType,
            boolean serviceClientPrincipal,
            boolean consoleSession) {

        public static Builder builder() {
            return new Builder();
        }

        public static final class Builder {

            private Boolean delegated;
            private String agentId;
            private String delegationId;
            private String declaredSubjectType;
            private String declaredExecutionMode;
            private String declaredLineageState;
            private String actorType;
            private String principalType;
            private boolean serviceClientPrincipal;
            private boolean consoleSession;

            private Builder() {
            }

            public Builder delegated(Boolean delegated) {
                this.delegated = delegated;
                return this;
            }

            public Builder agentId(String agentId) {
                this.agentId = agentId;
                return this;
            }

            public Builder delegationId(String delegationId) {
                this.delegationId = delegationId;
                return this;
            }

            public Builder declaredSubjectType(String declaredSubjectType) {
                this.declaredSubjectType = declaredSubjectType;
                return this;
            }

            public Builder declaredExecutionMode(String declaredExecutionMode) {
                this.declaredExecutionMode = declaredExecutionMode;
                return this;
            }

            public Builder declaredLineageState(String declaredLineageState) {
                this.declaredLineageState = declaredLineageState;
                return this;
            }

            public Builder actorType(String actorType) {
                this.actorType = actorType;
                return this;
            }

            public Builder principalType(String principalType) {
                this.principalType = principalType;
                return this;
            }

            public Builder consoleSession(boolean consoleSession) {
                this.consoleSession = consoleSession;
                return this;
            }

            public Builder serviceClientPrincipal(boolean serviceClientPrincipal) {
                this.serviceClientPrincipal = serviceClientPrincipal;
                return this;
            }

            public Facts build() {
                return new Facts(delegated, agentId, delegationId, declaredSubjectType, declaredExecutionMode,
                        declaredLineageState, actorType, principalType, serviceClientPrincipal, consoleSession);
            }
        }
    }

    /** The kind, with the execution mode and lineage to record for it. */
    public record Result(SubjectKind kind, String executionMode, String lineageState) {

        public String subjectType() {
            return kind.subjectType();
        }
    }

    public static Result classify(Facts facts) {
        Facts given = facts != null ? facts : Facts.builder().build();
        String declaredMode = upper(given.declaredExecutionMode());
        String declaredLineage = text(given.declaredLineageState());
        boolean imputedServiceClient = LINEAGE_IMPUTED_SERVICE_CLIENT.equalsIgnoreCase(declaredLineage);
        Boolean delegation = delegation(given, declaredMode, imputedServiceClient);
        String actorType = upper(given.actorType());

        boolean agent = Boolean.TRUE.equals(delegation)
                || (!imputedServiceClient && text(given.agentId()) != null)
                || SubjectKind.AUTONOMOUS_AGENT.executionMode().equals(declaredMode)
                || (actorType != null && actorType.contains("AGENT"))
                || SubjectKind.DELEGATED_AGENT.subjectType().equalsIgnoreCase(text(given.declaredSubjectType()));
        SubjectKind kind;
        if (given.consoleSession()) {
            kind = SubjectKind.CONSOLE_ADMIN;
        } else if (agent) {
            kind = Boolean.TRUE.equals(delegation) ? SubjectKind.DELEGATED_AGENT : SubjectKind.AUTONOMOUS_AGENT;
        } else if (imputedServiceClient || given.serviceClientPrincipal() || servicePrincipalType(given.principalType())
                || SubjectKind.SERVICE_CLIENT.subjectType().equalsIgnoreCase(text(given.declaredSubjectType()))) {
            kind = SubjectKind.SERVICE_CLIENT;
        } else {
            kind = SubjectKind.HUMAN_USER;
        }

        String executionMode = kind == SubjectKind.SERVICE_CLIENT && imputedServiceClient && declaredMode != null
                ? declaredMode
                : kind.executionMode();
        return new Result(kind, executionMode, lineage(kind, declaredLineage));
    }

    private static Boolean delegation(Facts facts, String declaredMode, boolean imputedServiceClient) {
        if (facts.delegated() != null) {
            return facts.delegated();
        }
        if (imputedServiceClient) {
            return false;
        }
        if (text(facts.delegationId()) != null) {
            return true;
        }
        if (declaredMode != null) {
            if (SubjectKind.DELEGATED_AGENT.executionMode().equals(declaredMode)) {
                return true;
            }
            if (SubjectKind.AUTONOMOUS_AGENT.executionMode().equals(declaredMode)
                    || SubjectKind.HUMAN_USER.executionMode().equals(declaredMode)) {
                return false;
            }
        }
        String actorType = upper(facts.actorType());
        return actorType != null && actorType.contains("DELEGATED") ? Boolean.TRUE : null;
    }

    /** A declared lineage is kept when it agrees with the kind: a delegation's is not direct, the others' not declared. */
    private static String lineage(SubjectKind kind, String declaredLineage) {
        if (declaredLineage == null) {
            return kind.lineageState();
        }
        boolean agrees = kind == SubjectKind.DELEGATED_AGENT
                ? !SubjectKind.HUMAN_USER.lineageState().equalsIgnoreCase(declaredLineage)
                : !SubjectKind.DELEGATED_AGENT.lineageState().equalsIgnoreCase(declaredLineage);
        return agrees ? declaredLineage : kind.lineageState();
    }

    private static boolean servicePrincipalType(String principalType) {
        String normalized = upper(principalType);
        return normalized != null
                && (normalized.contains("SERVICE") || normalized.contains("CLIENT") || normalized.contains("WORKLOAD"));
    }

    private static String upper(String value) {
        String text = text(value);
        return text != null ? text.toUpperCase(Locale.ROOT) : null;
    }

    private static String text(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
