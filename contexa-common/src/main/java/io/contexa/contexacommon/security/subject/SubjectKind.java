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

/**
 * Who a request acts as (A1-3, AG-1d). Each kind keeps the subject type, execution mode and lineage values Contexa
 * already records, so existing readers see the values they know: both agent kinds are {@code AGENT_RUNTIME} and the
 * execution mode tells an agent acting for a person from one acting on its own, as an access token's {@code act}
 * claim or Microsoft Entra's {@code idtyp} does. {@link SubjectClassifier} decides the kind.
 */
public enum SubjectKind {

    /** A person acting directly. */
    HUMAN_USER("HUMAN_USER", "DIRECT_USER", "DIRECT"),
    /** An agent acting for a person who delegated the work. */
    DELEGATED_AGENT("AGENT_RUNTIME", "DELEGATED_AGENT", "DECLARED"),
    /** An agent acting on its own, for no person. */
    AUTONOMOUS_AGENT("AGENT_RUNTIME", "AUTONOMOUS_AGENT", "DIRECT"),
    /** A service or workload that is neither a person nor an agent, such as a client using its own token. */
    SERVICE_CLIENT("SERVICE_CLIENT", "DIRECT_USER", "DIRECT");

    private final String subjectType;
    private final String executionMode;
    private final String lineageState;

    SubjectKind(String subjectType, String executionMode, String lineageState) {
        this.subjectType = subjectType;
        this.executionMode = executionMode;
        this.lineageState = lineageState;
    }

    public String subjectType() {
        return subjectType;
    }

    public String executionMode() {
        return executionMode;
    }

    public String lineageState() {
        return lineageState;
    }

    public boolean agent() {
        return this == DELEGATED_AGENT || this == AUTONOMOUS_AGENT;
    }

    /**
     * The kind a recorded subject type and execution mode stand for, or {@code null} when the subject type is none
     * of Contexa's. An agent recorded without the delegated mode acted on its own.
     */
    public static SubjectKind from(String subjectType, String executionMode) {
        if (subjectType == null) {
            return null;
        }
        String type = subjectType.trim();
        if (HUMAN_USER.subjectType.equalsIgnoreCase(type)) {
            return HUMAN_USER;
        }
        if (SERVICE_CLIENT.subjectType.equalsIgnoreCase(type)) {
            return SERVICE_CLIENT;
        }
        if (DELEGATED_AGENT.subjectType.equalsIgnoreCase(type)) {
            return executionMode != null && DELEGATED_AGENT.executionMode.equalsIgnoreCase(executionMode.trim())
                    ? DELEGATED_AGENT
                    : AUTONOMOUS_AGENT;
        }
        return null;
    }
}
