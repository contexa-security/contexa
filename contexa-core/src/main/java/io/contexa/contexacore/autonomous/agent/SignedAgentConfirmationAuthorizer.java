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
package io.contexa.contexacore.autonomous.agent;

import io.contexa.contexacore.verification.evidence.EvidenceSigner;

import java.time.temporal.ChronoUnit;
import java.util.Objects;

/**
 * An approval recorded as a keyed signature over the approval's facts (docs/agent A5-2), with the evidence signing
 * keys (A5-6): the authorization when no authorization server of Contexa records it. Its identifier is
 * {@code ctxa-sig:<key id>:<signature>}; a change of any approved fact, or a signature of another key, fails the
 * verification. Its single use is kept by the confirmation store.
 */
public class SignedAgentConfirmationAuthorizer implements AgentConfirmationAuthorizer {

    /** The prefix of the identifiers this authorizer makes. */
    public static final String PREFIX = "ctxa-sig:";

    private final EvidenceSigner signer;

    public SignedAgentConfirmationAuthorizer(EvidenceSigner signer) {
        this.signer = Objects.requireNonNull(signer, "signer");
    }

    @Override
    public String authorize(AgentConfirmation approved) {
        return PREFIX + signer.activeKeyId() + ":" + signer.sign(canonical(approved));
    }

    @Override
    public boolean verify(AgentConfirmation approved) {
        String authorization = approved.authorizationId();
        if (authorization == null || !authorization.startsWith(PREFIX)) {
            return false;
        }
        String rest = authorization.substring(PREFIX.length());
        int separator = rest.indexOf(':');
        if (separator <= 0) {
            return false;
        }
        return Boolean.TRUE.equals(signer.verify(rest.substring(0, separator), canonical(approved),
                rest.substring(separator + 1)));
    }

    /** The approved facts: which request, whose, by whom and when. */
    static String canonical(AgentConfirmation approved) {
        return String.join("|", "ctxa.agent-confirmation.v1", approved.confirmationId(),
                Objects.toString(approved.tenantId(), ""), approved.subjectKind(), approved.userId(),
                approved.agentId(), Objects.toString(approved.delegationId(), ""), approved.recipientId(),
                approved.requestHash(), Objects.toString(approved.decidedBy(), ""),
                approved.decidedAt() != null ? approved.decidedAt().truncatedTo(ChronoUnit.MICROS).toString() : "");
    }
}
