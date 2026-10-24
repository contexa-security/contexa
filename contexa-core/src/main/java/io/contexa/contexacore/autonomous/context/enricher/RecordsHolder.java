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
package io.contexa.contexacore.autonomous.context.enricher;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import org.springframework.lang.Nullable;

import java.util.Map;

/**
 * Whose company records a request is judged with (docs/agent A2-12), for a host's record providers
 * ({@link FrictionContextProvider}). A person's request is judged with that person's records. An agent's request is
 * judged with the records of the person who answers for it (A1-6): the person it acts for, or else its sponsor, since
 * an agent has no assignment, duty or tickets of its own. A provider looks the records up for {@link #id()} and states
 * the holder with {@link #stateOn(CanonicalSecurityContext)}, so that the prompt says whose records they are.
 *
 * @param id       the user id the records are looked up for
 * @param relation how the holder stands to the request: {@link #SUBJECT}, {@link #DELEGATOR} or {@link #SPONSOR}
 */
public record RecordsHolder(String id, String relation) {

    /** The request's own subject. */
    public static final String SUBJECT = "SUBJECT";
    /** The person a delegated agent acts for. */
    public static final String DELEGATOR = "DELEGATOR";
    /** The registered sponsor of an agent that acts on its own. */
    public static final String SPONSOR = "SPONSOR";

    /** The publisher's payload keys this reads (ZeroTrustEventPublisher A1-6). */
    private static final String SUBJECT_KIND = "executionSubjectKind";
    private static final String ACCOUNTABLE = "agentAccountableId";
    private static final String DELEGATOR_ID = "delegatorId";

    /** The holder of the request's records, or null without a user. */
    @Nullable
    public static RecordsHolder of(@Nullable SecurityEvent event) {
        if (event == null) {
            return null;
        }
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        String user = text(event.getUserId());
        String kind = text(metadata.get(SUBJECT_KIND));
        boolean agent = SubjectKind.DELEGATED_AGENT.name().equals(kind) || SubjectKind.AUTONOMOUS_AGENT.name().equals(kind);
        String accountable = agent ? text(metadata.get(ACCOUNTABLE)) : null;
        if (accountable != null && !accountable.equals(user)) {
            return new RecordsHolder(accountable,
                    accountable.equals(text(metadata.get(DELEGATOR_ID))) ? DELEGATOR : SPONSOR);
        }
        return user != null ? new RecordsHolder(user, SUBJECT) : null;
    }

    /** States on the context's company facts whose records they are. */
    public void stateOn(@Nullable CanonicalSecurityContext context) {
        if (context == null) {
            return;
        }
        if (context.getFrictionProfile() == null) {
            context.setFrictionProfile(new CanonicalSecurityContext.FrictionProfile());
        }
        context.getFrictionProfile().setRecordsHolderId(id);
        context.getFrictionProfile().setRecordsHolderRelation(relation);
    }

    @Nullable
    private static String text(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
