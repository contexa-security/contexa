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
package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.DecisionBaselines;

import java.util.Optional;

/**
 * Where a sealed package keeps the baselines its decision read, the person's and the organization's: under one key of
 * the baseline snapshot, a section the package hash has always covered. The hash and its schema are as they were, so a
 * package sealed before the baselines were reads, and verifies, as it did.
 *
 * <p>A package with the key says what the decision read: each baseline, or null where there was none. A package
 * without the key was sealed before the baselines were (or its decision read none it could keep) and says nothing
 * about them; whoever replays it has only the baselines kept now.</p>
 */
public final class SealedDecisionBaselines {

    /** The key of the baseline snapshot under which the decision's baselines are sealed. */
    public static final String KEY = "decisionBaselines";

    private static final String PERSONAL = "personal";
    private static final String ORGANIZATION = "organization";

    private SealedDecisionBaselines() {
    }

    /**
     * What the baseline snapshot keeps under {@link #KEY}: both baselines, each an explicit null when the decision
     * found none, so that "there was none" is told from a package that sealed no baselines at all.
     */
    public static ObjectNode write(DecisionBaselines read, ObjectMapper mapper) {
        ObjectNode sealed = mapper.createObjectNode();
        put(sealed, PERSONAL, read.personal(), mapper);
        put(sealed, ORGANIZATION, read.organization(), mapper);
        return sealed;
    }

    /**
     * The baselines the package's decision read; empty for a package that sealed none.
     *
     * @throws IllegalArgumentException when the baseline snapshot or a baseline sealed in it cannot be read: a replay
     *                                  must not take other baselines for the sealed ones without saying so
     */
    public static Optional<DecisionBaselines> read(SealedEvidencePackage sealed, ObjectMapper mapper) {
        String snapshot = sealed != null ? sealed.getBaselineSnapshotJson() : null;
        if (snapshot == null || snapshot.isBlank()) {
            return Optional.empty();
        }
        try {
            JsonNode kept = mapper.readTree(snapshot).get(KEY);
            if (kept == null || !kept.isObject()) {
                return Optional.empty();
            }
            return Optional.of(new DecisionBaselines(vector(kept.get(PERSONAL), mapper),
                    vector(kept.get(ORGANIZATION), mapper)));
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("The baselines sealed in package " + sealed.getPackageId()
                    + " could not be read: " + e.getOriginalMessage(), e);
        }
    }

    private static void put(ObjectNode sealed, String name, BaselineVector baseline, ObjectMapper mapper) {
        if (baseline == null) {
            sealed.putNull(name);
        } else {
            sealed.set(name, mapper.valueToTree(baseline));
        }
    }

    private static BaselineVector vector(JsonNode node, ObjectMapper mapper) throws JsonProcessingException {
        return node == null || node.isNull() ? null : mapper.treeToValue(node, BaselineVector.class);
    }
}
