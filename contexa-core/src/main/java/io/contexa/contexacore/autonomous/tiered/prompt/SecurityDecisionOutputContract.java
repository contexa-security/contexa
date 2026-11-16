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
package io.contexa.contexacore.autonomous.tiered.prompt;

import java.util.List;

/**
 * What the output contracts of the security decision share since the output contract v3 (dictionary 4 and 5, W4-2):
 * the actions, the form of a fact ID a reason cites and one reason as the model gave it. The fields, the reason codes
 * and the schema of the answer are those of the output contract the version asks for (v5, with the v4 answers the
 * response check still reads); the v3 schema, output block and reason codes went with the v20 bundle (plan 6-2).
 */
public final class SecurityDecisionOutputContract {

    public static final List<String> ACTIONS = List.of("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK");
    /** A fact ID the prompt draws: a block letter (USER BASELINE, SESSION, REQUEST, DECISION FACTS, PAST RECORDS). */
    public static final String FACT_ID_PATTERN = "^[BSRFPU][0-9]{1,2}$";

    /** One reason the model gave: a code of the output contract and the ID of the prompt fact it cites. */
    public record Citation(String code, String fact) {
    }

    private SecurityDecisionOutputContract() {
    }
}
