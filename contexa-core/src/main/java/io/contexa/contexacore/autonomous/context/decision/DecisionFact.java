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
package io.contexa.contexacore.autonomous.context.decision;

import java.util.List;

/**
 * One fact the engine computed for a request (W2-5): what the company records, the usual behaviour and the session
 * say about it, with the reason codes a decision may cite and the records that ground it.
 *
 * @param id        the fact's ID in the prompt ({@code F1}, {@code F2}, ...), the one a reason code cites
 * @param name      the fact's name in the prompt dictionary ({@code DeviationsFromBaseline}, {@code PolicySatisfied}, ...)
 * @param value     the fact in one line
 * @param codes     the reason codes the fact supports ({@code DEVIATION_TIME}, {@code POLICY_NOT_SATISFIED_LATE}, ...)
 * @param recordIds the company records the fact rests on ({@code APR-...}, {@code TCK-...})
 * @param source    the fact's source grade (dictionary 1.2): {@code host} (company records the host stated),
 *                  {@code learned} (what the engine learned from allowed requests) or {@code computed} (what the
 *                  engine computed from the request and the records)
 */
public record DecisionFact(String id, String name, String value, List<String> codes, List<String> recordIds,
                           String source) {

    public static final String HOST = "host";
    public static final String LEARNED = "learned";
    public static final String COMPUTED = "computed";

    public DecisionFact {
        codes = codes == null ? List.of() : List.copyOf(codes);
        recordIds = recordIds == null ? List.of() : List.copyOf(recordIds);
    }
}
