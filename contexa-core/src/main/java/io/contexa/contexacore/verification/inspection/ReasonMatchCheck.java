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
package io.contexa.contexacore.verification.inspection;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;

import java.util.ArrayList;
import java.util.List;

/**
 * W4-8 (VR-5, redesign 3.2): the reason codes of the sealed decision against the facts they cite, by the function the
 * response checker runs ({@link SecurityDecisionFactChecks#reasonFindings}): the ID is on a line of the prompt the model
 * got, that line is one the code cites, and the code's condition holds on the sealed canonical context. A condition
 * whose facts the sealed context does not hold, or that needs the host's rule settings (the minimum action rules),
 * cannot be told here. A decision without reason codes (a v19 decision, a fallback) has nothing to check.
 */
public final class ReasonMatchCheck implements PromptInspectionCheck {

    public static final String CODE = "REASON_MATCH";
    private static final String SOURCE = "decision.reasonCodes";
    private static final ObjectMapper JSON = new ObjectMapper();

    @Override
    public String code() {
        return CODE;
    }

    @Override
    public boolean dictionaryPromptOnly() {
        return true;
    }

    @Override
    public void inspect(PromptInspectionTally tally) {
        PromptInspectionSubject subject = tally.subject();
        List<SecurityDecisionOutputContract.Citation> citations;
        try {
            citations = citations(subject.evidencePackage().getDecisionJson());
        }
        catch (JsonProcessingException exception) {
            tally.unverifiable(tally.unverifiableFinding().sourceRef(SOURCE)
                    .reason("the sealed decision does not read: " + exception.getOriginalMessage()).build());
            return;
        }
        if (citations.isEmpty()) {
            return;
        }
        SecurityDecisionFactChecks.DrawnPrompt drawn =
                SecurityDecisionFactChecks.DrawnPrompt.of(subject.evidencePackage().getUserPromptText());
        for (SecurityDecisionFactChecks.ReasonFinding finding : SecurityDecisionFactChecks.reasonFindings(
                subject.canonicalContext(), null, drawn, citations)) {
            InspectedPrompt.Line line = lineOf(subject.prompt(), finding.fact(), drawn);
            String block = line != null && line.block() != null ? line.block().title() : null;
            Integer number = line != null ? line.number() : null;
            switch (finding.outcome()) {
                case MATCH -> {
                    if (line != null) {
                        tally.matched(line);
                    }
                    else {
                        tally.matched();
                    }
                }
                case MISMATCH -> tally.mismatch(tally.mismatchFinding().block(block).entry(finding.code())
                        .factId(finding.fact()).lineNumber(number).actual(finding.fact()).sourceRef(SOURCE)
                        .reason(finding.reason()).build());
                default -> tally.unverifiable(tally.unverifiableFinding().block(block).entry(finding.code())
                        .factId(finding.fact()).lineNumber(number).sourceRef(SOURCE).reason(finding.reason()).build());
            }
        }
    }

    /** The cited line: the line a line ID names, or the UNKNOWN line for an ID it gives; null when the prompt has none. */
    private static InspectedPrompt.Line lineOf(InspectedPrompt prompt, String fact,
                                               SecurityDecisionFactChecks.DrawnPrompt drawn) {
        boolean unknown = drawn.unknownIds().containsKey(fact);
        for (InspectedPrompt.Line line : prompt.lines()) {
            if (fact.equals(line.factId())) {
                return line;
            }
            if (unknown && line.block() == PromptBlock.UNKNOWN && line.entryLine() != null
                    && "Unknown".equals(line.entryLine().label())) {
                return line;
            }
        }
        return null;
    }

    /** The reason codes the sealed decision keeps (W4-3): each code with the fact ID it cites. */
    private static List<SecurityDecisionOutputContract.Citation> citations(String decisionJson)
            throws JsonProcessingException {
        List<SecurityDecisionOutputContract.Citation> citations = new ArrayList<>();
        if (decisionJson == null || decisionJson.isBlank()) {
            return citations;
        }
        for (JsonNode code : JSON.readTree(decisionJson).path("reasonCodes")) {
            String name = code.path("code").asText(null);
            if (name != null) {
                citations.add(new SecurityDecisionOutputContract.Citation(name, code.path("fact").asText(null)));
            }
        }
        return citations;
    }
}
