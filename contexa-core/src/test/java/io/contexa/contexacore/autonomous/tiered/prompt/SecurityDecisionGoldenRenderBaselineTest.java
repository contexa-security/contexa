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

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * N-GOLD-1: the golden render draws the baseline the sealed prompts state. Each case is rendered with the budget profile
 * its source decision was sealed with; its baseline status line and its line of deviations from the baseline are the
 * sealed prompt's (27 cases). The sealed prompts were drawn before the product version stated records in place of the
 * core's conclusions (V-4), so a deviation is compared without the conclusion the sealed line gave it (unexplained, or
 * explained by a record). N-K5-2: so are its past denied decisions, which the template relearn case draws; their
 * targets are quoted in UNTRUSTED TEXT (A3-5).
 */
class SecurityDecisionGoldenRenderBaselineTest {

    private static final List<String> NAMES = List.of("BaselineStatus", "DeviationsFromBaseline");
    /** How a prompt sealed before N-RATE-1 states its usual rate: counted by clock hours. */
    private static final String CLOCK_HOUR_RATE = " requests per active hour (";
    private static final Pattern COMPARED =
            Pattern.compile("^(.*DeviationsFromBaseline: \\d+ of )(\\d+)( compared.*)$");
    private static final String NOT_COMPARED = "; not compared: ";
    private static final String CLOSEST = "; closest of the past records";
    private static final String RATE_NOT_COMPARED = "rate (no usual rate in the view)";
    /** N-K5-2: the golden case whose sealed prompt draws past denied decisions (an engine template relearn step). */
    private static final String TEMPLATE_RELEARN_CASE = "TPL-ADM-C-50";
    private static final Pattern DENIED = Pattern.compile("^(?:\\[P[0-9]{1,2}] )?(PastDeniedDecision[0-9]+: .*)$");
    /** The target of a sealed past denied decision line, between its action and its decided action. */
    private static final Pattern DENIED_TARGET = Pattern.compile("^(.* [A-Z_]+ )(\\S+)( -> [A-Z_]+ \\(.+\\))$");
    /** The core's conclusion on a deviation, which a sealed line wrote after it and the product version does not. */
    private static final Pattern CONCLUSION = Pattern.compile(" \\((?:unexplained|explained by [^)]+)\\)");

    @Test
    void theBaselineStatusAndTheDeviationsAreTheSealedOnes() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        List<String> differing = new ArrayList<>();
        for (JsonNode goldenCase : golden.cases()) {
            PromptBudgetProfile profile = PromptBudgetProfile.fromKey(goldenCase.path("budgetProfile").asText(),
                    PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);
            String rendered = golden.render(goldenCase, profile, properties).userText();
            String sealed = goldenCase.path("rawUserPrompt").asText();
            for (String name : NAMES) {
                String expected = "DeviationsFromBaseline".equals(name) && sealed.contains(CLOCK_HOUR_RATE)
                        ? withTheRateNotCompared(line(sealed, name)) : line(sealed, name);
                if ("DeviationsFromBaseline".equals(name) && expected != null) {
                    expected = CONCLUSION.matcher(expected).replaceAll("");
                }
                String actual = line(rendered, name);
                if (!Objects.equals(expected, actual)) {
                    differing.add(goldenCase.path("caseKey").asText() + " " + name + "\n  sealed   " + expected
                            + "\n  rendered " + actual);
                }
            }
        }
        assertThat(golden.cases()).hasSize(27);
        assertThat(differing).isEmpty();
    }

    /**
     * N-K5-2 (completion criterion K5): the render draws the past denied decisions the sealed prompt draws, in its
     * order, and the template relearn case draws its three. Each line says its target is in UNTRUSTED TEXT, which quotes
     * the target the sealed line wrote (A3-5). The fact IDs are left out: the golden inputs carry no past record counts
     * (the sealed retrieval results do not keep them), so the render numbers the past records block from its first
     * record.
     */
    @Test
    void thePastDeniedDecisionsAreTheSealedOnes() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        Map<String, List<String>> drawn = new TreeMap<>();
        List<String> differing = new ArrayList<>();
        for (JsonNode goldenCase : golden.cases()) {
            PromptBudgetProfile profile = PromptBudgetProfile.fromKey(goldenCase.path("budgetProfile").asText(),
                    PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);
            String caseKey = goldenCase.path("caseKey").asText();
            String user = golden.render(goldenCase, profile, properties).userText();
            List<String> sealed = new ArrayList<>();
            for (String line : denied(goldenCase.path("rawUserPrompt").asText())) {
                Matcher target = DENIED_TARGET.matcher(line);
                assertThat(target.matches()).as(caseKey + " " + line).isTrue();
                sealed.add(target.group(1) + PastDeniedLines.TARGET_APART + target.group(3));
                String quoted = "source=" + UntrustedTextSources.PAST_RECORD_TARGET + "; \"" + target.group(2) + "\"";
                if (!user.substring(Math.max(0, user.indexOf("=== UNTRUSTED TEXT"))).contains(quoted)) {
                    differing.add(caseKey + " target not quoted: " + quoted);
                }
            }
            List<String> rendered = denied(user);
            if (!sealed.equals(rendered)) {
                differing.add(caseKey + "\n  sealed   " + sealed + "\n  rendered " + rendered);
            }
            if (!rendered.isEmpty()) {
                drawn.put(caseKey, rendered);
            }
        }
        assertThat(differing).isEmpty();
        assertThat(drawn).containsOnlyKeys(TEMPLATE_RELEARN_CASE);
        assertThat(drawn.get(TEMPLATE_RELEARN_CASE)).hasSize(3).contains("PastDeniedDecision2: 09-24 Thu 23:09 "
                + "(5 days before this request) READ " + PastDeniedLines.TARGET_APART
                + " -> CHALLENGE (verified by step-up)");
    }

    /** The PastDeniedDecision lines of a prompt in their order, without their fact IDs. */
    private static List<String> denied(String prompt) {
        List<String> lines = new ArrayList<>();
        for (String line : prompt.split("\n")) {
            Matcher denied = DENIED.matcher(line);
            if (denied.matches()) {
                lines.add(denied.group(1));
            }
        }
        return lines;
    }

    /**
     * N-RATE-1: a golden input sealed before holds a usual rate of clock hours, which this build reads as no usual rate
     * (BaselineView.Counts), so the rate the sealed line compared is not compared in the render: one dimension fewer is
     * compared and the rate is named with why. The rest of the line is the sealed one.
     */
    private static String withTheRateNotCompared(String sealed) {
        Matcher compared = sealed != null ? COMPARED.matcher(sealed) : null;
        if (compared == null || !compared.matches()) {
            return sealed;
        }
        String line = compared.group(1) + (Integer.parseInt(compared.group(2)) - 1) + compared.group(3);
        int closest = line.indexOf(CLOSEST);
        String head = closest < 0 ? line : line.substring(0, closest);
        String tail = closest < 0 ? "" : line.substring(closest);
        return head + (head.contains(NOT_COMPARED) ? ", " : NOT_COMPARED) + RATE_NOT_COMPARED + tail;
    }

    /** The line of the named entry, with its fact ID when it has one; null when the prompt draws no such line. */
    private static String line(String prompt, String name) {
        Pattern entry = Pattern.compile("^(\\[[A-Z][0-9]{1,2}] )?" + name + ": ");
        for (String line : prompt.split("\n")) {
            if (entry.matcher(line).find()) {
                return line;
            }
        }
        return null;
    }
}
