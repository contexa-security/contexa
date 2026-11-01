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

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CQ-1 (argument origin), proof 1 of design section 5: a host that gives no argument origins gets the user prompt it got
 * before the feature. The golden inputs are rendered by the v21 bundle for the L1 and L2 profiles and for the second
 * passes, and the sha-256 of each user prompt must be the one recorded from the code before the feature
 * ({@code v21-user-text-digests-before-argument-origins.txt}). The system text is not part of it: it lists the output
 * contract's reason codes, so a new code changes it by design.
 *
 * <p>When the user prompt layout is changed on purpose, record the digests again: run this test with the environment
 * variable {@code CONTEXA_PIN_CAPTURE} set to the path of the resource file; it then writes the file instead of
 * comparing.</p>
 */
class V21UserPromptByteIdentityTest {

    static final String PINNED = "prompt-bundles/golden/cortex.security-decision/"
            + "v21-user-text-digests-before-argument-origins.txt";
    /** BR-C6: the v19 and v20 user prompts as they were before the past record lines of a v21 prompt got new fields. */
    static final String PINNED_V19_V20 = "prompt-bundles/golden/cortex.security-decision/"
            + "v19-v20-user-text-digests-before-past-record-fields.txt";

    /**
     * BR-C6: the new past record fields (where a record was learned and which arguments came from a tool's output) belong
     * to the v21 dictionary alone. The v19 and the v20 bundles render every golden case, both profiles and the v20 second
     * passes as they did before, byte for byte.
     */
    @Test
    void everyGoldenV19AndV20UserPromptIsTheOneRenderedBeforeThePastRecordFields() throws IOException {
        Map<String, String> now = new LinkedHashMap<>();
        now.putAll(userTextDigests(SecurityDecisionPromptBundles.DEFAULT, "v19/"));
        now.putAll(userTextDigests(SecurityDecisionPromptBundles.V20, "v20/"));
        String capture = System.getenv("CONTEXA_PIN_CAPTURE_V19_V20");
        if (capture != null && !capture.isBlank()) {
            write(capture, now);
            return;
        }
        assertThat(differences(now, pinned(PINNED_V19_V20))).as("v19 and v20 user prompts that changed").isEmpty();
    }

    /** BR-C6: the v21 user prompts as v21.19 renders them: the past record lines carry the learned field. */
    static final String PINNED_V21_19 = "prompt-bundles/golden/cortex.security-decision/"
            + "v21-user-text-digests-v21-19.txt";
    /** What the fields BR-C6 added write on a record the golden inputs hold: nothing is known of its source. */
    private static final String LEARNED_FIELD_OF_THE_GOLDEN_RECORDS = " / learned: source not recorded";
    private static final Pattern PAST_RECORD_LINE = Pattern.compile("^(\\[[A-Z]\\d+\\] )?(New)?PastRecord\\d+: .*$",
            Pattern.MULTILINE);

    /**
     * CQ-1 and BR-C6, proof 1 of the designs (section 5): the user prompt of a request is the one it was before the two
     * features, except where BR-C6 changes it on purpose, and that is the past record lines alone.
     * <ul>
     * <li>A golden prompt without a past record line is the prompt of v21.17 (before CQ-1), byte for byte.</li>
     * <li>A golden prompt with past record lines is the prompt of v21.17 once the learned field is taken out of those
     * lines, and it is the prompt v21.19 is pinned to ({@code v21-user-text-digests-v21-19.txt}).</li>
     * </ul>
     */
    @Test
    void everyGoldenV21UserPromptIsTheOneRenderedBeforeTheFeatures() throws IOException {
        Map<String, String> texts = renderedUserTexts(SecurityDecisionPromptBundles.V21, "");
        Map<String, String> now = new LinkedHashMap<>();
        texts.forEach((key, text) -> now.put(key, sha256(text)));
        String capture = System.getenv("CONTEXA_PIN_CAPTURE");
        if (capture != null && !capture.isBlank()) {
            write(capture, now);
            return;
        }
        Map<String, String> before = pinned(PINNED);
        assertThat(now.keySet()).as("the rendered cases and profiles").containsExactlyElementsOf(before.keySet());
        Map<String, String> pinnedNow = pinned(PINNED_V21_19);
        Map<String, String> changedWithoutPastRecords = new LinkedHashMap<>();
        Map<String, String> changedBeyondTheField = new LinkedHashMap<>();
        List<String> withPastRecords = new ArrayList<>();
        texts.forEach((key, text) -> {
            if (!PAST_RECORD_LINE.matcher(text).find()) {
                if (!sha256(text).equals(before.get(key))) {
                    changedWithoutPastRecords.put(key, sha256(text));
                }
                return;
            }
            withPastRecords.add(key);
            String withoutTheField = text.replace(LEARNED_FIELD_OF_THE_GOLDEN_RECORDS, "");
            if (!sha256(withoutTheField).equals(before.get(key))) {
                changedBeyondTheField.put(key, sha256(withoutTheField));
            }
        });
        assertThat(changedWithoutPastRecords).as("prompts without a past record line that changed").isEmpty();
        assertThat(changedBeyondTheField).as("prompts with past record lines that changed beyond the learned field")
                .isEmpty();
        assertThat(withPastRecords).as("the prompts with past record lines").isNotEmpty();
        assertThat(withPastRecords.size()).as("and the ones without").isLessThan(now.size());
        assertThat(differences(now, pinnedNow)).as("user prompts that differ from the ones pinned for v21.19").isEmpty();
        assertThat(withPastRecords).as("only these prompts differ from v21.17 as digests")
                .containsExactlyInAnyOrderElementsOf(now.keySet().stream()
                        .filter(key -> !now.get(key).equals(before.get(key))).toList());
    }

    private static void write(String path, Map<String, String> digests) throws IOException {
        StringBuilder text = new StringBuilder();
        digests.forEach((key, digest) -> text.append(key).append('=').append(digest).append('\n'));
        Files.writeString(Path.of(path), text.toString(), StandardCharsets.UTF_8);
    }

    /** The keys whose digest differs from the pinned one; the keys themselves must be the same. */
    private static Map<String, String> differences(Map<String, String> now, Map<String, String> pinned) {
        assertThat(pinned).as("the recorded digests").isNotEmpty();
        assertThat(now.keySet()).as("the rendered cases and profiles").containsExactlyElementsOf(pinned.keySet());
        Map<String, String> changed = new LinkedHashMap<>();
        now.forEach((key, digest) -> {
            if (!digest.equals(pinned.get(key))) {
                changed.put(key, digest);
            }
        });
        return changed;
    }

    /** The sha-256 of the user prompt of every case, profile and second pass the v21 bundle renders. */
    static Map<String, String> userTextDigests() {
        return userTextDigests(SecurityDecisionPromptBundles.V21, "");
    }

    /**
     * The sha-256 of the user prompt of every case, profile and second pass the bundle renders (a second pass only for a
     * bundle of the dictionary blocks), each key with the prefix.
     */
    static Map<String, String> userTextDigests(SecurityDecisionPromptBundles.Bundle bundle, String prefix) {
        Map<String, String> digests = new LinkedHashMap<>();
        renderedUserTexts(bundle, prefix).forEach((key, text) -> digests.put(key, sha256(text)));
        return digests;
    }

    /** The user prompt of every case, profile and second pass the bundle renders, by key. */
    static Map<String, String> renderedUserTexts(SecurityDecisionPromptBundles.Bundle bundle, String prefix) {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(bundle.version());
        Map<String, String> texts = new LinkedHashMap<>();
        for (JsonNode goldenCase : golden.cases()) {
            String caseKey = goldenCase.path("caseKey").asText();
            for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
                texts.put(prefix + caseKey + "/" + profile.name(), golden.render(goldenCase, profile, properties).userText());
            }
            if (!bundle.layout().dictionaryBlocks() || goldenCase.path("ragResults").path("relatedDocuments").isEmpty()) {
                continue;
            }
            String first = golden.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties)
                    .userText();
            texts.put(prefix + caseKey + "/second-pass", golden.render(goldenCase,
                    PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT, properties, null,
                    Map.of("layer2FirstPassUserPrompt", first,
                            "layer2FirstPassVerdict", "ESCALATE",
                            "layer2FirstPassPastRecordsState", "TIMEOUT")).userText());
        }
        return texts;
    }

    static Map<String, String> pinned(String resource) throws IOException {
        Map<String, String> digests = new LinkedHashMap<>();
        try (InputStream input = V21UserPromptByteIdentityTest.class.getClassLoader().getResourceAsStream(resource)) {
            if (input == null) {
                return digests;
            }
            for (String line : new String(input.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                int equals = line.indexOf('=');
                if (equals > 0) {
                    digests.put(line.substring(0, equals), line.substring(equals + 1).trim());
                }
            }
        }
        return digests;
    }

    static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new UncheckedIOException(new IOException(exception));
        }
    }
}
