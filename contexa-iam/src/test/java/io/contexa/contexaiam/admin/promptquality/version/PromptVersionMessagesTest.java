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
package io.contexa.contexaiam.admin.promptquality.version;

import io.contexa.contexacore.std.components.prompt.version.PromptVersionProblem;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 6-6 (4): every word the prompt version screens show is in the English and the Korean messages and is
 * translated, the words of each state, mark, refusal and problem the API answers with included; the menu entry of the
 * prompt quality group is the version screens'. These took over from the checks of the release screens (6-6 (5)).
 */
class PromptVersionMessagesTest {

    private static final Pattern TEMPLATE_KEY = Pattern.compile("#\\{([A-Za-z0-9_.-]+)");
    private static final Pattern SCRIPT_KEY = Pattern.compile("'(pv\\.[A-Za-z0-9_.-]*[A-Za-z0-9_-])'");
    private static final List<String> TEMPLATES = List.of("fragments", "list", "version", "new", "trials", "advanced");
    private static final List<String> SCRIPTS = List.of("pv-common", "list", "version", "new", "trials", "advanced");

    /** A value made of placeholders and signs alone, or a style code, reads the same in both languages. */
    private static final Pattern NOT_A_WORD = Pattern.compile("[{}0-9\\s%\\u2190]*");
    private static final String STYLE_CODES = "pv.prepared.tone.";

    /** The codes the console refuses a request with (PromptVersionConsole and its controller). */
    private static final List<String> CONSOLE_REFUSALS = List.of("ACTION", "BASE_NOT_FOUND", "BASE_REQUIRED",
            "CANARY_PERCENT", "CANARY_RUNNING", "EMPTY_DOCUMENT", "FOLDER_NOT_SET", "NO_CANARY", "NO_SHADOW",
            "PROMPT_NOT_FOUND", "ROLLBACK_MISSING", "SHADOW_DAILY_LIMIT", "SHADOW_PERCENT", "SHADOW_RUNNING",
            "TRIALS_MISSING", "VERSION_HIDDEN", "VERSION_NOT_FOUND", "PROBLEMS");

    /** The marks of a part on the version and new version screens. */
    private static final List<String> MARKS = List.of("LOCKED", "DEFAULT", "SAME", "CHANGED", "DELETED", "ADDED",
            "INCLUDED");

    @Test
    void everyWordOfTheScreensIsInBothLanguagesAndTranslated() throws IOException {
        Set<String> keys = new LinkedHashSet<>();
        for (String template : TEMPLATES) {
            collect(TEMPLATE_KEY, read("templates/contexa/admin/prompt-version/" + template + ".html"), keys);
        }
        for (String script : SCRIPTS) {
            collect(SCRIPT_KEY, read("static/contexa/js/admin/prompt-version/" + script + ".js"), keys);
        }
        Stream.of(PromptVersionConsole.USED, PromptVersionConsole.CANARY, PromptVersionConsole.SHADOW,
                PromptVersionConsole.UNUSED, PromptVersionConsole.HIDDEN).forEach(state -> keys.add("pv.state." + state));
        Stream.of(PromptVersionTrials.QUEUED, PromptVersionTrials.RUNNING, PromptVersionTrials.DONE,
                PromptVersionTrials.FAILED, PromptVersionTrials.CANCELLED).forEach(status -> keys.add("pv.trial.status." + status));
        Stream.of(PromptVersionTrials.Refusal.values()).forEach(refusal -> keys.add("pv.refused.TRIAL_" + refusal.name()));
        CONSOLE_REFUSALS.forEach(code -> keys.add("pv.refused." + code));
        Stream.of(PromptVersionProblem.Code.values()).forEach(code -> keys.add("pv.problem." + code.name()));
        MARKS.forEach(mark -> keys.add("pv.mark." + mark));
        Stream.of(PromptBundleRollbackService.EXECUTED, PromptBundleRollbackService.AWAITING_APPROVAL,
                PromptBundleRollbackService.APPROVED, PromptBundleRollbackService.REFUSED)
                .forEach(status -> keys.add("pv.rollback.status." + status));
        Stream.of(JdbcPromptInspectionQueries.DECISION_STAGE, JdbcPromptInspectionQueries.SHADOW_STAGE)
                .forEach(stage -> keys.add("pv.shadow.stage." + stage));
        keys.add("menu.pqa.versions");

        Properties english = properties("contexa/i18n/messages.properties");
        Properties korean = properties("contexa/i18n/messages_ko.properties");
        assertThat(keys).hasSizeGreaterThan(300);
        assertThat(keys.stream().filter(key -> !english.containsKey(key)).toList()).as("in the English messages").isEmpty();
        assertThat(keys.stream().filter(key -> !korean.containsKey(key)).toList()).as("in the Korean messages").isEmpty();
        assertThat(keys.stream().filter(key -> !key.startsWith(STYLE_CODES))
                .filter(key -> !NOT_A_WORD.matcher(english.getProperty(key)).matches())
                .filter(key -> english.getProperty(key).equals(korean.getProperty(key))).toList())
                .as("translated").isEmpty();
    }

    /** The two message files hold the same words of the version screens, none in one language alone. */
    @Test
    void theTwoLanguagesHoldTheSameWords() throws IOException {
        Set<String> english = words(properties("contexa/i18n/messages.properties"));
        Set<String> korean = words(properties("contexa/i18n/messages_ko.properties"));

        assertThat(english).isEqualTo(korean);
    }

    /** Plan 6-6: the prompt version screens took the place of the release screens in the prompt quality group. */
    @Test
    void theMenuHasTheVersionScreenUnderThePromptQualityGroup() throws IOException {
        String seed = read("META-INF/contexa/db/data-menu.sql");

        assertThat(seed).containsPattern(
                "\\('menu\\.pqa\\.versions',\\s*'/contexa/admin/prompt-quality/versions',\\s*'',\\s*'prompt-quality',"
                        + "\\s*\\d+,\\s*TRUE,\\s*'CORE',\\s*'prompt-quality-versions'\\)");
        assertThat(seed).doesNotContain("'menu.pqa.releases'");
    }

    private static void collect(Pattern pattern, String text, Set<String> keys) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            keys.add(matcher.group(1));
        }
    }

    private static Set<String> words(Properties messages) {
        Set<String> words = new LinkedHashSet<>();
        for (String key : messages.stringPropertyNames()) {
            if (key.startsWith("pv.")) {
                words.add(key);
            }
        }
        return words;
    }

    private static String read(String resource) throws IOException {
        try (InputStream input = PromptVersionMessagesTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static Properties properties(String resource) throws IOException {
        Properties properties = new Properties();
        try (InputStream input = PromptVersionMessagesTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            properties.load(new InputStreamReader(input, StandardCharsets.UTF_8));
        }
        return properties;
    }
}
