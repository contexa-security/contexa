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
package io.contexa.contexaiam.admin.promptquality.screen;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseClass;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseKind;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseOrigin;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseResource;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSide;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSource;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.std.components.prompt.quality.QualityResourceCoverage;
import io.contexa.contexacore.std.components.prompt.quality.QualityVerdict;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseResources;
import io.contexa.contexaiam.admin.promptquality.measure.MeasuredQualityGateSource;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.InputLine;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.InputSummary;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
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
 * Quality plan 3.9: every word the screens of the labelled cases and of measure and compare show is in both languages
 * and translated: the words their scripts name, the codes the server sends them (refusals, states, metrics, grades,
 * the values of a case's input) and the names of the views. The two message files hold the same words of the two
 * screens. The trial moved from the version screens still finds every word it showed there.
 */
class PromptQualityScreenMessagesTest {

    private static final String SCRIPTS = "static/contexa/js/admin/prompt-quality/";
    /** The first argument of a call of the screen's words: a key, or the keys of a choice between some. */
    private static final Pattern CALL = Pattern.compile("\\b(m|caseWord)\\(([^,()]*)");
    private static final Pattern LITERAL = Pattern.compile("'([A-Za-z][A-Za-z0-9_.]*[A-Za-z0-9_])'");
    private static final Pattern WHOLE_KEY = Pattern.compile("'((?:pqa|pv|zt)\\.[A-Za-z0-9_.-]*[A-Za-z0-9_-])'");
    /** A value made of placeholders and signs alone reads the same in both languages. */
    private static final Pattern NOT_A_WORD = Pattern.compile("[{}0-9\\s%\\u00b7/\\u2190\\u2192~\\u00b1():]*");
    /** K197: the dictionaries the script of the cases reads the codes of an input by, in its order (CODE_WORDS). */
    private static final List<String> CODE_WORDS = List.of("pqa.cases.value.", "pqa.cases.resGrade.",
            "zt.console.ui.decision.value.action.", "zt.console.ui.decision.value.os.",
            "zt.console.ui.decision.value.zone.", "zt.console.ui.decision.value.recordStatus.",
            "zt.console.ui.decision.value.login.");
    /** The lines of an input the script reads codes in (CODED_LINES) and yes or no in (YES_NO_LINES). */
    private static final List<String> CODED_LINES = List.of("resourceClass", "sensitivity", "action", "authorization",
            "authentication", "network", "device", "approvalStatus");
    private static final List<String> YES_NO_LINES = List.of("mfa", "newSession", "newDevice");
    /** A code as the engine writes it, as the script finds it (ENGINE_CODE). */
    private static final Pattern ENGINE_CODE = Pattern.compile(
            "(?<![\\w./@#:+-])[A-Z][A-Z0-9_]*(?:\\+[A-Z][A-Z0-9_]*)*(?![\\w./@#:+-])");

    @Test
    void everyWordOfTheTwoScreensIsInBothLanguagesAndTranslated() throws IOException {
        Set<String> keys = new LinkedHashSet<>();
        calls(read(SCRIPTS + "cases.js"), "pqa.cases.", keys);
        // K200: the screen of the cases draws its answer fields with the shared script, in the words of the cases.
        calls(read(SCRIPTS + "case-answer.js"), "pqa.cases.", keys);
        calls(read(SCRIPTS + "measure.js"), "pqa.measure.", keys);
        calls(read(SCRIPTS + "measure-trials.js"), "pqa.measure.", keys);
        for (String script : List.of("pqa-common.js", "cases.js", "case-answer.js", "measure.js",
                "measure-trials.js")) {
            collect(WHOLE_KEY, read(SCRIPTS + script), "", keys);
        }
        for (String template : List.of("cases", "measure")) {
            collect(Pattern.compile("#\\{([A-Za-z0-9_.-]+)"), read("templates/contexa/admin/prompt-quality/" + template
                    + ".html"), "", keys);
        }
        keys.removeIf(key -> key.endsWith("."));
        keys.addAll(sentCodes());

        Properties english = properties("contexa/i18n/messages.properties");
        Properties korean = properties("contexa/i18n/messages_ko.properties");
        assertThat(keys).hasSizeGreaterThan(400);
        assertThat(keys.stream().filter(key -> !english.containsKey(key)).toList()).as("in the English messages").isEmpty();
        assertThat(keys.stream().filter(key -> !korean.containsKey(key)).toList()).as("in the Korean messages").isEmpty();
        assertThat(keys.stream().filter(key -> key.startsWith("pqa.cases.") || key.startsWith("pqa.measure."))
                .filter(key -> !NOT_A_WORD.matcher(english.getProperty(key)).matches())
                .filter(key -> english.getProperty(key).equals(korean.getProperty(key))).toList())
                .as("translated").isEmpty();
    }

    /** The codes the server sends the two screens, which their scripts put in words by a prefix. */
    private static Set<String> sentCodes() {
        Set<String> keys = new LinkedHashSet<>();
        Stream.of(QualityCaseClass.values()).forEach(value -> keys.add("pqa.cases.class." + value.name()));
        Stream.of(QualityCaseKind.values()).forEach(value -> keys.add("pqa.cases.kind." + value.name()));
        Stream.of(QualityCaseGrade.values()).forEach(value -> keys.add("pqa.cases.grade." + value.name()));
        Stream.of(QualityCaseOrigin.values()).forEach(value -> keys.add("pqa.cases.origin." + value.name()));
        Stream.of("HIT", "MISS", "OFF", "NONE", "PENDING").forEach(value -> keys.add("pqa.cases.now." + value));
        QualityCaseResources.CLASSES.forEach(value -> keys.add("pqa.cases.resGrade." + value));
        keys.add("pqa.cases.resGrade." + QualityCaseResource.UNCLASSIFIED);
        Stream.of(QualityResourceCoverage.Gap.values()).filter(gap -> gap != QualityResourceCoverage.Gap.NONE)
                .forEach(gap -> keys.add("pqa.cases.cover." + gap.name()));
        Stream.of("COVERED", "UNUSED").forEach(value -> keys.add("pqa.cases.cover." + value));
        Stream.of("request", "session", "deviation", "records", "unknown")
                .forEach(value -> keys.add("pqa.cases.detail.tab." + value));
        Stream.of(PromptQualityCases.Refusal.values()).forEach(value -> keys.add("pqa.cases.refused." + value.name()));
        Stream.of(PromptQualityCaseScreen.NOT_SEALED, PromptQualityCaseScreen.INVALID, PromptQualityCaseScreen.NOT_FOUND)
                .forEach(value -> keys.add("pqa.cases.refused." + value));
        // The values of the input of every case Contexa ships, by their names and the dimensions of their deviations.
        for (QualityCase item : QualityCaseSetReader.contexaDefault().cases()) {
            InputSummary summary = QualityCaseInputSummary.of(item.input());
            Stream.of(summary.request(), summary.session(), summary.records(), summary.unknown()).flatMap(List::stream)
                    .map(InputLine::name).filter(name -> name != null).forEach(name -> keys.add("pqa.cases.input." + name));
            summary.deviation().forEach(line -> keys.add("pqa.cases.dimension." + line.name()));
        }
        keys.add("pqa.cases.dimension.OTHER");
        // K197: the screen's own words of the values of an input (yes, no, an authorization effect, a level, a state).
        Stream.of("true", "false", "ALLOW", "DENY", "LOW", "MEDIUM", "HIGH", "NO_COVERING_APPROVAL")
                .forEach(value -> keys.add("pqa.cases.value." + value));

        PromptQualityMeasureScreen.METRICS.forEach(metric -> {
            keys.add("pqa.measure.metric." + metric.name());
            keys.add("pqa.measure.metric." + metric.name() + ".def");
        });
        keys.add("pqa.measure.metric." + PromptQualityMeasureScreen.TIME);
        keys.add("pqa.measure.metric." + PromptQualityMeasureScreen.TIME + ".def");
        Stream.of("ONE_RUN", "NO_CASES").forEach(value -> keys.add("pqa.measure.metric.none." + value));
        Stream.of(QualityVerdict.values()).forEach(value -> keys.add("pqa.measure.verdict." + value.name()));
        Stream.of("NEW_MISS", "NEW_CATCH", "NEW_STOP", "NEW_PASS").forEach(value -> {
            keys.add("pqa.measure.split." + value);
            keys.add("pqa.measure.split." + value + ".sub");
        });
        Stream.of("CONTEXA", "OURS").forEach(value -> keys.add("pqa.measure.split." + value));
        Stream.of(PromptQualityMeasurements.QUEUED, PromptQualityMeasurements.RUNNING, PromptQualityMeasurements.DONE,
                PromptQualityMeasurements.FAILED, PromptQualityMeasurements.CANCELLED, PromptVersionTrials.QUEUED,
                PromptVersionTrials.RUNNING, PromptVersionTrials.DONE, PromptVersionTrials.FAILED,
                PromptVersionTrials.CANCELLED, "INCOMPLETE").forEach(value -> keys.add("pqa.measure.run." + value));
        Stream.of("FIRST", "FINAL").forEach(value -> {
            keys.add("pqa.measure.run.basis." + value);
            keys.add("pqa.measure.run.basis." + value + ".def");
        });
        Stream.concat(Stream.of(QualityMeasurementState.values()).map(Enum::name),
                Stream.of(PromptQualityMeasureScreen.NONE, PromptQualityMeasureScreen.NOT_FOUND,
                        PromptQualityMeasureScreen.INCOMPARABLE)).forEach(value -> {
                    keys.add("pqa.measure.compare.state." + value);
                    keys.add("pqa.measure.compare.state." + value + ".line");
                });
        Stream.of(QualityGateSide.values()).forEach(value -> keys.add("pqa.measure.compare.side." + value.name()));
        Stream.of(PromptQualityMeasureScreen.CASE_SET, PromptQualityMeasureScreen.MODEL_SETTING,
                PromptQualityMeasureScreen.REPEATS).forEach(value -> keys.add("pqa.measure.compare.difference." + value));
        Stream.of(MeasuredQualityGateSource.NO_MEASUREMENT_RUNNER, MeasuredQualityGateSource.MEASURING,
                MeasuredQualityGateSource.NO_CASE_SET, MeasuredQualityGateSource.SHIPPED, QualityGateSource.NO_SOURCE)
                .forEach(value -> keys.add("pqa.measure.compare.detail." + value));
        Stream.of("BETTER", "SAME", "WORSE", "UNDECIDABLE", "gradeWorse")
                .forEach(value -> keys.add("pqa.measure.compare.sentence." + value));
        Stream.of(SecurityDecisionFactChecks.Outcome.values())
                .forEach(value -> keys.add("pqa.measure.finding." + value.name()));
        Stream.of(PromptQualityMeasurements.Refusal.values()).forEach(value -> keys.add("pqa.measure.refused."
                + value.name()));
        Stream.of(PromptQualityMeasureScreen.NO_RUNNER, PromptQualityMeasureScreen.NOT_FOUND)
                .forEach(value -> keys.add("pqa.measure.refused." + value));
        PromptQualityMeasureScreen.VIEWS.forEach(view -> keys.add(view.label()));
        keys.add("pqa.measure.tabs");
        // The labels the answers of a case are drawn under, passed to the drawing of each side.
        keys.add("pqa.measure.compare.currentLabel");
        keys.add("pqa.measure.compare.candidateLabel");
        keys.add("pqa.cases.tabCount");
        return keys;
    }

    /** The two message files hold the same words of the two screens, none in one language alone. */
    @Test
    void theTwoLanguagesHoldTheSameWords() throws IOException {
        Set<String> english = words(properties("contexa/i18n/messages.properties"));
        Set<String> korean = words(properties("contexa/i18n/messages_ko.properties"));

        assertThat(english).hasSizeGreaterThan(400).isEqualTo(korean);
    }

    /**
     * K197: the input of a case shows no code of the engine as it is. Every code the inputs of the cases Contexa ships
     * hold in a line of codes (a login, an action, a resource class, a level, an authorization effect, a network zone,
     * an operating system, an approval state, the deviations) has a word in a dictionary the script of the cases reads,
     * in both languages; yes and no and the names of the facts not known have their words; the page carries every
     * dictionary the script reads.
     */
    @Test
    void everyCodeOfTheShippedInputsHasAWord() throws IOException {
        Properties english = properties("contexa/i18n/messages.properties");
        Properties korean = properties("contexa/i18n/messages_ko.properties");
        String script = read(SCRIPTS + "cases.js");
        Set<String> missing = new LinkedHashSet<>();
        int codes = 0;
        for (QualityCase item : QualityCaseSetReader.contexaDefault().cases()) {
            InputSummary summary = QualityCaseInputSummary.of(item.input());
            List<InputLine> coded = Stream.of(summary.request(), summary.session(), summary.records())
                    .flatMap(List::stream).filter(line -> line.name() != null && CODED_LINES.contains(line.name()))
                    .toList();
            for (InputLine line : Stream.concat(coded.stream(), summary.deviation().stream()).toList()) {
                Matcher code = ENGINE_CODE.matcher(line.value());
                while (code.find()) {
                    for (String one : code.group().split("\\+")) {
                        codes++;
                        if (CODE_WORDS.stream().noneMatch(prefix -> english.containsKey(prefix + one)
                                && korean.containsKey(prefix + one))) {
                            missing.add(line.name() + ": " + one);
                        }
                    }
                }
            }
            summary.session().stream().filter(line -> line.name() != null && YES_NO_LINES.contains(line.name()))
                    .map(line -> "pqa.cases.value." + line.value())
                    .filter(key -> !english.containsKey(key) || !korean.containsKey(key)).forEach(missing::add);
            summary.unknown().stream().filter(line -> "unknownFact".equals(line.name()))
                    .map(line -> "zt.console.fact." + line.value())
                    .filter(key -> !english.containsKey(key) || !korean.containsKey(key)).forEach(missing::add);
        }

        assertThat(codes).as("codes read").isGreaterThan(50);
        assertThat(missing).as("codes without a word").isEmpty();
        Stream.concat(CODE_WORDS.stream(), Stream.of("zt.console.fact.")).forEach(prefix -> {
            assertThat(script).as("the script reads " + prefix).contains("'" + prefix + "'");
            assertThat(Stream.of(PromptQualityPageController.MESSAGE_PREFIXES).anyMatch(prefix::startsWith))
                    .as("the page carries " + prefix).isTrue();
        });
        assertThat(script.replaceAll("\\s+", " ")).contains("'" + String.join("', '", CODED_LINES) + "'",
                "'" + String.join("', '", YES_NO_LINES) + "'");
    }

    /** The trial moved to measure and compare still shows every word of its result and of the results alongside. */
    @Test
    void theMovedTrialKeepsEveryWordOfItsResult() throws IOException {
        String trials = read(SCRIPTS + "measure-trials.js");

        assertThat(trials).contains("'pv.trial.result'", "'pv.trial.statusLine'", "'pv.trial.fewer'", "'pv.trial.failure'",
                "'pv.trial.progressLine'", "'pv.trial.cancel'", "'pv.trial.verdict'", "'pv.trial.verdictErrors'",
                "'pv.trial.verdictNoErrors'", "'pv.trial.same'", "'pv.trial.format'", "'pv.trial.time'",
                "'pv.trial.length'", "'pv.trial.distribution'", "'pv.trial.noAnswer'", "'pv.trial.changed'",
                "'pv.trial.noChange'", "'pv.trial.canary'", "'pv.trial.use'", "'pv.trial.startNote'",
                "'pv.shadow.results'", "'pv.shadow.outcomes'", "'pv.shadow.cases'")
                .contains("PV.get('/trials/' + trialId)", "PV.get('/shadow/results'", "PV.send('/trials', body)",
                        "PV.useVersion(trial.candidate, true, drawTrial)", "result.sameAction",
                        "result.candidate.formatErrors", "result.candidate.averageMs",
                        "result.candidate.averageAnswerTokens", "result.changed", "MEASURE.views.trial = drawTrial");
        // Quality plan 3.10: the final actions beside the first answers; 3.3: a trial that waits for the lock says so;
        // 3.2: the person's data is said before a changed decision is made a case.
        assertThat(trials).contains("'pv.trial.firstTag'", "'pv.trial.finalTag'", "'pv.trial.finalNote'",
                "'pv.trial.queuedLine'", "side.finalActions", "side.finalAnswered",
                "global.PQA_CASE_ANSWER.privacyNotice()");
        assertThat(PromptQualityScreenMessagesTest.class.getClassLoader()
                .getResource("templates/contexa/admin/prompt-version/trials.html")).isNull();
        assertThat(PromptQualityScreenMessagesTest.class.getClassLoader()
                .getResource("static/contexa/js/admin/prompt-version/trials.js")).isNull();
    }

    /** The keys of the calls of a script's own words (m) and of the words of a case (caseWord). */
    private static void calls(String text, String own, Set<String> keys) {
        Matcher call = CALL.matcher(text);
        while (call.find()) {
            String prefix = "caseWord".equals(call.group(1)) ? "pqa.cases." : own;
            Matcher literal = LITERAL.matcher(call.group(2));
            while (literal.find()) {
                keys.add(prefix + literal.group(1));
            }
        }
    }

    private static void collect(Pattern pattern, String text, String prefix, Set<String> keys) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            keys.add(prefix + matcher.group(1));
        }
    }

    private static Set<String> words(Properties messages) {
        Set<String> words = new LinkedHashSet<>();
        for (String key : messages.stringPropertyNames()) {
            if (key.startsWith("pqa.cases.") || key.startsWith("pqa.measure.")) {
                words.add(key);
            }
        }
        return words;
    }

    private static String read(String resource) throws IOException {
        try (InputStream input = PromptQualityScreenMessagesTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static Properties properties(String resource) throws IOException {
        Properties properties = new Properties();
        try (InputStream input = PromptQualityScreenMessagesTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            properties.load(new InputStreamReader(input, StandardCharsets.UTF_8));
        }
        return properties;
    }
}
