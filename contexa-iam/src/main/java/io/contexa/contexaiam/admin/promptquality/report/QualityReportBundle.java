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
package io.contexa.contexaiam.admin.promptquality.report;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.contexa.contexaiam.admin.promptquality.status.PromptQualityStatus;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.VersionChange;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.VersionRate;
import org.springframework.context.MessageSource;
import org.springframework.lang.Nullable;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * The bundle of a quality report (quality plan 3.7): one zip file with the report as JSON for a machine to read
 * ({@value #JSON_FILE}), and the same report for a person to read in Korean ({@value #KOREAN_FILE}) and in English
 * ({@value #ENGLISH_FILE}), as Markdown with the texts of the message bundles. The readable files hold the numbers of
 * the JSON as they are: each rate with its numerator, its denominator and its 95% interval, an undecidable comparison
 * as undecidable, and a section without data as none, with why.
 */
final class QualityReportBundle {

    static final String JSON_FILE = "report.json";
    static final String KOREAN_FILE = "report-ko.md";
    static final String ENGLISH_FILE = "report-en.md";
    static final Locale KOREAN = Locale.KOREAN;
    static final Locale ENGLISH = Locale.ENGLISH;

    private static final List<String> OPERATION_KEYS = List.of("STOPPED", "CHALLENGE_PASS", "BLOCK_RELEASE",
            "REVIEW_VALID", "RETRY", "MODEL_LESS");

    private final MessageSource messages;
    private final ObjectMapper json;

    QualityReportBundle(MessageSource messages, ObjectMapper json) {
        this.messages = Objects.requireNonNull(messages, "messages");
        this.json = Objects.requireNonNull(json, "json").copy().enable(SerializationFeature.INDENT_OUTPUT);
    }

    /** The zip file of the report. */
    byte[] zip(QualityReport report) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes, StandardCharsets.UTF_8)) {
            entry(zip, JSON_FILE, json(report));
            entry(zip, KOREAN_FILE, markdown(report, KOREAN));
            entry(zip, ENGLISH_FILE, markdown(report, ENGLISH));
        }
        catch (IOException unwritable) {
            throw new UncheckedIOException("The quality report could not be written", unwritable);
        }
        return bytes.toByteArray();
    }

    /** The report as the JSON of the bundle. */
    String json(QualityReport report) {
        try {
            return json.writeValueAsString(report);
        }
        catch (JsonProcessingException unwritable) {
            throw new IllegalStateException("The quality report could not be written as JSON", unwritable);
        }
    }

    private static void entry(ZipOutputStream zip, String name, String text) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(text.getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }

    // ----- the readable report -----

    /** The report for a person to read in the language. */
    String markdown(QualityReport report, Locale locale) {
        Text out = new Text(messages, locale);
        QualityReport.Header header = report.header();
        out.line("# " + out.m("pqa.report.title"));
        out.blank();
        out.table(List.of(out.m("pqa.report.meta.item"), out.m("pqa.report.meta.value")), List.of(
                List.of(out.m("pqa.report.meta.scope"), code(header.scope())),
                List.of(out.m("pqa.report.meta.prompt"), code(header.prompt())),
                List.of(out.m("pqa.report.meta.period"), out.m("pqa.report.meta.periodValue", header.from(),
                        header.to())),
                List.of(out.m("pqa.report.meta.tenant"), header.decisionTenant() != null
                        ? code(header.decisionTenant()) : out.m("pqa.report.meta.allTenants")),
                List.of(out.m("pqa.report.meta.generatedAt"), header.generatedAt()),
                List.of(out.m("pqa.report.meta.exportedBy"), cell(header.exportedBy())),
                List.of(out.m("pqa.report.meta.format"), code(report.format())),
                List.of(out.m("pqa.report.meta.gate"), out.m("pqa.report.meta.gateValue", header.gate().mode(),
                        percent(header.gate().modelLessLimit()), String.valueOf(header.gate().significance()),
                        String.valueOf(header.gate().minimumStopRoots()),
                        String.valueOf(header.gate().minimumAllowRoots()))),
                List.of(out.m("pqa.report.meta.modelSetting"), header.modelSetting() != null
                        ? code(header.modelSetting().settingsHash()) : out.m("pqa.report.missing.UNMEASURABLE"))));
        out.blank();
        out.line(out.m("pqa.report.regulation.intro"));
        out.blank();
        out.table(List.of(out.m("pqa.report.regulation.question"), out.m("pqa.report.regulation.section")), List.of(
                List.of(out.m("pqa.report.regulation.ACCURACY_DECLARATION"), out.m("pqa.report.section.accuracy")),
                List.of(out.m("pqa.report.regulation.POST_MARKET_MONITORING"),
                        out.m("pqa.report.section.monitoring")),
                List.of(out.m("pqa.report.regulation.OVERTURNED_DECISIONS"), out.m("pqa.report.section.reversals"))));
        out.blank();
        out.line(out.m("pqa.report.numbers.note"));
        out.blank();
        accuracy(out, report.accuracy());
        caseSets(out, report.caseSets());
        monitoring(out, report.monitoring());
        reversals(out, report.reversals());
        history(out, report.history());
        masking(out, report.masking());
        return out.toString();
    }

    private static void accuracy(Text out, QualityReport.Accuracy accuracy) {
        out.line("## " + out.m("pqa.report.section.accuracy"));
        out.blank();
        out.line(out.m("pqa.report.accuracy.answers"));
        out.blank();
        out.line("- " + out.m("pqa.report.accuracy.version") + ": " + (accuracy.version() != null
                ? code(accuracy.version()) + (accuracy.versionSource() != null ? " (" + code(accuracy.versionSource())
                + ")" : "") : out.m("pqa.report.none")));
        out.line("- " + out.m("pqa.report.accuracy.state") + ": " + out.m("pqa.report.state." + accuracy.state())
                + (accuracy.measuring() ? " / " + out.m("pqa.report.accuracy.measuring") : ""));
        if (accuracy.versionInfo() != null) {
            QualityReport.VersionInfo info = accuracy.versionInfo();
            out.line("- " + out.m("pqa.report.accuracy.versionInfo", code(info.provider()), code(info.origin()),
                    cell(info.createdBy()), info.createdAt(), code(info.contentHash())));
        }
        if (accuracy.missing() != null) {
            out.line("- " + none(out, accuracy.missing()));
        }
        QualityReport.Declared declared = accuracy.declared();
        if (declared != null) {
            out.line("- " + out.m("pqa.report.accuracy.measurement", String.valueOf(declared.measureId()),
                    code(declared.caseSetVersion()), String.valueOf(declared.repeats()), code(declared.modelSetting()),
                    Objects.toString(declared.finishedAt(), "-")));
            out.line("- " + (declared.fresh() ? out.m("pqa.report.accuracy.fresh")
                    : out.m("pqa.report.accuracy.stale", cell(changed(declared.changedSettings())))));
            out.blank();
            out.table(List.of(out.m("pqa.report.column.metric"), out.m("pqa.report.column.firstAnswer"),
                    out.m("pqa.report.column.finalAction")), scoreRows(out, declared.firstAnswer(),
                    declared.finalAction()));
            out.blank();
            out.line(out.m("pqa.report.accuracy.answersCount", String.valueOf(declared.firstAnswer().answers()),
                    String.valueOf(declared.firstAnswer().scoredAnswers()),
                    String.valueOf(declared.firstAnswer().incompleteAnswers()),
                    String.valueOf(declared.firstAnswer().cases()),
                    String.valueOf(declared.firstAnswer().unmeasuredCases()),
                    String.valueOf(declared.firstAnswer().roots())));
            out.line(out.m("pqa.report.accuracy.spreads", spread(declared.firstAnswer().decisionMillis()),
                    spread(declared.firstAnswer().answerTokens())));
            if (!declared.missingCases().isEmpty()) {
                out.line(out.m("pqa.report.accuracy.missingCases", codes(declared.missingCases())));
            }
            out.blank();
            if (declared.secondAnalysisFirstAnswer() != null) {
                out.line(out.m("pqa.report.accuracy.secondAnalysis", String.valueOf(declared.secondAnalysisCases())));
                out.blank();
                out.table(List.of(out.m("pqa.report.column.metric"), out.m("pqa.report.column.firstAnswer")),
                        declared.secondAnalysisFirstAnswer().rates().entrySet().stream()
                                .map(rate -> List.of(out.m("pqa.report.metric." + rate.getKey()),
                                        rate(out, rate.getValue()))).toList());
                out.blank();
            }
            else {
                out.line(out.m("pqa.report.accuracy.noSecondAnalysis"));
                out.blank();
            }
        }
        QualityReport.Sufficiency sufficiency = accuracy.sufficiency();
        if (sufficiency != null) {
            out.line("### " + out.m("pqa.report.accuracy.sufficiency"));
            out.blank();
            out.line(out.m("pqa.report.accuracy.sufficiencyValue", String.valueOf(sufficiency.stopRoots()),
                    String.valueOf(sufficiency.neededStopRoots()), String.valueOf(sufficiency.allowRoots()),
                    String.valueOf(sufficiency.neededAllowRoots())) + " " + (sufficiency.enough()
                    ? out.m("pqa.report.accuracy.enough") : out.m("pqa.report.accuracy.notEnough")));
            out.blank();
        }
        if (!accuracy.alone().isEmpty()) {
            out.line("### " + out.m("pqa.report.accuracy.alone"));
            out.blank();
            findings(out, accuracy.alone());
            out.blank();
        }
        out.line("### " + out.m("pqa.report.accuracy.comparisons"));
        out.blank();
        if (accuracy.comparisons().isEmpty()) {
            out.line(out.m("pqa.report.accuracy.noComparison"));
            out.blank();
        }
        for (QualityReport.Comparison comparison : accuracy.comparisons()) {
            out.line("#### " + out.m("pqa.report.accuracy.against", code(Objects.toString(accuracy.version(), "-")),
                    code(comparison.against())));
            out.blank();
            out.line("- " + out.m("pqa.report.accuracy.state") + ": " + out.m("pqa.report.state." + comparison.state())
                    + (comparison.sides().isEmpty() ? "" : " (" + comparison.sides().stream()
                    .map(side -> out.m("pqa.report.side." + side)).collect(Collectors.joining(", ")) + ")"));
            out.line("- " + out.m("pqa.report.accuracy.verdict") + ": " + out.m("pqa.report.status."
                    + comparison.verdict()));
            out.blank();
            if (comparison.metrics().isEmpty()) {
                out.line(out.m("pqa.report.accuracy.notCompared"));
                out.blank();
            }
            else {
                List<List<String>> rows = new ArrayList<>();
                for (QualityReport.MetricComparison metric : comparison.metrics()) {
                    rows.add(List.of(out.m("pqa.report.metric." + metric.metric()),
                            out.m("pqa.report.verdict." + metric.verdict()), percentOrDash(metric.inUseValue()),
                            percentOrDash(metric.beforeValue()), percentOrDash(metric.difference()),
                            metric.noiseWidth() != null ? percent(metric.noiseWidth())
                                    : out.m("pqa.report.accuracy.noiseUnknown"),
                            metric.pairedCases() + " / " + metric.pairedRoots(),
                            metric.worseRoots() + " / " + metric.betterRoots(),
                            probability(metric.worseProbability()) + " / " + probability(metric.betterProbability())));
                }
                out.table(List.of(out.m("pqa.report.column.metric"), out.m("pqa.report.column.verdict"),
                        out.m("pqa.report.column.inUse"), out.m("pqa.report.column.before"),
                        out.m("pqa.report.column.difference"), out.m("pqa.report.column.noise"),
                        out.m("pqa.report.column.paired"), out.m("pqa.report.column.worseBetter"),
                        out.m("pqa.report.column.probability")), rows);
                out.blank();
            }
            if (!comparison.findings().isEmpty()) {
                findings(out, comparison.findings());
                out.blank();
            }
            out.line(out.m("pqa.report.accuracy.changes", codes(comparison.changes().newlyMissed()),
                    codes(comparison.changes().newlyCaught()), codes(comparison.changes().newlyStopped()),
                    codes(comparison.changes().newlyReleased())));
            out.blank();
        }
        out.line("### " + out.m("pqa.report.accuracy.measurements"));
        out.blank();
        if (accuracy.measurements().isEmpty()) {
            out.line(out.m("pqa.report.accuracy.noMeasurements"));
        }
        else {
            List<List<String>> rows = new ArrayList<>();
            for (QualityReport.MeasurementRow row : accuracy.measurements()) {
                rows.add(List.of(String.valueOf(row.id()), code(row.version()), code(row.caseSetVersion()),
                        String.valueOf(row.repeats()), code(row.status()), code(Objects.toString(row.startReason(),
                                "-")), cell(row.createdBy()), Objects.toString(row.finishedAt(), "-"),
                        String.valueOf(row.answered()),
                        row.firstAnswer() != null ? rate(out, row.firstAnswer().rates().get("MISS")) : "-",
                        row.firstAnswer() != null ? rate(out, row.firstAnswer().rates().get("FALSE_STOP")) : "-",
                        cell(Objects.toString(row.failure(), "-"))));
            }
            out.table(List.of(out.m("pqa.report.column.id"), out.m("pqa.report.column.version"),
                    out.m("pqa.report.column.caseSet"), out.m("pqa.report.column.repeats"),
                    out.m("pqa.report.column.status"), out.m("pqa.report.column.startReason"),
                    out.m("pqa.report.column.by"), out.m("pqa.report.column.finishedAt"),
                    out.m("pqa.report.column.answers"), out.m("pqa.report.metric.MISS"),
                    out.m("pqa.report.metric.FALSE_STOP"), out.m("pqa.report.column.failure")), rows);
            if (accuracy.measurementsLeftOut() > 0) {
                out.blank();
                out.line(out.m("pqa.report.leftOut", String.valueOf(accuracy.measurementsLeftOut())));
            }
        }
        out.blank();
    }

    private static void caseSets(Text out, QualityReport.CaseSets caseSets) {
        out.line("## " + out.m("pqa.report.section.caseSets"));
        out.blank();
        QualityReport.Inventory inventory = caseSets.inventory();
        out.line(out.m("pqa.report.caseSets.inventory", String.valueOf(inventory.kept()),
                String.valueOf(inventory.operation()), String.valueOf(inventory.secondAnalysis()),
                String.valueOf(inventory.pending()), code(inventory.defaultSetVersion()),
                String.valueOf(inventory.defaultSetCases())) + " " + (inventory.twoPersonConfirmation()
                ? out.m("pqa.report.caseSets.twoPersonOn") : out.m("pqa.report.caseSets.twoPersonOff")));
        out.blank();
        if (caseSets.missing() != null) {
            out.line(none(out, caseSets.missing()));
            out.blank();
            return;
        }
        List<List<String>> rows = new ArrayList<>();
        for (QualityReport.SetRow set : caseSets.sets()) {
            rows.add(List.of(code(set.version()), cell(set.name()), String.valueOf(set.caseCount()),
                    String.valueOf(set.readable()), set.missingCases().isEmpty() ? "0"
                            : set.missingCases().size() + " (" + codes(set.missingCases()) + ")",
                    set.defaultSetVersion() != null ? code(set.defaultSetVersion()) + " / " + set.defaultCaseCount()
                            : "-", cell(set.publishedBy()) + " / " + set.publishedAt(),
                    set.reasons().stream().map(reason -> out.m("pqa.report.caseSets.reason." + reason))
                            .collect(Collectors.joining(", ")),
                    set.stopRoots() + " / " + set.allowRoots(), String.valueOf(set.secondAnalysis()),
                    counts(set.byOrigin()), counts(set.byGrade()), counts(set.byClass()), counts(set.byKind())));
        }
        out.table(List.of(out.m("pqa.report.column.version"), out.m("pqa.report.column.name"),
                out.m("pqa.report.column.cases"), out.m("pqa.report.column.readable"),
                out.m("pqa.report.column.missingCases"), out.m("pqa.report.column.defaultSet"),
                out.m("pqa.report.column.published"), out.m("pqa.report.column.listedFor"),
                out.m("pqa.report.column.roots"), out.m("pqa.report.column.secondAnalysis"),
                out.m("pqa.report.column.origin"), out.m("pqa.report.column.grade"),
                out.m("pqa.report.column.class"), out.m("pqa.report.column.kind")), rows);
        out.blank();
    }

    private static void monitoring(Text out, QualityReport.Monitoring monitoring) {
        out.line("## " + out.m("pqa.report.section.monitoring"));
        out.blank();
        out.line(out.m("pqa.report.monitoring.answers"));
        out.blank();
        out.line("### " + out.m("pqa.report.monitoring.operation"));
        out.blank();
        if (monitoring.missing() != null) {
            out.line(none(out, monitoring.missing()));
        }
        else {
            List<String> heads = new ArrayList<>(List.of(out.m("pqa.report.column.version"),
                    out.m("pqa.report.column.inUse"), out.m("pqa.report.column.decisions"),
                    out.m("pqa.report.column.hours")));
            OPERATION_KEYS.forEach(key -> heads.add(out.m("pqa.report.operation." + key)));
            List<List<String>> rows = new ArrayList<>();
            for (QualityReport.VersionOperation version : monitoring.versions()) {
                List<String> row = new ArrayList<>(List.of(code(version.version()), version.inUse() ? "O" : "",
                        String.valueOf(version.decisions()), Objects.toString(version.firstHour(), "-") + " - "
                                + Objects.toString(version.lastHour(), "-")));
                OPERATION_KEYS.forEach(key -> row.add(operationRate(out, version.rates().get(key))));
                rows.add(row);
            }
            out.table(heads, rows);
        }
        out.blank();
        out.line("### " + out.m("pqa.report.monitoring.change"));
        out.blank();
        VersionChange change = monitoring.change();
        if (change == null) {
            out.line(none(out, "NO_OPERATIONS"));
        }
        else if (change.previousVersion() == null) {
            out.line(out.m("pqa.report.monitoring.noChange", code(change.version()), change.afterFrom(),
                    change.afterTo()));
        }
        else {
            out.line(out.m("pqa.report.monitoring.changeValue", code(change.previousVersion()),
                    code(change.version()), Objects.toString(change.changedAt(), "-"),
                    Objects.toString(change.beforeFrom(), "-"), change.afterTo()));
        }
        if (change != null) {
            out.blank();
            List<List<String>> rows = new ArrayList<>();
            for (VersionRate rate : change.rates()) {
                rows.add(List.of(out.m("pqa.report.operation." + rate.key()),
                        operationRate(out, PromptQualityReports.operationRate(rate.beforeEvents(), rate.beforeTrials())),
                        operationRate(out, PromptQualityReports.operationRate(rate.afterEvents(), rate.afterTrials()))));
            }
            out.table(List.of(out.m("pqa.report.column.metric"), out.m("pqa.report.column.before"),
                    out.m("pqa.report.column.after")), rows);
        }
        out.blank();
        out.line("### " + out.m("pqa.report.monitoring.remeasure"));
        out.blank();
        QualityReport.Remeasure remeasure = monitoring.latestRemeasure();
        out.line(remeasure != null ? out.m("pqa.report.monitoring.remeasureValue",
                out.m("pqa.report.remeasure." + remeasure.verdict()), String.valueOf(remeasure.measureId()),
                Objects.toString(remeasure.comparedMeasureId(), "-"), remeasure.comparedAt(),
                code(Objects.toString(remeasure.startReason(), "-"))) : out.m("pqa.report.monitoring.noRemeasure"));
        out.line(monitoring.nextScheduled() != null ? out.m("pqa.report.monitoring.next", monitoring.nextScheduled())
                : out.m("pqa.report.monitoring.scheduleOff"));
        out.blank();
        out.line("### " + out.m("pqa.report.monitoring.toCheck"));
        out.blank();
        if (monitoring.toCheck().isEmpty()) {
            out.line(out.m("pqa.report.monitoring.nothingToCheck"));
        }
        else {
            List<List<String>> rows = new ArrayList<>();
            for (PromptQualityStatus.ToCheck check : monitoring.toCheck()) {
                rows.add(List.of(out.m("pqa.report.toCheck." + check.kind()),
                        out.m("pqa.report.severity." + check.severity()), String.valueOf(check.count())));
            }
            out.table(List.of(out.m("pqa.report.column.item"), out.m("pqa.report.column.severity"),
                    out.m("pqa.report.column.count")), rows);
        }
        out.blank();
        out.line("### " + out.m("pqa.report.monitoring.causes"));
        out.blank();
        causes(out, out.m("pqa.report.monitoring.measurementCauses"), monitoring.measurementCauses());
        causes(out, out.m("pqa.report.monitoring.decisionCauses"), monitoring.decisionCauses());
    }

    private static void causes(Text out, String title, QualityReport.Causes causes) {
        out.line("- " + title + (causes.measureId() != null ? " (" + causes.measureId() + ")" : ""));
        out.blank();
        if (causes.missing() != null) {
            out.line(none(out, causes.missing()));
        }
        else {
            List<List<String>> rows = new ArrayList<>();
            for (QualityReport.CauseCount count : causes.counts()) {
                rows.add(List.of(out.m("pqa.report.cause." + count.cause()), count.fix() != null
                        ? out.m("pqa.report.fix." + count.fix()) : "-", String.valueOf(count.count()),
                        String.valueOf(count.notComputed())));
            }
            out.table(List.of(out.m("pqa.report.column.cause"), out.m("pqa.report.column.fix"),
                    out.m("pqa.report.column.count"), out.m("pqa.report.column.notComputed")), rows);
            out.blank();
            out.line(out.m("pqa.report.monitoring.causesListed", String.valueOf(causes.listed()),
                    String.valueOf(causes.withoutRecord())));
        }
        out.blank();
    }

    private static void reversals(Text out, QualityReport.Reversals reversals) {
        out.line("## " + out.m("pqa.report.section.reversals"));
        out.blank();
        out.line(out.m("pqa.report.reversals.answers"));
        out.blank();
        List<List<String>> kinds = new ArrayList<>();
        for (QualityReport.KindSummary kind : reversals.kinds()) {
            kinds.add(List.of(out.m("zt.console.ui.decisions.outcome." + kind.kind()),
                    String.valueOf(kind.decisions()), counts(kind.byAction()), counts(kind.byVersion()),
                    kind.byReason().isEmpty() ? "-" : counts(kind.byReason())));
        }
        out.table(List.of(out.m("pqa.report.column.kind"), out.m("pqa.report.column.decisions"),
                out.m("pqa.report.column.byAction"), out.m("pqa.report.column.byVersion"),
                out.m("pqa.report.column.byReason")), kinds);
        out.blank();
        out.line(out.m("pqa.report.reversals.invalidShare", operationRate(out, reversals.invalidShare())));
        out.blank();
        if (reversals.missing() != null) {
            out.line(none(out, reversals.missing()));
            out.blank();
            return;
        }
        List<List<String>> rows = new ArrayList<>();
        for (QualityReport.ReversedDecision entry : reversals.entries()) {
            rows.add(List.of(entry.occurredAt(), out.m("zt.console.ui.decisions.outcome." + entry.kind()),
                    code(Objects.toString(entry.observationId(), "-")),
                    entry.recordFound() ? Objects.toString(entry.decidedAt(), "-") : out.m("pqa.report.reversals.noRecord"),
                    code(Objects.toString(entry.action(), "-")) + " / " + code(Objects.toString(entry.proposedAction(),
                            "-")), code(Objects.toString(entry.version(), "-")),
                    code(Objects.toString(entry.evaluationReason(), "-")), cell(Objects.toString(entry.reviewer(), "-")),
                    code(Objects.toString(entry.subject(), "-")), entry.noted() ? out.m("pqa.report.reversals.noted")
                            : "-"));
        }
        out.table(List.of(out.m("pqa.report.column.at"), out.m("pqa.report.column.kind"),
                out.m("pqa.report.column.decision"), out.m("pqa.report.column.decidedAt"),
                out.m("pqa.report.column.action"), out.m("pqa.report.column.version"),
                out.m("pqa.report.column.reason"), out.m("pqa.report.column.reviewer"),
                out.m("pqa.report.column.subject"), out.m("pqa.report.column.note")), rows);
        if (reversals.leftOut() > 0) {
            out.blank();
            out.line(out.m("pqa.report.leftOut", String.valueOf(reversals.leftOut())));
        }
        out.blank();
    }

    private static void history(Text out, QualityReport.History history) {
        out.line("## " + out.m("pqa.report.section.history"));
        out.blank();
        out.line("### " + out.m("pqa.report.history.audit"));
        out.blank();
        if (history.audit().isEmpty()) {
            out.line(out.m("pqa.report.history.noAudit"));
        }
        else {
            out.line(out.m("pqa.report.history.byAction", counts(history.auditByAction())));
            out.blank();
            out.table(List.of(out.m("pqa.report.column.at"), out.m("pqa.report.column.by"),
                    out.m("pqa.report.column.action"), out.m("pqa.report.column.resource"),
                    out.m("pqa.report.column.reason")), history.audit().stream().map(entry -> List.of(entry.at(),
                    cell(entry.actor()), code(entry.action()), code(entry.resource()),
                    cell(Objects.toString(entry.reason(), "-")))).toList());
            if (history.auditLeftOut() > 0) {
                out.blank();
                out.line(out.m("pqa.report.leftOut", String.valueOf(history.auditLeftOut())));
            }
        }
        out.blank();
        out.line("### " + out.m("pqa.report.history.transitions"));
        out.blank();
        out.line(out.m("pqa.report.history.overrides", String.valueOf(history.overrides())));
        out.blank();
        if (history.transitions().isEmpty()) {
            out.line(out.m("pqa.report.history.noTransitions"));
        }
        else {
            out.table(List.of(out.m("pqa.report.column.at"), out.m("pqa.report.column.version"),
                    out.m("pqa.report.column.transition"), out.m("pqa.report.column.workflow"),
                    out.m("pqa.report.column.gate"), out.m("pqa.report.column.by"),
                    out.m("pqa.report.column.channel"), out.m("pqa.report.column.rationale")),
                    history.transitions().stream().map(entry -> List.of(entry.at(), code(entry.version()),
                            code(entry.fromStatus()) + " -> " + code(entry.toStatus()), code(entry.workflowState()),
                            code(entry.gateState()) + (entry.overridden() ? " (" + out.m("pqa.report.history.overridden")
                                    + ")" : ""), cell(entry.actor()), code(entry.channel()),
                            cell(entry.rationale()))).toList());
            if (history.transitionsLeftOut() > 0) {
                out.blank();
                out.line(out.m("pqa.report.leftOut", String.valueOf(history.transitionsLeftOut())));
            }
        }
        out.blank();
        out.line("### " + out.m("pqa.report.history.rollbacks"));
        out.blank();
        if (history.rollbacks().isEmpty()) {
            out.line(out.m("pqa.report.history.noRollbacks"));
        }
        else {
            out.table(List.of(out.m("pqa.report.column.at"), out.m("pqa.report.column.transition"),
                    out.m("pqa.report.column.by"), out.m("pqa.report.column.emergency"),
                    out.m("pqa.report.column.status"), out.m("pqa.report.column.approved"),
                    out.m("pqa.report.column.reason")), history.rollbacks().stream().map(entry -> List.of(entry.at(),
                    code(entry.fromVersion()) + " -> " + code(entry.toVersion()),
                    cell(Objects.toString(entry.actor(), "-")), entry.emergency() ? "O" : "", code(entry.status()),
                    entry.approvedBy() != null ? cell(entry.approvedBy()) + " / " + Objects.toString(entry.approvedAt(),
                            "-") : "-", cell(Objects.toString(entry.reason(), "-")))).toList());
            if (history.rollbacksLeftOut() > 0) {
                out.blank();
                out.line(out.m("pqa.report.leftOut", String.valueOf(history.rollbacksLeftOut())));
            }
        }
        out.blank();
    }

    private static void masking(Text out, QualityReport.Masking masking) {
        out.line("## " + out.m("pqa.report.section.masking"));
        out.blank();
        for (String rule : masking.rules()) {
            out.line("- " + out.m("pqa.report.masking.rule." + rule));
        }
        out.blank();
        out.line(out.m("pqa.report.masking.counts", String.valueOf(masking.subjects()),
                String.valueOf(masking.scrubbedTexts())));
    }

    // ----- the pieces -----

    private static List<List<String>> scoreRows(Text out, PromptQualityStatus.Score first,
                                                PromptQualityStatus.Score last) {
        List<List<String>> rows = new ArrayList<>();
        for (Map.Entry<String, PromptQualityStatus.Rate> rate : first.rates().entrySet()) {
            rows.add(List.of(out.m("pqa.report.metric." + rate.getKey()), rate(out, rate.getValue()),
                    rate(out, last.rates().get(rate.getKey()))));
        }
        return rows;
    }

    private static void findings(Text out, List<QualityReport.Finding> findings) {
        out.table(List.of(out.m("pqa.report.column.condition"), out.m("pqa.report.column.status"),
                out.m("pqa.report.column.figures"), out.m("pqa.report.column.cases")), findings.stream()
                .map(finding -> List.of(out.m("pqa.report.condition." + finding.condition()),
                        out.m("pqa.report.status." + finding.status()), cell(finding.figures().entrySet().stream()
                                .map(figure -> figure.getKey() + "=" + figure.getValue())
                                .collect(Collectors.joining(", "))), codes(finding.caseKeys()))).toList());
    }

    /** A rate of a measurement: numerator, denominator, value and its 95% interval over the roots; or none. */
    static String rate(Text out, @Nullable PromptQualityStatus.Rate rate) {
        if (rate == null || rate.trials() == 0 || rate.value() == null) {
            return out.m("pqa.report.rate.none");
        }
        return out.m("pqa.report.rate", String.valueOf(rate.events()), String.valueOf(rate.trials()),
                percent(rate.value()), percentOrDash(rate.lower()), percentOrDash(rate.upper()),
                String.valueOf(rate.roots()));
    }

    /** A rate of the operation: numerator, denominator, value and its 95% interval over the decisions; or none. */
    static String operationRate(Text out, @Nullable PromptQualityStatus.Rate rate) {
        if (rate == null || rate.trials() == 0 || rate.value() == null) {
            return out.m("pqa.report.rate.none");
        }
        return out.m("pqa.report.rate.operation", String.valueOf(rate.events()), String.valueOf(rate.trials()),
                percent(rate.value()), percentOrDash(rate.lower()), percentOrDash(rate.upper()));
    }

    private static String none(Text out, String reason) {
        return out.m("pqa.report.none") + ": " + out.m("pqa.report.missing." + reason);
    }

    private static String spread(PromptQualityStatus.Spread spread) {
        if (spread.count() == 0 || spread.median() == null) {
            return "-";
        }
        return String.format(Locale.ROOT, "%.0f / %s (n=%d)", spread.median(),
                spread.ninetyFifth() != null ? String.format(Locale.ROOT, "%.0f", spread.ninetyFifth()) : "-",
                spread.count());
    }

    private static String changed(Map<String, List<String>> settings) {
        return settings.entrySet().stream().map(entry -> entry.getKey() + ": " + String.join(" -> ", entry.getValue()))
                .collect(Collectors.joining("; "));
    }

    private static String counts(Map<String, Integer> counts) {
        if (counts.isEmpty()) {
            return "-";
        }
        return cell(counts.entrySet().stream().map(entry -> entry.getKey() + " " + entry.getValue())
                .collect(Collectors.joining(", ")));
    }

    private static String codes(List<String> keys) {
        return keys.isEmpty() ? "-" : keys.stream().map(QualityReportBundle::code).collect(Collectors.joining(", "));
    }

    private static String percent(double value) {
        return String.format(Locale.ROOT, "%.1f%%", value * 100);
    }

    private static String percentOrDash(@Nullable Double value) {
        return value != null ? percent(value) : "-";
    }

    private static String probability(@Nullable Double value) {
        return value != null ? String.format(Locale.ROOT, "%.4f", value) : "-";
    }

    /** An identifier in a cell: as code, with what would end it or a cell taken out. */
    static String code(@Nullable String value) {
        if (value == null) {
            return "-";
        }
        return "`" + value.replace("`", "'").replace("|", "/").replaceAll("[\\r\\n]+", " ") + "`";
    }

    /**
     * A text in a cell of a table: on one line, with the column mark escaped and the marks of HTML and of code made
     * plain, so a written text can neither break the table nor become markup when the file is shown.
     */
    static String cell(@Nullable String value) {
        if (value == null) {
            return "-";
        }
        return value.replace("\\", "\\\\").replace("|", "\\|").replace("`", "'").replace("<", "&lt;")
                .replace(">", "&gt;").replaceAll("[\\r\\n]+", " ").trim();
    }

    /** The lines of a readable file, with the texts of the language. */
    static final class Text {

        private final MessageSource messages;
        private final Locale locale;
        private final StringBuilder text = new StringBuilder();

        Text(MessageSource messages, Locale locale) {
            this.messages = messages;
            this.locale = locale;
        }

        /** The text of the key in the language; a key the bundles lack stops the report. */
        String m(String key, Object... arguments) {
            return messages.getMessage(key, arguments.length == 0 ? null : arguments, locale);
        }

        void line(String line) {
            text.append(line).append('\n');
        }

        void blank() {
            text.append('\n');
        }

        void table(List<String> heads, List<List<String>> rows) {
            line("| " + String.join(" | ", heads) + " |");
            line("|" + " --- |".repeat(heads.size()));
            for (List<String> row : rows) {
                line("| " + String.join(" | ", row) + " |");
            }
        }

        @Override
        public String toString() {
            return text.toString();
        }
    }
}
