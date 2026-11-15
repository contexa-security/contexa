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
package io.contexa.contexaiam.admin.web.zerotrust;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContractV4;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MetricValue;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Adoption;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Alert;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.BlockOutcome;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.BundleModelRow;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Cell;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.ChallengeFunnel;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.ChallengedUser;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Component;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Cost;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.CostSide;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.CoverageCard;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Criterion;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DayPoint;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.EvidenceSection;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.FailureDay;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Header;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.HourPoint;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Impact;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.ImpactCard;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.ModeChange;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Operations;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.OutcomeSection;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Overview;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.OverviewSummary;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.QualitySection;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.RangedMetric;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.RankedItem;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Share;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.SourceSection;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.StageLatency;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Storage;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.StoppedCard;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.StoppedSide;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Throughput;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Trust;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.TrustCard;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.UnknownFact;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.WouldHave;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleReader.DayRow;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleReader.ItemRow;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleReader.LatencyRow;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleReader.StatsRow;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.jdbc.core.JdbcOperations;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.ToLongFunction;
import java.util.stream.Collectors;

/**
 * The numbers of the Zero Trust console's screens (console design 3, 5, 6). A decision is a first attempt that
 * reached an action; a technical failure is a "no decision"; SHADOW's numbers are what ENFORCE would have done. Every
 * number is read from the hourly tables, and a number without data says why instead of showing 0.
 */
@Slf4j
public class ZeroTrustConsoleService {

    /** The action of a request that got no decision (a technical failure). */
    public static final String NO_DECISION = "NO_DECISION";
    static final List<String> STOPPED = List.of("CHALLENGE", "ESCALATE", "BLOCK");
    static final String SHADOW = "SHADOW";
    static final String ENFORCE = "ENFORCE";
    private static final int TOP = 10;

    private final ZeroTrustConsoleReader reader;
    private final SecurityZeroTrustProperties properties;
    private final MessageSource messages;
    private final ObjectMapper objectMapper;
    private final Supplier<SecurityPlaneAgent> agent;
    private final boolean standalone;
    private final Clock clock;

    public ZeroTrustConsoleService(Supplier<JdbcOperations> jdbc, SecurityZeroTrustProperties properties,
                                   MessageSource messages, ObjectMapper objectMapper, Supplier<SecurityPlaneAgent> agent,
                                   boolean standalone, Clock clock) {
        this.reader = new ZeroTrustConsoleReader(jdbc);
        this.properties = properties != null ? properties : new SecurityZeroTrustProperties();
        this.messages = messages;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
        this.agent = agent != null ? agent : () -> null;
        this.standalone = standalone;
        this.clock = clock != null ? clock : Clock.systemDefaultZone();
    }

    ZeroTrustConsoleRange range(String period, String from, String to) {
        return ZeroTrustConsoleRange.of(period, from, to, clock);
    }

    // ----- the band above every screen (6.0) -----

    Header header(ZeroTrustConsoleRange range, String tenant, List<StatsRow> rows) {
        String mode = properties.getMode() != null ? properties.getMode().name() : null;
        Instant since = modeSince(mode);
        Map<String, Long> bundles = new LinkedHashMap<>();
        Map<String, Long> models = new LinkedHashMap<>();
        for (StatsRow row : rows) {
            if (row.decision()) {
                bundles.merge(blankAsNone(row.bundle()), row.decisions(), Long::sum);
                models.merge(blankAsNone(row.model()), row.decisions(), Long::sum);
            }
        }
        return new Header(range.period(), mode, since != null ? since.toString() : null, decisions(rows),
                reader.distinct(range, tenant, null, "USER", null), ZeroTrustConsoleMetrics.shares(bundles),
                ZeroTrustConsoleMetrics.shares(models), standalone, tenant);
    }

    /** Since when the mode in effect has been in effect: the operator's change to it, else its first decision. */
    Instant modeSince(String mode) {
        for (String[] change : reader.modeChanges(50)) {
            if (mode != null && mode.equals(change[2])) {
                return Instant.parse(change[0]);
            }
        }
        return reader.firstDecisionIn(mode);
    }

    // ----- overview (6.1) -----

    public Overview overview(String period, String from, String to, String tenant, Locale locale) {
        ZeroTrustConsoleRange range = range(period, from, to);
        ZeroTrustConsoleMetrics metrics = new ZeroTrustConsoleMetrics(messages, locale);
        List<StatsRow> rows = reader.stats(range, tenant);
        long decisions = decisions(rows);
        long stopped = sum(rows, r -> STOPPED.contains(r.action()), StatsRow::decisions);
        long challenges = sum(rows, r -> "CHALLENGE".equals(r.action()), StatsRow::decisions);
        long passed = sum(rows, r -> "CHALLENGE".equals(r.action()), StatsRow::passed);
        long blocks = sum(rows, r -> "BLOCK".equals(r.action()), StatsRow::decisions);
        long released = sum(rows, r -> "BLOCK".equals(r.action()), StatsRow::released);
        long users = reader.distinct(range, tenant, null, "USER", null);

        OverviewSummary summary = new OverviewSummary(decisions, stopped,
                decisions == 0 ? null : (double) stopped / decisions, challenges, passed, blocks, released);
        CoverageCard coverage = coverage(range, tenant, rows, metrics);
        Map<String, Long> byAction = new LinkedHashMap<>();
        for (String action : STOPPED) {
            byAction.put(action, sum(rows, r -> action.equals(r.action()), StatsRow::decisions));
        }
        long beforeResponse = sum(rows, r -> STOPPED.contains(r.action()) && "BEFORE_RESPONSE".equals(r.timing()),
                StatsRow::decisions);
        StoppedCard stoppedCard = new StoppedCard(metrics.ratio("stopped", stopped, decisions,
                ZeroTrustConsoleMetrics.NO_DECISIONS), ZeroTrustConsoleMetrics.sharesOf(byAction, stopped),
                metrics.ratio("stoppedBeforeResponse", beforeResponse, stopped, ZeroTrustConsoleMetrics.EMPTY_DENOMINATOR));
        LatencyRow wait = latency(range, tenant, null).get("USER_WAIT");
        ImpactCard impact = new ImpactCard(
                metrics.value("challengesPerUserWeek", users == 0 ? null : challenges / (double) users / range.weeks(),
                        "PER_USER_WEEK", ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.ranged("challengePass", passed, challenges, ZeroTrustConsoleMetrics.EMPTY_DENOMINATOR),
                userWait(metrics, "userWaitP95", wait, 0.95),
                metrics.ranged("blockRelease", released, blocks, ZeroTrustConsoleMetrics.EMPTY_DENOMINATOR));
        long reviewed = sum(rows, StatsRow::decision, r -> r.valid() + r.invalid());
        TrustCard trust = new TrustCard(
                metrics.ratio("modelDecided", sum(rows, r -> r.decision() && "MODEL".equals(r.source()),
                        StatsRow::decisions), decisions, ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.ratio("baselineEstablished", sum(rows, StatsRow::decision, StatsRow::established), decisions,
                        ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.ranged("reviewValid", sum(rows, StatsRow::decision, StatsRow::valid), reviewed,
                        ZeroTrustConsoleMetrics.EMPTY_DENOMINATOR),
                metrics.ratio("modelLess", sum(rows, r -> r.decision() && "MODEL_LESS".equals(r.source()),
                        StatsRow::decisions), decisions, ZeroTrustConsoleMetrics.NO_DECISIONS));
        List<Share> reasonGroups = reasonGroups(range, tenant, null);
        return new Overview(header(range, tenant, rows), summary, coverage, stoppedCard, impact, trust,
                trend(range, tenant), reasonGroups, alerts(range, tenant, rows, metrics));
    }

    /**
     * Console design 5: the protected calls that a decision answered, new or still valid. The coverage counts are
     * the nodes' over every tenant, so a tenant's coverage is not shown.
     */
    CoverageCard coverage(ZeroTrustConsoleRange range, String tenant, List<StatsRow> rows,
                          ZeroTrustConsoleMetrics metrics) {
        long technical = sum(rows, r -> !r.decision(), StatsRow::decisions);
        if (tenant != null) {
            return new CoverageCard(metrics.unavailable("coverage", "RATIO", ZeroTrustConsoleMetrics.TENANT_FILTERED),
                    metrics.unavailable("noDecision", "COUNT", ZeroTrustConsoleMetrics.TENANT_FILTERED), List.of());
        }
        Map<String, Long> counts = reader.coverage(range);
        long protectedCalls = counts.getOrDefault("PROTECTED_CALL", 0L);
        long reused = counts.getOrDefault("REUSED", 0L);
        long decided = sum(rows, StatsRow::decision, StatsRow::protectedDecisions);
        Map<String, Long> reasons = new LinkedHashMap<>();
        reasons.put("REUSED", reused);
        counts.forEach((key, count) -> {
            if (key.startsWith("SKIPPED:")) {
                reasons.merge(key.substring("SKIPPED:".length()), count, Long::sum);
            }
        });
        if (technical > 0) {
            reasons.put("TECHNICAL_FAILURE", technical);
        }
        long noDecision = ZeroTrustConsoleMetrics.sum(reasons.values());
        // A decision can land in the period of a call counted before it: the coverage never reads past all.
        long answered = Math.min(protectedCalls, decided + reused);
        return new CoverageCard(metrics.ratio("coverage", answered, protectedCalls, ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.count("noDecision", noDecision), ZeroTrustConsoleMetrics.shares(reasons));
    }

    List<DayPoint> trend(ZeroTrustConsoleRange range, String tenant) {
        return trend(range, tenant, null);
    }

    List<DayPoint> trend(ZeroTrustConsoleRange range, String tenant, String mode) {
        Map<LocalDate, long[]> days = new TreeMap<>();
        for (DayRow row : reader.days(range, tenant, mode)) {
            long[] day = days.computeIfAbsent(row.day(), ignored -> new long[13]);
            switch (row.action()) {
                case "ALLOW" -> day[0] += row.decisions();
                case "CHALLENGE" -> day[1] += row.decisions();
                case "ESCALATE" -> day[2] += row.decisions();
                case "BLOCK" -> day[3] += row.decisions();
                case NO_DECISION -> day[4] += row.decisions();
                default -> {
                }
            }
            if (!NO_DECISION.equals(row.action())) {
                day[5] += row.decisions();
                day[6] += row.established();
                switch (row.source()) {
                    case "MODEL" -> day[7] += row.decisions();
                    case "ENGINE_CHANGED" -> day[8] += row.decisions();
                    case "MODEL_LESS" -> day[9] += row.decisions();
                    default -> {
                    }
                }
                day[10] += row.passed();
                day[11] += row.tokens();
                day[12] += row.protectedDecisions();
            }
        }
        // The coverage counts are the nodes' over every tenant, and SHADOW's decisions are no coverage of their own.
        Map<LocalDate, Map<String, Long>> coverage = tenant == null && mode == null ? reader.coverageDays(range) : Map.of();
        Map<LocalDate, long[]> latency = reader.latencyDays(range, tenant, "TOTAL");
        List<DayPoint> points = new ArrayList<>();
        days.forEach((day, n) -> {
            Map<String, Long> counts = coverage.get(day);
            long[] buckets = latency.get(day);
            points.add(new DayPoint(day.toString(), n[0], n[1], n[2], n[3], n[4], n[5] == 0 ? null : (double) n[6] / n[5],
                    n[7], n[8], n[9], n[10], n[11], counts == null ? null : counts.getOrDefault("PROTECTED_CALL", 0L),
                    counts == null ? null : counts.getOrDefault("REUSED", 0L),
                    buckets == null ? null : ZeroTrustConsoleMetrics.percentile(buckets, 0.95), n[12]));
        });
        return points;
    }

    /** The groups of the first reason of the stopped decisions (console design 6.1). */
    List<Share> reasonGroups(ZeroTrustConsoleRange range, String tenant, String mode) {
        Map<String, Long> groups = new LinkedHashMap<>();
        for (ItemRow row : reader.items(range, tenant, mode, "FIRST_REASON")) {
            if (STOPPED.contains(row.detail())) {
                groups.merge(groupOf(row.item()), row.counted(), Long::sum);
            }
        }
        return ZeroTrustConsoleMetrics.shares(groups);
    }

    /**
     * The overview's warnings (console design 6.1): each is a rule on the period's numbers, with its definition in the
     * messages and the decision list it opens.
     */
    List<Alert> alerts(ZeroTrustConsoleRange range, String tenant, List<StatsRow> rows, ZeroTrustConsoleMetrics metrics) {
        List<Alert> alerts = new ArrayList<>();
        long blocks = sum(rows, r -> "BLOCK".equals(r.action()), StatsRow::decisions);
        long answeredBlocks = sum(rows, r -> "BLOCK".equals(r.action()), r -> r.released() + r.kept()
                + r.valid() + r.invalid());
        long unreviewed = Math.max(0, blocks - answeredBlocks);
        if (unreviewed > 0) {
            alerts.add(new Alert("unreviewedBlocks", "WARN",
                    metrics.message("zt.console.alert.unreviewedBlocks", unreviewed + " blocks no administrator has "
                            + "reviewed", unreviewed), "/contexa/admin/zero-trust/decisions?action=BLOCK&outcome=NONE"));
        }
        ZeroTrustConsoleRange today = new ZeroTrustConsoleRange("day", clock.instant().minus(Duration.ofHours(24)),
                clock.instant());
        ZeroTrustConsoleRange yesterday = new ZeroTrustConsoleRange("day", today.from().minus(Duration.ofHours(24)),
                today.from());
        long modelLessToday = sum(reader.stats(today, tenant), r -> r.decision() && "MODEL_LESS".equals(r.source()),
                StatsRow::decisions);
        long modelLessYesterday = sum(reader.stats(yesterday, tenant),
                r -> r.decision() && "MODEL_LESS".equals(r.source()), StatsRow::decisions);
        if (modelLessToday >= 10 && modelLessToday >= 3 * Math.max(1, modelLessYesterday)) {
            alerts.add(new Alert("modelLessRising", "WARN",
                    metrics.message("zt.console.alert.modelLessRising", "Decisions set without the model rose to "
                            + modelLessToday + " in 24 hours", modelLessToday, modelLessYesterday),
                    "/contexa/admin/zero-trust/decisions?period=day&source=MODEL_LESS"));
        }
        long decisions = decisions(rows);
        long established = sum(rows, StatsRow::decision, StatsRow::established);
        if (decisions >= 100 && established < 0.7 * decisions) {
            long share = Math.round(100.0 * (decisions - established) / decisions);
            alerts.add(new Alert("baselineNotEstablished", "INFO",
                    metrics.message("zt.console.alert.baselineNotEstablished", share
                            + "% of decisions without an established baseline", share),
                    "/contexa/admin/zero-trust/trust"));
        }
        List<ItemRow> unknown = reader.top(range, tenant, null, "UNKNOWN_FACT", List.of("NOT_INTEGRATED"), 1);
        if (!unknown.isEmpty() && unknown.get(0).counted() > 0) {
            String fact = unknown.get(0).item();
            String factName = metrics.message("zt.console.fact." + fact, fact);
            alerts.add(new Alert("notIntegrated", "INFO",
                    metrics.message("zt.console.alert.notIntegrated", "The fact the model most often lacked: "
                            + factName, factName, unknown.get(0).counted()),
                    "/contexa/admin/zero-trust/trust"));
        }
        return alerts;
    }

    // ----- threats and business impact (6.2) -----

    public Impact impact(String period, String from, String to, String tenant, Locale locale) {
        ZeroTrustConsoleRange range = range(period, from, to);
        ZeroTrustConsoleMetrics metrics = new ZeroTrustConsoleMetrics(messages, locale);
        List<StatsRow> rows = reader.stats(range, tenant);
        long stopped = sum(rows, r -> STOPPED.contains(r.action()), StatsRow::decisions);
        Map<String, Long> byAction = new LinkedHashMap<>();
        for (String action : STOPPED) {
            byAction.put(action, sum(rows, r -> action.equals(r.action()), StatsRow::decisions));
        }
        Map<String, Long> timing = group(rows, r -> STOPPED.contains(r.action()), StatsRow::timing);
        Map<String, Long> hypotheses = group(rows, r -> STOPPED.contains(r.action()) && !r.hypothesis().isEmpty(),
                StatsRow::hypothesis);
        long explained = ZeroTrustConsoleMetrics.sum(hypotheses.values());
        Map<String, Long> classes = group(rows, r -> STOPPED.contains(r.action()), StatsRow::resourceClass);
        StoppedSide stoppedSide = new StoppedSide(stopped, ZeroTrustConsoleMetrics.sharesOf(byAction, stopped),
                ZeroTrustConsoleMetrics.sharesOf(timing, stopped), explained,
                ZeroTrustConsoleMetrics.sharesOf(hypotheses, explained), ZeroTrustConsoleMetrics.sharesOf(classes, stopped),
                ranked(range, tenant, "FIRST_REASON", STOPPED), ranked(range, tenant, "RESOURCE", STOPPED),
                ranked(range, tenant, "USER", STOPPED));

        long challenges = byAction.get("CHALLENGE");
        long passed = sum(rows, r -> "CHALLENGE".equals(r.action()), StatsRow::passed);
        long failed = sum(rows, r -> "CHALLENGE".equals(r.action()), StatsRow::failed);
        long expired = sum(rows, r -> "CHALLENGE".equals(r.action()), StatsRow::expired);
        ChallengeFunnel funnel = new ChallengeFunnel(challenges,
                metrics.unavailable("codeRequests", "COUNT", ZeroTrustConsoleMetrics.NOT_RECORDED), passed, failed,
                expired, metrics.ranged("challengePass", passed, challenges, ZeroTrustConsoleMetrics.EMPTY_DENOMINATOR));
        long blocks = byAction.get("BLOCK");
        long released = sum(rows, r -> "BLOCK".equals(r.action()), StatsRow::released);
        long kept = sum(rows, r -> "BLOCK".equals(r.action()), StatsRow::kept);
        Double releaseHours = reader.releaseMedianHours(range, tenant);
        BlockOutcome blockOutcome = new BlockOutcome(blocks, released, kept,
                metrics.value("releaseMedianHours", releaseHours, "HOURS", ZeroTrustConsoleMetrics.EMPTY_DENOMINATOR));
        LatencyRow wait = latency(range, tenant, null).get("USER_WAIT");
        List<Double> burden = burden(range, tenant, null);
        CostSide cost = new CostSide(funnel, userWait(metrics, "userWaitP50", wait, 0.5),
                userWait(metrics, "userWaitP95", wait, 0.95), byAction.get("ESCALATE"), blockOutcome,
                metrics.value("burdenMedianPerWeek", ZeroTrustConsoleMetrics.percentileOf(burden, 0.5), "PER_USER_WEEK",
                        ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.value("burdenP95PerWeek", ZeroTrustConsoleMetrics.percentileOf(burden, 0.95), "PER_USER_WEEK",
                        ZeroTrustConsoleMetrics.NO_DECISIONS),
                challengedUsers(range, tenant));
        List<Cell> whenStopped = new ArrayList<>();
        for (long[] cell : reader.stoppedByWeekdayAndBand(range, tenant)) {
            whenStopped.add(new Cell(String.valueOf(cell[0]), String.valueOf(cell[1]), cell[2]));
        }
        Map<String, Long> matrix = new LinkedHashMap<>();
        for (StatsRow row : rows) {
            if (STOPPED.contains(row.action())) {
                matrix.merge(blankAsNone(row.hypothesis()) + '\u0000' + blankAsNone(row.resourceClass()), row.decisions(),
                        Long::sum);
            }
        }
        List<Cell> hypothesisByClass = new ArrayList<>();
        matrix.forEach((key, count) -> {
            String[] parts = key.split("\u0000", -1);
            hypothesisByClass.add(new Cell(parts[0], parts[1], count));
        });
        Map<String, Long> histogram = new LinkedHashMap<>();
        for (String bucket : List.of("0", "1", "2", "3", "4+")) {
            histogram.put(bucket, 0L);
        }
        challengesPerUser(range, tenant, null).values().forEach(count ->
                histogram.merge(count >= 4 ? "4+" : String.valueOf(count), 1L, Long::sum));
        return new Impact(header(range, tenant, rows), stoppedSide, cost, whenStopped, hypothesisByClass,
                ZeroTrustConsoleMetrics.sharesOf(histogram, ZeroTrustConsoleMetrics.sum(histogram.values()))
                        .stream().sorted(Comparator.comparing(share -> share.key())).toList());
    }

    /** The challenges each decided user got in the period, a user without one counted as 0. */
    Map<String, Long> challengesPerUser(ZeroTrustConsoleRange range, String tenant, String mode) {
        Map<String, Long> perUser = new LinkedHashMap<>();
        for (ItemRow row : reader.items(range, tenant, mode, "USER")) {
            perUser.merge(row.item(), "CHALLENGE".equals(row.detail()) ? row.counted() : 0L, Long::sum);
        }
        return perUser;
    }

    /** The challenges each decided user got per week in the period, a user without one counted as 0. */
    List<Double> burden(ZeroTrustConsoleRange range, String tenant, String mode) {
        double weeks = range.weeks();
        return challengesPerUser(range, tenant, mode).values().stream().map(count -> count / weeks)
                .collect(Collectors.toList());
    }

    List<ChallengedUser> challengedUsers(ZeroTrustConsoleRange range, String tenant) {
        List<ItemRow> top = reader.top(range, tenant, null, "USER", List.of("CHALLENGE"), TOP);
        if (top.isEmpty()) {
            return List.of();
        }
        Map<String, Long> passed = new LinkedHashMap<>();
        reader.items(range, tenant, null, "USER_PASSED").forEach(row -> passed.merge(row.item(), row.counted(), Long::sum));
        Map<String, Map<String, Long>> reasons = new LinkedHashMap<>();
        reader.items(range, tenant, null, "USER_REASON").forEach(row -> reasons
                .computeIfAbsent(row.item(), ignored -> new LinkedHashMap<>()).merge(row.detail(), row.counted(), Long::sum));
        Map<String, String> baselines = latestBaselines(range, tenant);
        List<ChallengedUser> users = new ArrayList<>();
        for (ItemRow row : top) {
            // The reason the user's challenges cited first most often; a tie goes to the code first in order.
            String mainReason = reasons.getOrDefault(row.item(), Map.of()).entrySet().stream()
                    .sorted(Map.Entry.<String, Long>comparingByValue().reversed()
                            .thenComparing(Map.Entry.comparingByKey()))
                    .map(Map.Entry::getKey).findFirst().orElse(null);
            users.add(new ChallengedUser(row.item(), row.counted(), passed.getOrDefault(row.item(), 0L), mainReason,
                    baselines.get(row.item())));
        }
        return users;
    }

    /** Each user's baseline status in the latest hour the user was decided in. */
    private Map<String, String> latestBaselines(ZeroTrustConsoleRange range, String tenant) {
        Map<String, Map<String, Long>> statuses = new LinkedHashMap<>();
        reader.items(range, tenant, null, "USER_BASELINE").forEach(row -> statuses
                .computeIfAbsent(row.item(), ignored -> new LinkedHashMap<>()).merge(row.detail(), row.counted(), Long::sum));
        Map<String, String> latest = new LinkedHashMap<>();
        statuses.forEach((user, counts) -> latest.put(user, counts.entrySet().stream()
                .max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse(null)));
        return latest;
    }

    private List<RankedItem> ranked(ZeroTrustConsoleRange range, String tenant, String dimension, List<String> details) {
        List<ItemRow> top = reader.top(range, tenant, null, dimension, details, TOP);
        if (top.isEmpty()) {
            return List.of();
        }
        Map<String, Map<String, Long>> byDetail = new LinkedHashMap<>();
        for (ItemRow row : reader.items(range, tenant, null, dimension)) {
            if (details == null || details.contains(row.detail())) {
                byDetail.computeIfAbsent(row.item(), ignored -> new LinkedHashMap<>())
                        .merge(row.detail(), row.counted(), Long::sum);
            }
        }
        List<RankedItem> ranked = new ArrayList<>();
        for (ItemRow row : top) {
            ranked.add(new RankedItem(row.item(), row.counted(), byDetail.getOrDefault(row.item(), Map.of()),
                    "FIRST_REASON".equals(dimension) ? groupOf(row.item()) : null));
        }
        return ranked;
    }

    // ----- trust (6.3) -----

    public Trust trust(String period, String from, String to, String tenant, Locale locale) {
        ZeroTrustConsoleRange range = range(period, from, to);
        ZeroTrustConsoleMetrics metrics = new ZeroTrustConsoleMetrics(messages, locale);
        List<StatsRow> rows = reader.stats(range, tenant);
        long decisions = decisions(rows);
        long model = sum(rows, r -> r.decision() && "MODEL".equals(r.source()), StatsRow::decisions);
        long engine = sum(rows, r -> r.decision() && "ENGINE_CHANGED".equals(r.source()), StatsRow::decisions);
        long modelLess = sum(rows, r -> r.decision() && "MODEL_LESS".equals(r.source()), StatsRow::decisions);
        SourceSection source = new SourceSection(
                metrics.ratio("modelDecided", model, decisions, ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.ratio("engineChanged", engine, decisions, ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.ratio("modelLess", modelLess, decisions, ZeroTrustConsoleMetrics.NO_DECISIONS),
                ZeroTrustConsoleMetrics.sharesOf(group(rows, r -> r.decision() && "ENGINE_CHANGED".equals(r.source()),
                        StatsRow::cause), engine),
                ZeroTrustConsoleMetrics.sharesOf(group(rows, r -> r.decision() && "MODEL_LESS".equals(r.source()),
                        StatsRow::cause), modelLess),
                sum(rows, r -> "BLOCK".equals(r.action()) && "MODEL_LESS".equals(r.source()), StatsRow::decisions));

        Map<String, Long> baseline = new LinkedHashMap<>();
        long established = sum(rows, StatsRow::decision, StatsRow::established);
        long provisional = sum(rows, StatsRow::decision, StatsRow::provisional);
        long none = sum(rows, StatsRow::decision, StatsRow::none);
        baseline.put("ESTABLISHED", established);
        baseline.put("PROVISIONAL", provisional);
        baseline.put("NONE", none);
        baseline.put("UNKNOWN", Math.max(0, decisions - established - provisional - none));
        Map<String, Long> context = new LinkedHashMap<>();
        context.put("ENVIRONMENT_ONLY", sum(rows, StatsRow::decision, StatsRow::environment));
        context.put("IDENTITY_AWARE", sum(rows, StatsRow::decision, StatsRow::identity));
        context.put("SCOPE_AWARE", sum(rows, StatsRow::decision, StatsRow::scope));
        context.put("BUSINESS_AWARE", sum(rows, StatsRow::decision, StatsRow::business));
        long withContext = ZeroTrustConsoleMetrics.sum(context.values());
        context.put("UNKNOWN", Math.max(0, decisions - withContext));
        List<UnknownFact> unknown = new ArrayList<>();
        Map<String, Map<String, Long>> unknownFacts = new LinkedHashMap<>();
        reader.items(range, tenant, null, "UNKNOWN_FACT").forEach(row -> unknownFacts
                .computeIfAbsent(row.item(), ignored -> new LinkedHashMap<>()).merge(row.detail(), row.counted(), Long::sum));
        unknownFacts.forEach((fact, reasons) -> unknown.add(new UnknownFact(fact,
                ZeroTrustConsoleMetrics.sum(reasons.values()), reasons.entrySet().stream()
                .max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse(null))));
        unknown.sort(Comparator.comparingLong(UnknownFact::decisions).reversed().thenComparing(UnknownFact::fact));
        EvidenceSection evidence = new EvidenceSection(ZeroTrustConsoleMetrics.sharesOf(baseline, decisions),
                reader.usersWithLatestBaseline(range, tenant, "ESTABLISHED"),
                reader.distinct(range, tenant, null, "USER", null), ZeroTrustConsoleMetrics.sharesOf(context, decisions),
                unknown.size() > TOP ? unknown.subList(0, TOP) : unknown);

        long challenges = sum(rows, r -> "CHALLENGE".equals(r.action()), StatsRow::decisions);
        long passed = sum(rows, r -> "CHALLENGE".equals(r.action()), StatsRow::passed);
        long blocks = sum(rows, r -> "BLOCK".equals(r.action()), StatsRow::decisions);
        long released = sum(rows, r -> "BLOCK".equals(r.action()), StatsRow::released);
        long valid = sum(rows, StatsRow::decision, StatsRow::valid);
        long reviewed = valid + sum(rows, StatsRow::decision, StatsRow::invalid);
        OutcomeSection outcomes = new OutcomeSection(
                metrics.ranged("challengePass", passed, challenges, ZeroTrustConsoleMetrics.EMPTY_DENOMINATOR),
                metrics.ranged("blockRelease", released, blocks, ZeroTrustConsoleMetrics.EMPTY_DENOMINATOR),
                metrics.ranged("reviewValid", valid, reviewed, ZeroTrustConsoleMetrics.EMPTY_DENOMINATOR),
                ZeroTrustConsoleMetrics.shares(reader.invalidReasons(range, tenant)), reader.reviewPending());

        QualitySection quality = new QualitySection(
                metrics.ratio("corrected", sum(rows, StatsRow::decision, StatsRow::retried), decisions,
                        ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.ratio("formatFallback", sum(rows, r -> r.decision() && "MODEL_LESS".equals(r.source())
                        && isResponseFormat(r.cause()), StatsRow::decisions), decisions, ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.ratio("contractFallback", sum(rows, r -> r.decision() && "CONTRACT_FALLBACK".equals(r.cause()),
                        StatsRow::decisions), decisions, ZeroTrustConsoleMetrics.NO_DECISIONS));
        return new Trust(header(range, tenant, rows), source, evidence, outcomes, quality, bundleModels(rows));
    }

    /** A fallback for an answer whose action had no usable form (console design 1.4). */
    private static boolean isResponseFormat(String cause) {
        return cause != null && (cause.startsWith("ACTION_") || "RESPONSE_FORMAT".equals(cause));
    }

    /** Console design 6.3: each prompt bundle and model, when it decided and how its decisions came out. */
    List<BundleModelRow> bundleModels(List<StatsRow> rows) {
        Map<String, long[]> counts = new LinkedHashMap<>();
        Map<String, Instant[]> spans = new LinkedHashMap<>();
        for (StatsRow row : rows) {
            if (!row.decision()) {
                continue;
            }
            String key = row.bundle() + '\u0000' + row.model();
            long[] count = counts.computeIfAbsent(key, ignored -> new long[3]);
            count[0] += row.decisions();
            count[1] += STOPPED.contains(row.action()) ? row.decisions() : 0;
            count[2] += "MODEL_LESS".equals(row.source()) ? row.decisions() : 0;
            Instant[] span = spans.computeIfAbsent(key, ignored -> new Instant[2]);
            if (row.first() != null && (span[0] == null || row.first().isBefore(span[0]))) {
                span[0] = row.first();
            }
            if (row.last() != null && (span[1] == null || row.last().isAfter(span[1]))) {
                span[1] = row.last();
            }
        }
        List<BundleModelRow> result = new ArrayList<>();
        counts.forEach((key, count) -> {
            String[] parts = key.split("\u0000", -1);
            Instant[] span = spans.get(key);
            result.add(new BundleModelRow(blankAsNone(parts[0]), blankAsNone(parts[1]),
                    span[0] != null ? span[0].toString() : null,
                    span[1] != null ? span[1].plus(Duration.ofHours(1)).toString() : null, count[0],
                    count[0] == 0 ? null : (double) count[1] / count[0],
                    count[0] == 0 ? null : (double) count[2] / count[0]));
        });
        result.sort(Comparator.comparing(BundleModelRow::from, Comparator.nullsLast(Comparator.naturalOrder())));
        return result;
    }

    // ----- adoption (6.5, decision 11.5) -----

    public Adoption adoption(String tenant, Locale locale) {
        ZeroTrustConsoleMetrics metrics = new ZeroTrustConsoleMetrics(messages, locale);
        SecurityZeroTrustProperties.Adoption criteria = properties.getConsole().getAdoption();
        String mode = properties.getMode() != null ? properties.getMode().name() : null;
        // What is weighed is the SHADOW trial: since SHADOW started, or the last 90 days of SHADOW decisions.
        Instant shadowSince = SHADOW.equals(mode) ? modeSince(SHADOW) : null;
        Instant now = clock.instant();
        Instant from = shadowSince != null ? shadowSince : now.minus(Duration.ofDays(90));
        ZeroTrustConsoleRange range = new ZeroTrustConsoleRange("custom", from, now);
        List<StatsRow> all = reader.stats(range, tenant);
        List<StatsRow> rows = all.stream().filter(r -> SHADOW.equals(r.mode())).toList();
        Instant first = rows.stream().map(StatsRow::first).filter(Objects::nonNull).min(Comparator.naturalOrder())
                .orElse(null);
        long days = first == null ? 0 : Math.max(1, Duration.between(first, now).toDays());
        long decisions = decisions(rows);
        long model = sum(rows, r -> r.decision() && "MODEL".equals(r.source()), StatsRow::decisions);
        long modelLess = sum(rows, r -> r.decision() && "MODEL_LESS".equals(r.source()), StatsRow::decisions);
        long established = sum(rows, StatsRow::decision, StatsRow::established);
        long valid = sum(rows, StatsRow::decision, StatsRow::valid);
        long reviewed = valid + sum(rows, StatsRow::decision, StatsRow::invalid);
        long business = sum(rows, StatsRow::decision, StatsRow::business);
        List<Double> burden = burden(range, tenant, SHADOW);
        Double burdenP95 = ZeroTrustConsoleMetrics.percentileOf(burden, 0.95);
        LatencyRow wait = latency(range, tenant, SHADOW).get("USER_WAIT");
        Long waitP95 = wait == null ? null : ZeroTrustConsoleMetrics.percentile(wait.buckets(), 0.95);

        List<Criterion> list = new ArrayList<>();
        boolean enough = days >= criteria.getMinObservedDays() && decisions >= criteria.getMinDecisions();
        list.add(new Criterion("observed", metrics.count("observedDecisions", decisions),
                criteria.getMinObservedDays() + "d/" + criteria.getMinDecisions(), enough ? "MET" : "INSUFFICIENT"));
        list.add(ratioCriterion(metrics, "modelDecided", model, decisions, criteria.getMinModelDecidedRatio(), true));
        list.add(ratioCriterion(metrics, "modelLess", modelLess, decisions, criteria.getMaxModelLessRatio(), false));
        list.add(ratioCriterion(metrics, "baselineEstablished", established, decisions,
                criteria.getMinBaselineEstablishedRatio(), true));
        RangedMetric review = metrics.ranged("reviewValid", valid, reviewed, ZeroTrustConsoleMetrics.EMPTY_DENOMINATOR);
        String reviewStatus = reviewed < criteria.getMinReviewSample() ? "INSUFFICIENT"
                : review.lower95() != null && review.lower95() >= criteria.getMinReviewValidLowerBound() ? "MET" : "UNMET";
        list.add(new Criterion("reviewValid", new MetricValue(review.metric().key(), review.metric().label(),
                review.metric().description(), review.lower95(), review.metric().numerator(),
                review.metric().denominator(), "RATIO", review.metric().noDataReason()),
                criteria.getMinReviewValidLowerBound() + "/" + criteria.getMinReviewSample(), reviewStatus));
        list.add(new Criterion("burdenP95", metrics.value("burdenP95PerWeek", burdenP95, "PER_USER_WEEK",
                ZeroTrustConsoleMetrics.NO_DECISIONS), String.valueOf(criteria.getMaxBurdenP95PerWeek()),
                burdenP95 == null ? "INSUFFICIENT" : burdenP95 <= criteria.getMaxBurdenP95PerWeek() ? "MET" : "UNMET"));
        list.add(new Criterion("userWaitP95", metrics.value("userWaitP95", waitP95 == null ? null : waitP95.doubleValue(),
                "MILLISECONDS", ZeroTrustConsoleMetrics.NO_SYNCHRONOUS_DECISIONS),
                String.valueOf(criteria.getMaxUserWaitP95Ms()),
                // No synchronous decision: nobody waited, which meets the bound.
                waitP95 == null || waitP95 <= criteria.getMaxUserWaitP95Ms() ? "MET" : "UNMET"));
        list.add(new Criterion("businessContext", metrics.ratio("businessContext", business, decisions,
                ZeroTrustConsoleMetrics.NO_DECISIONS), null, "INFO"));
        int unmet = (int) list.stream().filter(c -> "UNMET".equals(c.status()) || "INSUFFICIENT".equals(c.status()))
                .count();
        String verdict = !enough ? "DATA_INSUFFICIENT" : unmet > 0 ? "CONDITIONS_UNMET" : "RECOMMENDED";

        long stopped = sum(rows, r -> STOPPED.contains(r.action()), StatsRow::decisions);
        WouldHave wouldHave = new WouldHave(stopped, reader.distinct(range, tenant, SHADOW, "USER", STOPPED),
                reader.distinct(range, tenant, SHADOW, "USER", List.of("BLOCK")),
                metrics.value("burdenMedianPerWeek", ZeroTrustConsoleMetrics.percentileOf(burden, 0.5), "PER_USER_WEEK",
                        ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.value("burdenP95PerWeek", burdenP95, "PER_USER_WEEK", ZeroTrustConsoleMetrics.NO_DECISIONS));
        return new Adoption(header(range, tenant, all), verdict, unmet, mode,
                first != null ? first.toString() : null, days, list, wouldHave, trend(range, tenant, SHADOW),
                modeHistory());
    }

    private Criterion ratioCriterion(ZeroTrustConsoleMetrics metrics, String key, long numerator, long denominator,
                                     double bound, boolean atLeast) {
        MetricValue value = metrics.ratio(key, numerator, denominator, ZeroTrustConsoleMetrics.NO_DECISIONS);
        String status = value.value() == null ? "INSUFFICIENT"
                : (atLeast ? value.value() >= bound : value.value() <= bound) ? "MET" : "UNMET";
        return new Criterion(key, value, (atLeast ? ">=" : "<=") + bound, status);
    }

    List<ModeChange> modeHistory() {
        List<ModeChange> history = new ArrayList<>();
        for (String[] change : reader.modeChanges(20)) {
            String previous = null;
            try {
                JsonNode details = change[3] != null ? objectMapper.readTree(change[3]) : null;
                previous = details != null && details.hasNonNull("previousMode") ? details.get("previousMode").asText()
                        : null;
            } catch (Exception unreadable) {
                log.debug("[ZeroTrustConsole] The details of a mode change could not be read", unreadable);
            }
            history.add(new ModeChange(change[0], previous, change[2], change[1]));
        }
        return history;
    }

    // ----- operations (6.6) -----

    public Operations operations(String period, String from, String to, String tenant, Locale locale) {
        ZeroTrustConsoleRange range = range(period, from, to);
        ZeroTrustConsoleMetrics metrics = new ZeroTrustConsoleMetrics(messages, locale);
        List<StatsRow> rows = reader.stats(range, tenant);
        long decisions = decisions(rows);
        CoverageCard coverage = coverage(range, tenant, rows, metrics);
        Map<String, Long> counts = tenant == null ? reader.coverage(range) : Map.of();
        SecurityPlaneAgent planeAgent = agent.get();
        Throughput throughput = new Throughput(
                tenant == null ? metrics.value("protectedPerMinute",
                        counts.getOrDefault("PROTECTED_CALL", 0L) / (double) range.minutes(), "PER_MINUTE", null)
                        : metrics.unavailable("protectedPerMinute", "PER_MINUTE", ZeroTrustConsoleMetrics.TENANT_FILTERED),
                metrics.value("decisionsPerMinute", decisions / (double) range.minutes(), "PER_MINUTE", null),
                planeAgent != null ? planeAgent.analysesInProgress() : null);
        Map<LocalDate, Map<String, Long>> failures = new TreeMap<>();
        for (DayRow row : reader.days(range, tenant)) {
            boolean noDecision = NO_DECISION.equals(row.action());
            if (noDecision || "MODEL_LESS".equals(row.source())) {
                String cause = row.cause() == null || row.cause().isEmpty() ? "UNKNOWN" : row.cause();
                failures.computeIfAbsent(row.day(), ignored -> new LinkedHashMap<>())
                        .merge((noDecision ? "NO_DECISION:" : "MODEL_LESS:") + cause, row.decisions(), Long::sum);
            }
        }
        List<FailureDay> failureTrend = new ArrayList<>();
        failures.forEach((day, kinds) -> failureTrend.add(new FailureDay(day.toString(), kinds)));
        List<StageLatency> latency = new ArrayList<>();
        Map<String, LatencyRow> stages = latency(range, tenant, null);
        for (String stage : List.of("QUEUE", "PREPARE", "RAG", "MODEL", "PERSIST", "TOTAL")) {
            LatencyRow row = stages.get(stage);
            latency.add(new StageLatency(stage, row == null ? null : ZeroTrustConsoleMetrics.percentile(row.buckets(), 0.5),
                    row == null ? null : ZeroTrustConsoleMetrics.percentile(row.buckets(), 0.95),
                    row == null ? 0 : row.measured()));
        }
        List<Share> histogram = new ArrayList<>();
        LatencyRow total = stages.get("TOTAL");
        String[] bucketKeys = {"<=100ms", "<=250ms", "<=500ms", "<=1s", "<=2s", "<=5s", "<=10s", "<=30s", "<=60s", ">60s"};
        for (int i = 0; i < bucketKeys.length; i++) {
            long count = total == null ? 0 : total.buckets()[i];
            histogram.add(new Share(bucketKeys[i], count,
                    total == null || total.measured() == 0 ? null : (double) count / total.measured()));
        }
        long promptTokens = sum(rows, StatsRow::decision, StatsRow::promptTokens);
        long cachedTokens = sum(rows, StatsRow::decision, StatsRow::cachedTokens);
        long outputTokens = sum(rows, StatsRow::decision, StatsRow::outputTokens);
        long calls = sum(rows, StatsRow::decision, StatsRow::modelCalls);
        SecurityZeroTrustProperties.Console console = properties.getConsole();
        Double cost = null;
        if (console.getPromptTokenPricePerMillion() != null && console.getOutputTokenPricePerMillion() != null) {
            double cachedPrice = console.getCachedPromptTokenPricePerMillion() != null
                    ? console.getCachedPromptTokenPricePerMillion() : console.getPromptTokenPricePerMillion();
            cost = ((promptTokens - cachedTokens) * console.getPromptTokenPricePerMillion()
                    + cachedTokens * cachedPrice + outputTokens * console.getOutputTokenPricePerMillion())
                    / 1_000_000.0 / range.days();
        }
        Cost costs = new Cost(
                metrics.value("tokensPerDecision", decisions == 0 ? null : (promptTokens + outputTokens) / (double) decisions,
                        "TOKENS", ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.value("callsPerDecision", decisions == 0 ? null : calls / (double) decisions, "CALLS",
                        ZeroTrustConsoleMetrics.NO_DECISIONS),
                metrics.value("costPerDay", cost, "CURRENCY_PER_DAY", ZeroTrustConsoleMetrics.NO_PRICE),
                console.getPriceCurrency());
        List<RankedItem> failedPaths = ranked(range, tenant, "FAILED_PATH", null);
        List<HourPoint> hourly = new ArrayList<>();
        reader.hours(range, tenant).forEach((hour, hourCounts) -> hourly.add(new HourPoint(hour.toString(),
                hourCounts[0], hourCounts[1] < 0 ? null : hourCounts[1])));
        return new Operations(header(range, tenant, rows),
                components(range, tenant, rows, throughput, stages, planeAgent), throughput, hourly,
                coverage.noDecisionReasons(), failureTrend, failedPaths, latency, histogram, trend(range, tenant),
                costs, bundleModels(rows),
                new Storage(console.getDecisionRetentionDays(), console.getAggregateRetentionDays(), standalone));
    }

    /**
     * Console design 6.6: the path a decision takes and the state of each part. A part nothing records says so; a
     * state is GOOD, WARN, BAD or UNKNOWN.
     */
    List<Component> components(ZeroTrustConsoleRange range, String tenant, List<StatsRow> rows, Throughput throughput,
                               Map<String, LatencyRow> stages, SecurityPlaneAgent planeAgent) {
        List<Component> components = new ArrayList<>();
        Double perMinute = throughput.protectedPerMinute().value();
        components.add(new Component("PROTECTED_CALLS", perMinute == null ? "UNKNOWN" : "GOOD",
                perMinute == null ? null : String.valueOf(perMinute), throughput.protectedPerMinute().noDataReason()));
        if (planeAgent != null) {
            int inLine = planeAgent.analysesInProgress();
            int bound = planeAgent.analysisLineBound();
            String status = bound > 0 && bound < Integer.MAX_VALUE && inLine >= 0.8 * bound ? "WARN" : "GOOD";
            components.add(new Component("ANALYSIS_LINE", status,
                    inLine + "/" + (bound == Integer.MAX_VALUE ? "-" : String.valueOf(bound)), null));
        } else {
            components.add(new Component("ANALYSIS_LINE", "UNKNOWN", null, ZeroTrustConsoleMetrics.NOT_RECORDED));
        }
        components.add(new Component("PAST_RECORDS", "UNKNOWN", null, ZeroTrustConsoleMetrics.NOT_RECORDED));
        long decisions = decisions(rows);
        long modelLess = sum(rows, r -> r.decision() && "MODEL_LESS".equals(r.source()), StatsRow::decisions);
        long failed = sum(rows, r -> !r.decision(), StatsRow::decisions);
        double maxModelLess = properties.getConsole().getAdoption().getMaxModelLessRatio();
        String modelStatus = decisions + failed == 0 ? "UNKNOWN"
                : (double) (modelLess + failed) / (decisions + failed) > maxModelLess ? "WARN" : "GOOD";
        components.add(new Component("MODEL", modelStatus, String.valueOf(modelLess + failed), null));
        LatencyRow persist = stages.get("PERSIST");
        Long persistMs = persist == null ? null : ZeroTrustConsoleMetrics.percentile(persist.buckets(), 0.5);
        components.add(new Component("DECISION_STORE", persistMs == null ? "UNKNOWN" : "GOOD",
                persistMs == null ? null : String.valueOf(persistMs), persistMs == null
                ? ZeroTrustConsoleMetrics.NO_DECISIONS : null));
        components.add(new Component("STATE_STORE", standalone ? "WARN" : "GOOD", standalone ? "MEMORY" : "REDIS",
                null));
        Instant computed = reader.lastComputed();
        long interval = Math.max(60_000L, properties.getConsole().getAggregationIntervalMs());
        String aggregation = computed == null ? "UNKNOWN"
                : Duration.between(computed, clock.instant()).toMillis() > 5 * interval ? "WARN" : "GOOD";
        components.add(new Component("AGGREGATION", aggregation, computed == null ? null : computed.toString(),
                computed == null ? ZeroTrustConsoleMetrics.NOT_RECORDED : null));
        return components;
    }

    // ----- helpers -----

    private Map<String, LatencyRow> latency(ZeroTrustConsoleRange range, String tenant, String mode) {
        Map<String, LatencyRow> stages = new LinkedHashMap<>();
        reader.latency(range, tenant, mode).forEach(row -> stages.put(row.stage(), row));
        return stages;
    }

    private MetricValue userWait(ZeroTrustConsoleMetrics metrics, String key, LatencyRow wait, double p) {
        Long value = wait == null ? null : ZeroTrustConsoleMetrics.percentile(wait.buckets(), p);
        return metrics.value(key, value == null ? null : value.doubleValue(), "MILLISECONDS",
                ZeroTrustConsoleMetrics.NO_SYNCHRONOUS_DECISIONS);
    }

    static long decisions(List<StatsRow> rows) {
        return sum(rows, StatsRow::decision, StatsRow::decisions);
    }

    static long sum(List<StatsRow> rows, Predicate<StatsRow> filter, ToLongFunction<StatsRow> value) {
        long total = 0;
        for (StatsRow row : rows) {
            if (filter.test(row)) {
                total += value.applyAsLong(row);
            }
        }
        return total;
    }

    private static Map<String, Long> group(List<StatsRow> rows, Predicate<StatsRow> filter,
                                           Function<StatsRow, String> key) {
        Map<String, Long> groups = new LinkedHashMap<>();
        for (StatsRow row : rows) {
            if (filter.test(row)) {
                groups.merge(blankAsNone(key.apply(row)), row.decisions(), Long::sum);
            }
        }
        return groups;
    }

    /** The group a reason code belongs to in the output contract, or OTHER. */
    static String groupOf(String code) {
        return SecurityDecisionOutputContractV4.REASON_CODES.stream()
                .filter(reasonCode -> reasonCode.code().equals(code))
                .map(reasonCode -> reasonCode.group().name())
                .findFirst().orElse("OTHER");
    }

    private static String blankAsNone(String value) {
        return value == null || value.isBlank() ? "NONE" : value;
    }
}
