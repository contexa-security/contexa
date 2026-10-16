package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRun;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The inspection read model the console shows: the sealed packages of a capture period with their latest result,
 * and the overview counts of those latest results. A package without a result reads as
 * {@link #NOT_INSPECTED}.
 */
public class JdbcPromptInspectionQueries {

    /** The result word of a sealed package that has no stored result yet. */
    public static final String NOT_INSPECTED = "NOT_INSPECTED";

    private static final int RANKING_LIMIT = 10;
    /**
     * The latest result of each package captured in the period (the two arguments every query on it starts with; the
     * screens look at a period, so the results of other packages are not computed again for each query, W3-20-A6), and
     * the finding lines of those results: the lines of each kind a result lists (W3-20), or a finding row each for a
     * result stored before W3-20.
     */
    private static final String LATEST = """
            with latest as (
                select distinct on (r.package_id) r.*
                  from prompt_inspection_result r
                  join sealed_evidence_package lp on lp.package_id = r.package_id
                 where lp.captured_at between ? and ?
                 order by r.package_id, r.inspected_at desc, r.id desc
            ),
            finding_lines as (
                select l.id as result_id, k.check_code, k.outcome, nullif(k.block_name, '') as block_name,
                       nullif(k.entry_name, '') as entry_name, (e ->> 'lines')::bigint as lines
                  from latest l
                  cross join lateral json_array_elements(l.finding_kinds_json::json) e
                  join prompt_inspection_finding_kind k on k.id = (e ->> 'kind')::bigint
                 where l.finding_kinds_json is not null
                union all
                select f.result_id, f.check_code, f.outcome, f.block_name, f.entry_name, 1
                  from prompt_inspection_finding f
                  join latest l on l.id = f.result_id
                 where l.finding_kinds_json is null
            )
            """;

    private final JdbcOperations jdbc;

    public JdbcPromptInspectionQueries(JdbcOperations jdbc) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
    }

    /**
     * The package list's filter: the capture period (both ends included), the latest result's verdict or
     * {@link #NOT_INSPECTED}, a check code, a block and an entry (a finding of the latest result in that block, with
     * that entry, or both); a blank filter value does not filter.
     */
    public record PackageFilter(Instant from, Instant to, String verdict, String checkCode, String block, String entry) {
    }

    public record PackageRow(String packageId, Instant capturedAt, String userId, String httpMethod, String requestPath,
                             String resourceId, String verdict, Integer mismatchCount, Integer unverifiableCount,
                             String inspectorVersion, Instant inspectedAt) {
    }

    public record PackagePage(long total, int page, int size, List<PackageRow> rows) {
    }

    public record CheckCount(String checkCode, long mismatch, long unverifiable) {
    }

    public record DayCount(LocalDate day, String checkCode, long mismatch, long unverifiable) {
    }

    public record EntryCount(String block, String entry, long mismatch, long unverifiable) {
    }

    public record ResourceCount(String resourceId, long packages, long mismatch) {
    }

    public record VersionCount(String bundleVersion, String dictionaryVersion, String inspectorVersion, long packages,
                               long failed, long incomplete, long passed, long notApplicable, long errors) {
    }

    /**
     * The latest results of the packages captured in a period: packages by verdict, findings by check, by capture day
     * (UTC) and by entry, packages and mismatches by protected resource, and results by bundle, dictionary and
     * inspector version.
     */
    public record Overview(Instant from, Instant to, Map<String, Long> verdicts, List<CheckCount> checks,
                           List<DayCount> trend, List<EntryCount> entries, List<ResourceCount> resources,
                           List<VersionCount> versions) {
    }

    public PackagePage packages(PackageFilter filter, int page, int size) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 200);
        List<Object> arguments = new ArrayList<>();
        String where = packageWhere(filter, arguments);
        Long total = jdbc.queryForObject(LATEST + """
                select count(*)
                  from sealed_evidence_package p
                  left join latest l on l.package_id = p.package_id
                """ + where, Long.class, withPeriod(filter.from(), filter.to(), arguments));
        List<Object> pageArguments = new ArrayList<>(arguments);
        pageArguments.add(safeSize);
        pageArguments.add((long) safePage * safeSize);
        List<PackageRow> rows = jdbc.query(LATEST + """
                select p.package_id, p.captured_at, p.user_id,
                       p.request_facts_jsonb ->> 'httpMethod' as http_method,
                       p.request_facts_jsonb ->> 'requestPath' as request_path,
                       p.request_facts_jsonb ->> 'resourceId' as resource_id,
                       l.verdict, l.mismatch_count, l.unverifiable_count, l.inspector_version, l.inspected_at
                  from sealed_evidence_package p
                  left join latest l on l.package_id = p.package_id
                """ + where + """
                 order by p.captured_at desc, p.id desc
                 limit ? offset ?
                """, (rs, rowNum) -> packageRow(rs), withPeriod(filter.from(), filter.to(), pageArguments));
        return new PackagePage(total == null ? 0L : total, safePage, safeSize, rows);
    }

    public Overview overview(Instant from, Instant to) {
        Object[] period = withPeriod(from, to, List.of(Timestamp.from(from), Timestamp.from(to)));
        Map<String, Long> verdicts = new LinkedHashMap<>();
        jdbc.query(LATEST + """
                select coalesce(l.verdict, ?) as verdict, count(*) as packages
                  from sealed_evidence_package p
                  left join latest l on l.package_id = p.package_id
                 where p.captured_at between ? and ?
                 group by 1
                 order by 1
                """, rs -> {
            verdicts.put(rs.getString("verdict"), rs.getLong("packages"));
        }, withPeriod(from, to, List.of(NOT_INSPECTED, Timestamp.from(from), Timestamp.from(to))));
        String findings = """
                  from sealed_evidence_package p
                  join latest l on l.package_id = p.package_id
                  join finding_lines f on f.result_id = l.id
                 where p.captured_at between ? and ?
                """;
        String counts = "sum(case when f.outcome = 'MISMATCH' then f.lines else 0 end) as mismatch, "
                + "sum(case when f.outcome = 'UNVERIFIABLE' then f.lines else 0 end) as unverifiable";
        List<CheckCount> checks = jdbc.query(LATEST + "select f.check_code, " + counts + findings
                        + " group by f.check_code order by f.check_code",
                (rs, rowNum) -> new CheckCount(rs.getString("check_code"), rs.getLong("mismatch"),
                        rs.getLong("unverifiable")), period);
        List<DayCount> trend = jdbc.query(LATEST + "select (p.captured_at at time zone 'UTC')::date as day, "
                        + "f.check_code, " + counts + findings + " group by 1, 2 order by 1, 2",
                (rs, rowNum) -> new DayCount(rs.getObject("day", LocalDate.class), rs.getString("check_code"),
                        rs.getLong("mismatch"), rs.getLong("unverifiable")), period);
        List<EntryCount> entries = jdbc.query(LATEST + "select f.block_name, f.entry_name, " + counts + findings
                        + " and f.entry_name is not null group by 1, 2 order by mismatch desc, unverifiable desc, "
                        + "f.block_name, f.entry_name limit " + RANKING_LIMIT,
                (rs, rowNum) -> new EntryCount(rs.getString("block_name"), rs.getString("entry_name"),
                        rs.getLong("mismatch"), rs.getLong("unverifiable")), period);
        List<ResourceCount> resources = jdbc.query(LATEST + """
                select p.request_facts_jsonb ->> 'resourceId' as resource_id,
                       count(distinct p.package_id) as packages,
                       coalesce(sum(f.lines) filter (where f.outcome = 'MISMATCH'), 0) as mismatch
                  from sealed_evidence_package p
                  left join latest l on l.package_id = p.package_id
                  left join finding_lines f on f.result_id = l.id
                 where p.captured_at between ? and ?
                   and p.request_facts_jsonb ->> 'resourceId' is not null
                 group by 1
                 order by mismatch desc, packages desc, 1
                 limit\s""" + RANKING_LIMIT,
                (rs, rowNum) -> new ResourceCount(rs.getString("resource_id"), rs.getLong("packages"),
                        rs.getLong("mismatch")), period);
        List<VersionCount> versions = jdbc.query(LATEST + """
                select contexa_safe_jsonb(p.prompt_execution_metadata_json)
                           #>> '{%s,promptBundleVersion}' as bundle_version,
                       l.dictionary_version, l.inspector_version,
                       count(*) as packages,
                       count(*) filter (where l.verdict = 'FAIL') as failed,
                       count(*) filter (where l.verdict = 'INCOMPLETE') as incomplete,
                       count(*) filter (where l.verdict = 'PASS') as passed,
                       count(*) filter (where l.verdict = 'NOT_APPLICABLE') as not_applicable,
                       count(*) filter (where l.verdict = 'ERROR') as errors
                  from sealed_evidence_package p
                  join latest l on l.package_id = p.package_id
                 where p.captured_at between ? and ?
                 group by 1, 2, 3
                 order by 1 desc nulls last, 2, 3
                """.formatted(PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR), (rs, rowNum) -> new VersionCount(rs.getString("bundle_version"),
                rs.getString("dictionary_version"), rs.getString("inspector_version"), rs.getLong("packages"),
                rs.getLong("failed"), rs.getLong("incomplete"), rs.getLong("passed"), rs.getLong("not_applicable"),
                rs.getLong("errors")), period);
        return new Overview(from, to, verdicts, checks, trend, entries, resources, versions);
    }

    /** W7-14: the stage of an applied decision's seal and of a shadow run's seal (decisionAppliedStage, W6-9). */
    public static final String DECISION_STAGE = "DECISION";
    public static final String SHADOW_STAGE = "SHADOW";

    /**
     * W7-14: the sealed decisions of a capture period per bundle version, stage and action, with the verdicts of their
     * latest inspection result; the behaviour difference of the version comparison. The two stage words are
     * {@link #DECISION_STAGE} and {@link #SHADOW_STAGE}.
     */
    private static final String BUNDLE_OUTCOMES = """
            with latest as (
                select distinct on (r.package_id) r.package_id, r.verdict
                  from prompt_inspection_result r
                  join sealed_evidence_package lp on lp.package_id = r.package_id
                 where lp.captured_at between ? and ?
                 order by r.package_id, r.inspected_at desc, r.id desc
            ),
            sealed as (
                select p.package_id,
                       contexa_safe_jsonb(p.prompt_execution_metadata_json) #>> '{%s,promptBundleVersion}'
                           as bundle_version,
                       case when p.decision_jsonb ->> 'decisionAppliedStage' = 'SHADOW' then 'SHADOW'
                            else 'DECISION' end as stage,
                       coalesce(p.decision_jsonb ->> 'action', '') as action
                  from sealed_evidence_package p
                 where p.captured_at between ? and ?
            )
            select s.bundle_version, s.stage, s.action, count(*) as packages,
                   count(*) filter (where l.verdict = 'FAIL') as failed,
                   count(*) filter (where l.verdict = 'PASS') as passed,
                   count(*) filter (where l.verdict is null) as not_inspected
              from sealed s
              left join latest l on l.package_id = s.package_id
             where s.bundle_version in (%s)
             group by 1, 2, 3
             order by 1, 2, 3
            """;

    /** W7-14: how the sealed decisions of one bundle came out at one stage with one action. */
    public record BundleOutcome(String bundleVersion, String stage, String action, long packages, long failed,
                                long passed, long notInspected) {
    }

    public List<BundleOutcome> bundleOutcomes(Instant from, Instant to, List<String> bundleVersions) {
        List<String> versions = bundleVersions.stream().filter(StringUtils::hasText).distinct().toList();
        if (versions.isEmpty()) {
            return List.of();
        }
        List<Object> arguments = new ArrayList<>(List.of(Timestamp.from(from), Timestamp.from(to),
                Timestamp.from(from), Timestamp.from(to)));
        arguments.addAll(versions);
        String sql = BUNDLE_OUTCOMES.formatted(PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR,
                String.join(", ", Collections.nCopies(versions.size(), "?")));
        return jdbc.query(sql, (rs, rowNum) -> new BundleOutcome(rs.getString("bundle_version"), rs.getString("stage"),
                rs.getString("action"), rs.getLong("packages"), rs.getLong("failed"), rs.getLong("passed"),
                rs.getLong("not_inspected")), arguments.toArray());
    }

    /**
     * N-SHD-1: one shadow run with the sealed decision of the request it was copied from: the request (the decision's
     * correlation id), when the shadow was sealed, the shadow seal, bundle and action, and the decision seal, bundle and
     * action (none when the decision was not sealed, or the shadow seal names no request).
     */
    public record ShadowPair(String requestId, Instant capturedAt, String shadowPackageId, String shadowBundleVersion,
                             String shadowAction, String decisionPackageId, String decisionBundleVersion,
                             String decisionAction) {
    }

    /** N-SHD-1: the shadow seals of a period and bundles, each with the latest decision seal of its request. */
    private static final String SHADOW_PAIRS = """
            with shadow_seals as (
                select p.package_id, p.captured_at,
                       p.decision_jsonb ->> '%2$s' as original_request_id,
                       contexa_safe_jsonb(p.prompt_execution_metadata_json) #>> '{%1$s,promptBundleVersion}'
                           as bundle_version,
                       coalesce(p.decision_jsonb ->> 'action', '') as action
                  from sealed_evidence_package p
                 where p.captured_at between ? and ?
                   and p.decision_jsonb ->> 'decisionAppliedStage' = 'SHADOW'
            ),
            shadows as (
                select * from shadow_seals where bundle_version in (%3$s)
            ),
            decisions as (
                select distinct on (d.correlation_id) d.package_id, d.correlation_id,
                       contexa_safe_jsonb(d.prompt_execution_metadata_json) #>> '{%1$s,promptBundleVersion}'
                           as bundle_version,
                       coalesce(d.decision_jsonb ->> 'action', '') as action
                  from sealed_evidence_package d
                 where d.correlation_id in (select original_request_id from shadows)
                   and coalesce(d.decision_jsonb ->> 'decisionAppliedStage', '') <> 'SHADOW'
                 order by d.correlation_id, d.captured_at desc, d.id desc
            )
            select s.original_request_id, s.captured_at, s.package_id as shadow_package_id,
                   s.bundle_version as shadow_bundle_version, s.action as shadow_action,
                   d.package_id as decision_package_id, d.bundle_version as decision_bundle_version,
                   d.action as decision_action
              from shadows s
              left join decisions d on d.correlation_id = s.original_request_id
             order by s.captured_at desc, s.package_id
            """;

    public List<ShadowPair> shadowPairs(Instant from, Instant to, List<String> bundleVersions) {
        List<String> versions = bundleVersions.stream().filter(StringUtils::hasText).distinct().toList();
        if (versions.isEmpty()) {
            return List.of();
        }
        List<Object> arguments = new ArrayList<>(List.of(Timestamp.from(from), Timestamp.from(to)));
        arguments.addAll(versions);
        String sql = SHADOW_PAIRS.formatted(PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR,
                PromptShadowRun.ORIGINAL_REQUEST_ID, String.join(", ", Collections.nCopies(versions.size(), "?")));
        return jdbc.query(sql, (rs, rowNum) -> new ShadowPair(rs.getString("original_request_id"),
                rs.getTimestamp("captured_at").toInstant(), rs.getString("shadow_package_id"),
                rs.getString("shadow_bundle_version"), rs.getString("shadow_action"),
                rs.getString("decision_package_id"), rs.getString("decision_bundle_version"),
                rs.getString("decision_action")), arguments.toArray());
    }

    /** The arguments of a query on the latest results: the period of the latest results, then the query's own. */
    private static Object[] withPeriod(Instant from, Instant to, List<Object> arguments) {
        List<Object> all = new ArrayList<>(List.of(Timestamp.from(from), Timestamp.from(to)));
        all.addAll(arguments);
        return all.toArray();
    }

    private static String packageWhere(PackageFilter filter, List<Object> arguments) {
        StringBuilder where = new StringBuilder(" where p.captured_at between ? and ?");
        arguments.add(Timestamp.from(filter.from()));
        arguments.add(Timestamp.from(filter.to()));
        if (StringUtils.hasText(filter.verdict())) {
            where.append(" and coalesce(l.verdict, ?) = ?");
            arguments.add(NOT_INSPECTED);
            arguments.add(filter.verdict().trim());
        }
        if (StringUtils.hasText(filter.checkCode())) {
            where.append(" and exists (select 1 from finding_lines f where f.result_id = l.id"
                    + " and f.check_code = ?)");
            arguments.add(filter.checkCode().trim());
        }
        if (StringUtils.hasText(filter.block()) || StringUtils.hasText(filter.entry())) {
            where.append(" and exists (select 1 from finding_lines f where f.result_id = l.id");
            if (StringUtils.hasText(filter.block())) {
                where.append(" and f.block_name = ?");
                arguments.add(filter.block().trim());
            }
            if (StringUtils.hasText(filter.entry())) {
                where.append(" and f.entry_name = ?");
                arguments.add(filter.entry().trim());
            }
            where.append(")");
        }
        return where + "\n";
    }

    private static PackageRow packageRow(ResultSet rs) throws SQLException {
        Timestamp inspectedAt = rs.getTimestamp("inspected_at");
        String verdict = rs.getString("verdict");
        return new PackageRow(rs.getString("package_id"), rs.getTimestamp("captured_at").toInstant(),
                rs.getString("user_id"), rs.getString("http_method"), rs.getString("request_path"),
                rs.getString("resource_id"), verdict != null ? verdict : NOT_INSPECTED,
                verdict != null ? rs.getInt("mismatch_count") : null,
                verdict != null ? rs.getInt("unverifiable_count") : null,
                rs.getString("inspector_version"), inspectedAt != null ? inspectedAt.toInstant() : null);
    }
}
