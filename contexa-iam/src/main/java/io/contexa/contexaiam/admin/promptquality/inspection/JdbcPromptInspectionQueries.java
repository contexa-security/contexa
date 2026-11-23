package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRun;
import io.contexa.contexacore.verification.inspection.SealIntegrityCheck;
import io.contexa.contexacore.verification.inspection.SourceTruthCheck;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * The inspection read model the console shows: the sealed packages of a capture period with their latest result. A
 * package without a result reads as {@link #NOT_INSPECTED}.
 */
public class JdbcPromptInspectionQueries {

    /** The result word of a sealed package that has no stored result yet. */
    public static final String NOT_INSPECTED = "NOT_INSPECTED";

    /**
     * The latest result of each package captured in the period (the two arguments every query on it starts with; the
     * screens look at a period, so the results of other packages are not computed again for each query, W3-20-A6), and
     * the finding lines of those results: the lines of each kind a result lists (W3-20), or a finding row each for a
     * result stored before W3-20.
     */
    private static final String LATEST = """
            with latest as (
                select distinct on (r.package_id) r.*
                  from ctxa_prompt_inspection_result r
                  join ctxa_sealed_evidence_package lp on lp.package_id = r.package_id
                 where lp.captured_at between ? and ?
                 order by r.package_id, r.inspected_at desc, r.id desc
            ),
            finding_lines as (
                select l.id as result_id, k.check_code, k.outcome, nullif(k.block_name, '') as block_name,
                       nullif(k.entry_name, '') as entry_name, (e ->> 'lines')::bigint as lines
                  from latest l
                  cross join lateral json_array_elements(l.finding_kinds_json::json) e
                  join ctxa_prompt_inspection_finding_kind k on k.id = (e ->> 'kind')::bigint
                 where l.finding_kinds_json is not null
                union all
                select f.result_id, f.check_code, f.outcome, f.block_name, f.entry_name, 1
                  from ctxa_prompt_inspection_finding f
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

    /** The request's facts are read from the sealed column, which the package hash covers: the jsonb copy is not. */
    public record PackageRow(String packageId, Instant capturedAt, String userId, String httpMethod, String requestPath,
                             String resourceId, String verdict, Integer mismatchCount, Integer unverifiableCount,
                             String inspectorVersion, Instant inspectedAt) {
    }

    public record PackagePage(long total, int page, int size, List<PackageRow> rows) {
    }

    public PackagePage packages(PackageFilter filter, int page, int size) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 200);
        List<Object> arguments = new ArrayList<>();
        String where = packageWhere(filter, arguments);
        Long total = jdbc.queryForObject(LATEST + """
                select count(*)
                  from ctxa_sealed_evidence_package p
                  left join latest l on l.package_id = p.package_id
                """ + where, Long.class, withPeriod(filter.from(), filter.to(), arguments));
        List<Object> pageArguments = new ArrayList<>(arguments);
        pageArguments.add(safeSize);
        pageArguments.add((long) safePage * safeSize);
        List<PackageRow> rows = jdbc.query(LATEST + """
                select p.package_id, p.captured_at, p.user_id,
                       contexa_safe_jsonb(p.request_facts_json) ->> 'httpMethod' as http_method,
                       contexa_safe_jsonb(p.request_facts_json) ->> 'requestPath' as request_path,
                       contexa_safe_jsonb(p.request_facts_json) ->> 'resourceId' as resource_id,
                       l.verdict, l.mismatch_count, l.unverifiable_count, l.inspector_version, l.inspected_at
                  from ctxa_sealed_evidence_package p
                  left join latest l on l.package_id = p.package_id
                """ + where + """
                 order by p.captured_at desc, p.id desc
                 limit ? offset ?
                """, (rs, rowNum) -> packageRow(rs), withPeriod(filter.from(), filter.to(), pageArguments));
        return new PackagePage(total == null ? 0L : total, safePage, safeSize, rows);
    }

    /** W7-14: the stage of an applied decision's seal and of a shadow run's seal (decisionAppliedStage, W6-9). */
    public static final String DECISION_STAGE = "DECISION";
    public static final String SHADOW_STAGE = "SHADOW";

    /**
     * W7-14: the sealed decisions of a capture period per bundle version, stage and action, with the verdicts of their
     * latest inspection result; the behaviour difference of the version comparison. The two stage words are
     * {@link #DECISION_STAGE} and {@link #SHADOW_STAGE}. The decision is read from the sealed column, which the package
     * hash covers: the jsonb copy beside it is outside the hash (Q-21).
     */
    private static final String BUNDLE_OUTCOMES = """
            with latest as (
                select distinct on (r.package_id) r.package_id, r.verdict
                  from ctxa_prompt_inspection_result r
                  join ctxa_sealed_evidence_package lp on lp.package_id = r.package_id
                 where lp.captured_at between ? and ?
                 order by r.package_id, r.inspected_at desc, r.id desc
            ),
            sealed as (
                select p.package_id,
                       coalesce(contexa_safe_jsonb(p.prompt_execution_metadata_json) ->> 'promptVersionName',
                                contexa_safe_jsonb(p.prompt_execution_metadata_json) #>> '{%s,promptBundleVersion}')
                           as bundle_version,
                       case when contexa_safe_jsonb(p.decision_json) ->> 'decisionAppliedStage' = 'SHADOW' then 'SHADOW'
                            else 'DECISION' end as stage,
                       coalesce(contexa_safe_jsonb(p.decision_json) ->> 'action', '') as action
                  from ctxa_sealed_evidence_package p
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
                       contexa_safe_jsonb(p.decision_json) ->> '%2$s' as original_request_id,
                       coalesce(contexa_safe_jsonb(p.prompt_execution_metadata_json) ->> 'promptVersionName',
                                contexa_safe_jsonb(p.prompt_execution_metadata_json) #>> '{%1$s,promptBundleVersion}')
                           as bundle_version,
                       coalesce(contexa_safe_jsonb(p.decision_json) ->> 'action', '') as action
                  from ctxa_sealed_evidence_package p
                 where p.captured_at between ? and ?
                   and contexa_safe_jsonb(p.decision_json) ->> 'decisionAppliedStage' = 'SHADOW'
            ),
            shadows as (
                select * from shadow_seals where bundle_version in (%3$s)
            ),
            decisions as (
                select distinct on (d.correlation_id) d.package_id, d.correlation_id,
                       coalesce(contexa_safe_jsonb(d.prompt_execution_metadata_json) ->> 'promptVersionName',
                                contexa_safe_jsonb(d.prompt_execution_metadata_json) #>> '{%1$s,promptBundleVersion}')
                           as bundle_version,
                       coalesce(contexa_safe_jsonb(d.decision_json) ->> 'action', '') as action
                  from ctxa_sealed_evidence_package d
                 where d.correlation_id in (select original_request_id from shadows)
                   and coalesce(contexa_safe_jsonb(d.decision_json) ->> 'decisionAppliedStage', '') <> 'SHADOW'
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

    // ----- the sealed evidence (quality plan 3.7, 3.8) -----

    /** The result of one check of the evidence audit on a sealed decision, by its latest inspection. */
    public static final String RESULT_OK = "OK";
    public static final String RESULT_MISMATCH = "MISMATCH";
    /** Not inspected yet, the inspection failed, or the check could not read what it checks. */
    public static final String RESULT_UNCHECKED = "UNCHECKED";

    /** The words of the audit result filter: any check mismatched, one of the three, any unchecked, all whole. */
    public static final List<String> EVIDENCE_RESULTS = List.of("PROBLEM", "INTEGRITY", "TRACE", "SOURCE", "UNCHECKED",
            "WHOLE");

    /** The actions of the decisions that stopped; the others allowed. */
    private static final String STOPPED = "('CHALLENGE', 'ESCALATE', 'BLOCK')";

    /**
     * The sealed decisions of a capture period, each with the action and the version of its decision (read from the
     * sealed columns the package hash covers) and the result of the three checks of the evidence audit by its latest
     * inspection: integrity (the seal), the trace of the version and the source records.
     */
    private static final String EVIDENCE = LATEST.stripTrailing() + """
            ,
            evidence as (
                select p.id, p.package_id, p.captured_at, p.user_id, l.id as result_id, l.verdict, l.mismatch_count,
                       l.unverifiable_count, l.inspector_version, l.inspected_at,
                       contexa_safe_jsonb(p.request_facts_json) ->> 'httpMethod' as http_method,
                       contexa_safe_jsonb(p.request_facts_json) ->> 'requestPath' as request_path,
                       coalesce(contexa_safe_jsonb(p.decision_json) ->> 'action', '') as action,
                       coalesce(contexa_safe_jsonb(p.prompt_execution_metadata_json) ->> 'promptVersionName',
                                contexa_safe_jsonb(p.prompt_execution_metadata_json) #>> '{%s,promptBundleVersion}')
                           as version,
                       %s as integrity, %s as trace, %s as source
                  from ctxa_sealed_evidence_package p
                  left join latest l on l.package_id = p.package_id
                 where p.captured_at between ? and ?
            )
            """.formatted(PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR, checkResult(SealIntegrityCheck.CODE),
            checkResult(BundleTraceCheck.CODE), checkResult(SourceTruthCheck.CODE));

    /**
     * The sealed evidence list's filter: the capture period (both ends included), the decision's action, its version,
     * the audit result ({@link #EVIDENCE_RESULTS}), the user, a part of the request path, a block and an entry (a
     * finding of the latest result in that block, with that entry, or both), and, as the sealed prompt list filtered,
     * the latest result's verdict or {@link #NOT_INSPECTED} and a check with a finding in it; a blank filter value does
     * not filter.
     */
    public record EvidenceFilter(Instant from, Instant to, String action, String version, String result, String user,
                                 String path, String block, String entry, String verdict, String checkCode) {
    }

    /**
     * A sealed decision as the list shows it; each check's result is OK, MISMATCH or UNCHECKED. As the sealed prompt
     * list showed them: the latest result's verdict ({@link #NOT_INSPECTED} without one), its mismatches and the items
     * it could not check (none without one), the inspector and when it inspected.
     */
    public record EvidenceRow(String packageId, Instant capturedAt, String userId, String httpMethod,
                              String requestPath, String action, String version, String integrity, String trace,
                              String source, String verdict, Integer mismatchCount, Integer unverifiableCount,
                              String inspectorVersion, Instant inspectedAt) {
    }

    /**
     * The sealed decisions of the period, whatever the filter: how many, how many stopped and allowed, and how many a
     * check of the audit found mismatched.
     */
    public record EvidenceTotals(long sealed, long stopped, long allowed, long integrity, long trace, long source) {
    }

    /** A page of the list, the totals of the period and the versions its decisions ran, for the filter. */
    public record EvidencePage(long total, int page, int size, List<EvidenceRow> rows, EvidenceTotals totals,
                               List<String> versions) {
    }

    /**
     * A page of the sealed decisions of the period that the filter keeps, newest first.
     *
     * @throws IllegalArgumentException when the audit result is none of {@link #EVIDENCE_RESULTS}
     */
    public EvidencePage evidence(EvidenceFilter filter, int page, int size) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 200);
        Object[] period = periodTwice(filter.from(), filter.to());
        List<Object> arguments = new ArrayList<>(List.of(period));
        String where = evidenceWhere(filter, arguments);
        Long total = jdbc.queryForObject(EVIDENCE + "select count(*) from evidence e" + where, Long.class,
                arguments.toArray());
        List<Object> pageArguments = new ArrayList<>(arguments);
        pageArguments.add(safeSize);
        pageArguments.add((long) safePage * safeSize);
        List<EvidenceRow> rows = jdbc.query(EVIDENCE + """
                select e.package_id, e.captured_at, e.user_id, e.http_method, e.request_path, e.action, e.version,
                       e.integrity, e.trace, e.source, e.verdict, e.mismatch_count, e.unverifiable_count,
                       e.inspector_version, e.inspected_at
                  from evidence e
                """ + where + """
                 order by e.captured_at desc, e.id desc
                 limit ? offset ?
                """, (rs, rowNum) -> evidenceRow(rs), pageArguments.toArray());
        EvidenceTotals totals = jdbc.queryForObject(EVIDENCE + """
                select count(*) as sealed,
                       count(*) filter (where e.action in %s) as stopped,
                       count(*) filter (where e.action = 'ALLOW') as allowed,
                       count(*) filter (where e.integrity = 'MISMATCH') as integrity,
                       count(*) filter (where e.trace = 'MISMATCH') as trace,
                       count(*) filter (where e.source = 'MISMATCH') as source
                  from evidence e
                """.formatted(STOPPED), (rs, rowNum) -> new EvidenceTotals(rs.getLong("sealed"),
                rs.getLong("stopped"), rs.getLong("allowed"), rs.getLong("integrity"), rs.getLong("trace"),
                rs.getLong("source")), period);
        List<String> versions = jdbc.queryForList(EVIDENCE + """
                select distinct e.version from evidence e where e.version is not null order by 1 limit 100
                """, String.class, period);
        return new EvidencePage(total == null ? 0L : total, safePage, safeSize, rows, totals, versions);
    }

    /** The result of one check by the latest inspection's findings of it; a failed inspection checked nothing. */
    private static String checkResult(String code) {
        String finding = "exists (select 1 from finding_lines f where f.result_id = l.id and f.check_code = '" + code
                + "' and f.outcome = '%s')";
        return "case when l.id is null or l.verdict = 'ERROR' then '" + RESULT_UNCHECKED + "'"
                + " when " + finding.formatted("MISMATCH") + " then '" + RESULT_MISMATCH + "'"
                + " when " + finding.formatted("UNVERIFIABLE") + " then '" + RESULT_UNCHECKED + "'"
                + " else '" + RESULT_OK + "' end";
    }

    /** The period of the latest results and the period of the sealed decisions, the same both times. */
    private static Object[] periodTwice(Instant from, Instant to) {
        return new Object[]{Timestamp.from(from), Timestamp.from(to), Timestamp.from(from), Timestamp.from(to)};
    }

    private static String evidenceWhere(EvidenceFilter filter, List<Object> arguments) {
        StringBuilder where = new StringBuilder(" where true");
        if (StringUtils.hasText(filter.action())) {
            where.append(" and e.action = ?");
            arguments.add(filter.action().trim().toUpperCase(Locale.ROOT));
        }
        if (StringUtils.hasText(filter.version())) {
            where.append(" and e.version = ?");
            arguments.add(filter.version().trim());
        }
        if (StringUtils.hasText(filter.result())) {
            where.append(switch (filter.result().trim().toUpperCase(Locale.ROOT)) {
                case "PROBLEM" -> " and 'MISMATCH' in (e.integrity, e.trace, e.source)";
                case "INTEGRITY" -> " and e.integrity = 'MISMATCH'";
                case "TRACE" -> " and e.trace = 'MISMATCH'";
                case "SOURCE" -> " and e.source = 'MISMATCH'";
                case "UNCHECKED" -> " and 'UNCHECKED' in (e.integrity, e.trace, e.source)";
                case "WHOLE" -> " and e.integrity = 'OK' and e.trace = 'OK' and e.source = 'OK'";
                default -> throw new IllegalArgumentException("Unknown audit result " + filter.result());
            });
        }
        if (StringUtils.hasText(filter.user())) {
            where.append(" and e.user_id = ?");
            arguments.add(filter.user().trim());
        }
        if (StringUtils.hasText(filter.path())) {
            // A part of the path, its wildcards taken as they are written.
            where.append(" and e.request_path ilike ? escape '\\'");
            arguments.add("%" + filter.path().trim().replace("\\", "\\\\")
                    .replace("%", "\\%").replace("_", "\\_") + "%");
        }
        if (StringUtils.hasText(filter.verdict())) {
            where.append(" and coalesce(e.verdict, ?) = ?");
            arguments.add(NOT_INSPECTED);
            arguments.add(filter.verdict().trim().toUpperCase(Locale.ROOT));
        }
        if (StringUtils.hasText(filter.checkCode())) {
            where.append(" and exists (select 1 from finding_lines f where f.result_id = e.result_id"
                    + " and f.check_code = ?)");
            arguments.add(filter.checkCode().trim());
        }
        if (StringUtils.hasText(filter.block()) || StringUtils.hasText(filter.entry())) {
            where.append(" and exists (select 1 from finding_lines f where f.result_id = e.result_id");
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

    private static EvidenceRow evidenceRow(ResultSet rs) throws SQLException {
        Timestamp inspectedAt = rs.getTimestamp("inspected_at");
        String verdict = rs.getString("verdict");
        return new EvidenceRow(rs.getString("package_id"), rs.getTimestamp("captured_at").toInstant(),
                rs.getString("user_id"), rs.getString("http_method"), rs.getString("request_path"),
                rs.getString("action"), rs.getString("version"), rs.getString("integrity"), rs.getString("trace"),
                rs.getString("source"), verdict != null ? verdict : NOT_INSPECTED,
                verdict != null ? rs.getInt("mismatch_count") : null,
                verdict != null ? rs.getInt("unverifiable_count") : null,
                rs.getString("inspector_version"), inspectedAt != null ? inspectedAt.toInstant() : null);
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
