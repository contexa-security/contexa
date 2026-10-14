package io.contexa.contexaiam.admin.promptquality.inspection;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionRecord;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionResultStore;
import io.contexa.contexacore.verification.inspection.PromptInspectionTrigger;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.support.TransactionOperations;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The inspection results in the {@code prompt_inspection_result} and {@code prompt_inspection_finding_kind} tables of
 * the OSS schema (W3-20, storage design A). A finding kind is the inspector version, check, outcome, block, entry and
 * reason; the packages that show it share one row that counts them and keeps its latest examples. A result row lists
 * its kinds with the lines each showed. A result is written in one transaction, in place of the package's earlier
 * result of the same inspector version, and a package keeps the results of its latest and previous inspector versions.
 * Results stored before W3-20 keep their findings in {@code prompt_inspection_finding} and read from there.
 */
public class JdbcPromptInspectionResultStore implements PromptInspectionResultStore {

    private static final TypeReference<List<CheckCount>> CHECK_COUNTS = new TypeReference<>() {
    };
    private static final TypeReference<List<KindLines>> KIND_LINES = new TypeReference<>() {
    };
    private static final TypeReference<List<String>> PACKAGE_IDS = new TypeReference<>() {
    };
    private static final String SELECT_RESULT = """
            select id, package_id, inspector_version, dictionary_version, layout_version, verdict, check_counts_json,
                   finding_kinds_json, inspection_trigger, inspected_at, error_reason
              from prompt_inspection_result
            """;
    private static final String KIND_KEY = "inspector_version = ? and check_code = ? and outcome = ? and block_name = ? "
            + "and entry_name = ? and reason = ?";
    /** The latest packages a kind keeps as its examples. */
    private static final int EXAMPLES = 5;

    /** The share of packages the automatic round samples: a stable hash of the package id, so a package left out stays out. */
    private static final String SAMPLE = "mod(abs(hashtext(p.package_id)::bigint), 100) < ?";

    /**
     * R4-S5: the packages captured before a time whose latest result found nothing wrong and that no official
     * verification run names, oldest capture first. The latest result is the one a package's console shows first.
     */
    private static final String CLEAN_PACKAGES = """
            select p.package_id
              from sealed_evidence_package p
             where p.captured_at < ?
               and (select latest.verdict
                      from prompt_inspection_result latest
                     where latest.package_id = p.package_id
                     order by latest.inspected_at desc, latest.id desc
                     limit 1) in ('PASS', 'NOT_APPLICABLE')
               and not exists (select 1 from official_verification_run_batch batch
                                where batch.package_id = p.package_id)
               and not exists (select 1 from verification_run_ledger ledger
                                where ledger.package_id = p.package_id)
             order by p.captured_at, p.id
             limit ?
            """;

    private final JdbcOperations jdbc;
    private final TransactionOperations transactions;
    private final ObjectMapper objectMapper;

    public JdbcPromptInspectionResultStore(JdbcOperations jdbc, TransactionOperations transactions,
                                           ObjectMapper objectMapper) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.transactions = Objects.requireNonNull(transactions, "transactions");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    public List<String> findUninspectedPackageIds(String inspectorVersion, int limit, int samplePercent) {
        boolean sampled = samplePercent < 100;
        String sql = """
                select p.package_id
                  from sealed_evidence_package p
                 where not exists (select 1 from prompt_inspection_result r
                                    where r.package_id = p.package_id and r.inspector_version = ?)
                """ + (sampled ? "   and " + SAMPLE + "\n" : "") + """
                 order by p.captured_at, p.id
                 limit ?
                """;
        Object[] arguments = sampled
                ? new Object[]{inspectorVersion, samplePercent, limit}
                : new Object[]{inspectorVersion, limit};
        return jdbc.queryForList(sql, String.class, arguments);
    }

    @Override
    public int removeResults(String inspectorVersion, Instant from, Instant to, int samplePercent) {
        boolean sampled = samplePercent < 100;
        String sql = """
                select r.id, r.finding_kinds_json
                  from prompt_inspection_result r
                  join sealed_evidence_package p on p.package_id = r.package_id
                 where r.inspector_version = ?
                   and p.captured_at between ? and ?
                """ + (sampled ? "   and " + SAMPLE + "\n" : "");
        Object[] arguments = sampled
                ? new Object[]{inspectorVersion, Timestamp.from(from), Timestamp.from(to), samplePercent}
                : new Object[]{inspectorVersion, Timestamp.from(from), Timestamp.from(to)};
        Integer removed = transactions.execute(status -> remove(jdbc.query(sql, this::listedKinds, arguments)));
        return removed == null ? 0 : removed;
    }

    @Override
    public int removeCleanPackagesCapturedBefore(Instant before, int limit) {
        if (limit < 1) {
            throw new IllegalArgumentException("limit must be at least 1");
        }
        Integer removed = transactions.execute(status -> {
            List<String> packageIds = jdbc.queryForList(CLEAN_PACKAGES, String.class, Timestamp.from(before), limit);
            if (packageIds.isEmpty()) {
                return 0;
            }
            String placeholders = String.join(", ", Collections.nCopies(packageIds.size(), "?"));
            Object[] arguments = packageIds.toArray();
            // The results go first so that their finding kinds lose them, as a period's removal does.
            remove(jdbc.query("select id, finding_kinds_json from prompt_inspection_result where package_id in ("
                    + placeholders + ")", this::listedKinds, arguments));
            return jdbc.update("delete from sealed_evidence_package where package_id in (" + placeholders + ")",
                    arguments);
        });
        return removed == null ? 0 : removed;
    }

    @Override
    public PromptInspectionResultStore.PeriodCount countPeriod(String inspectorVersion, Instant from, Instant to,
                                                               int samplePercent) {
        boolean sampled = samplePercent < 100;
        String sql = """
                select count(*),
                       count(*) filter (where not exists (select 1 from prompt_inspection_result r
                                                           where r.package_id = p.package_id
                                                             and r.inspector_version = ?))
                  from sealed_evidence_package p
                 where p.captured_at between ? and ?
                """ + (sampled ? "   and " + SAMPLE + "\n" : "");
        Object[] arguments = sampled
                ? new Object[]{inspectorVersion, Timestamp.from(from), Timestamp.from(to), samplePercent}
                : new Object[]{inspectorVersion, Timestamp.from(from), Timestamp.from(to)};
        return jdbc.queryForObject(sql, (row, number) -> new PromptInspectionResultStore.PeriodCount(row.getLong(1),
                row.getLong(2)), arguments);
    }

    @Override
    public void save(PromptInspectionResult result, PromptInspectionTrigger trigger, Instant inspectedAt) {
        String checkCounts = write(checkCounts(result));
        transactions.executeWithoutResult(status -> {
            remove(jdbc.query("select id, finding_kinds_json from prompt_inspection_result "
                    + "where package_id = ? and inspector_version = ?", this::listedKinds, result.packageId(),
                    result.inspectorVersion()));
            String kinds = write(kinds(result, inspectedAt));
            jdbc.update("""
                            insert into prompt_inspection_result (package_id, inspector_version, dictionary_version,
                                   layout_version, verdict, checked_count, mismatch_count, unverifiable_count,
                                   check_counts_json, finding_kinds_json, inspection_trigger, inspected_at,
                                   error_reason)
                            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    result.packageId(), result.inspectorVersion(), result.dictionaryVersion(), result.layoutVersion(),
                    result.verdict().name(),
                    result.matchedCount() + result.mismatchCount() + result.unverifiableCount(),
                    result.mismatchCount(), result.unverifiableCount(), checkCounts, kinds, trigger.name(),
                    Timestamp.from(inspectedAt), result.errorReason());
            // W3-20 (A5): a package keeps the results of its latest and previous inspector versions.
            remove(jdbc.query("""
                    select id, finding_kinds_json from prompt_inspection_result
                     where package_id = ?
                       and id not in (select id from prompt_inspection_result where package_id = ?
                                       order by inspected_at desc, id desc limit 2)
                    """, this::listedKinds, result.packageId(), result.packageId()));
        });
    }

    @Override
    public List<PromptInspectionRecord> findAll(String packageId) {
        return records(jdbc.query(SELECT_RESULT + " where package_id = ? order by inspected_at desc, id desc",
                this::storedResult, packageId));
    }

    /** The result's findings as kinds with their lines, each kind counted on its row (made when it is new). */
    private List<KindLines> kinds(PromptInspectionResult result, Instant inspectedAt) {
        Map<List<String>, List<PromptInspectionFinding>> byKind = new LinkedHashMap<>();
        for (PromptInspectionFinding finding : result.findings()) {
            byKind.computeIfAbsent(List.of(result.inspectorVersion(), finding.checkCode(), finding.outcome().name(),
                    text(finding.block()), text(finding.entry()), text(finding.reason())), key -> new ArrayList<>())
                    .add(finding);
        }
        List<KindLines> kinds = new ArrayList<>();
        for (Map.Entry<List<String>, List<PromptInspectionFinding>> kind : byKind.entrySet()) {
            kinds.add(new KindLines(count(kind.getKey(), kind.getValue(), result.packageId(), inspectedAt),
                    kind.getValue().size()));
        }
        return kinds;
    }

    /** Counts a package's lines of one kind on the kind's row; a new kind keeps its first finding's values. */
    private long count(List<String> key, List<PromptInspectionFinding> findings, String packageId, Instant at) {
        PromptInspectionFinding first = findings.get(0);
        Timestamp seen = Timestamp.from(at);
        jdbc.update("""
                insert into prompt_inspection_finding_kind (inspector_version, check_code, outcome, block_name,
                       entry_name, reason, first_package_id, first_seen_at, last_package_id, last_seen_at,
                       package_count, line_count, example_package_ids, example_expected, example_actual,
                       example_source_ref)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, '[]', ?, ?, ?)
                on conflict on constraint uq_prompt_inspection_finding_kind do nothing
                """, key.get(0), key.get(1), key.get(2), key.get(3), key.get(4), key.get(5), packageId, seen, packageId,
                seen, first.expected(), first.actual(), first.sourceRef());
        Map<String, Object> row = jdbc.queryForMap("select id, example_package_ids from prompt_inspection_finding_kind "
                + "where " + KIND_KEY + " for update", key.toArray());
        long id = ((Number) row.get("id")).longValue();
        List<String> examples = new ArrayList<>(read((String) row.get("example_package_ids"), PACKAGE_IDS));
        examples.remove(packageId);
        examples.add(packageId);
        jdbc.update("""
                update prompt_inspection_finding_kind
                   set last_package_id = ?, last_seen_at = ?, package_count = package_count + 1,
                       line_count = line_count + ?, example_package_ids = ?
                 where id = ?
                """, packageId, seen, findings.size(),
                write(examples.subList(Math.max(0, examples.size() - EXAMPLES), examples.size())), id);
        return id;
    }

    /** Removes result rows and takes their lines off the kinds they list; a kind no result shows any more goes too. */
    private int remove(List<ListedKinds> results) {
        if (results.isEmpty()) {
            return 0;
        }
        for (ListedKinds result : results) {
            for (KindLines kind : result.kinds()) {
                jdbc.update("update prompt_inspection_finding_kind set package_count = package_count - 1, "
                        + "line_count = line_count - ? where id = ?", kind.lines(), kind.kind());
            }
            jdbc.update("delete from prompt_inspection_result where id = ?", result.id());
        }
        jdbc.update("delete from prompt_inspection_finding_kind where package_count <= 0");
        return results.size();
    }

    /** The stored results with their findings, kept in the results' order. */
    private List<PromptInspectionRecord> records(List<StoredResult> stored) {
        if (stored.isEmpty()) {
            return List.of();
        }
        Map<Long, List<PromptInspectionFinding>> findings = new LinkedHashMap<>();
        List<Long> earlier = stored.stream().filter(result -> result.kinds() == null).map(StoredResult::id).toList();
        if (!earlier.isEmpty()) {
            // Results stored before W3-20 keep a row for each finding.
            String placeholders = String.join(", ", Collections.nCopies(earlier.size(), "?"));
            jdbc.query("select result_id, check_code, outcome, block_name, entry_name, fact_id, line_number, "
                    + "expected_value, actual_value, source_ref, reason from prompt_inspection_finding "
                    + "where result_id in (" + placeholders + ") order by id", rs -> {
                findings.computeIfAbsent(rs.getLong("result_id"), id -> new ArrayList<>()).add(finding(rs));
            }, earlier.toArray());
        }
        Map<Long, PromptInspectionFinding> kinds = kindFindings(stored.stream()
                .filter(result -> result.kinds() != null)
                .flatMap(result -> result.kinds().stream()).map(KindLines::kind).distinct().toList());
        for (StoredResult result : stored) {
            if (result.kinds() == null) {
                continue;
            }
            List<PromptInspectionFinding> listed = findings.computeIfAbsent(result.id(), id -> new ArrayList<>());
            for (KindLines kind : result.kinds()) {
                PromptInspectionFinding finding = kinds.get(kind.kind());
                if (finding != null) {
                    listed.addAll(Collections.nCopies(kind.lines(), finding));
                }
            }
        }
        return stored.stream()
                .map(result -> new PromptInspectionRecord(result.id(),
                        result.with(findings.getOrDefault(result.id(), List.of())), result.trigger(),
                        result.inspectedAt()))
                .toList();
    }

    /** Each kind as a finding without a line or values of its own (those were of one package only). */
    private Map<Long, PromptInspectionFinding> kindFindings(List<Long> ids) {
        Map<Long, PromptInspectionFinding> kinds = new LinkedHashMap<>();
        if (ids.isEmpty()) {
            return kinds;
        }
        String placeholders = String.join(", ", Collections.nCopies(ids.size(), "?"));
        jdbc.query("select id, check_code, outcome, block_name, entry_name, reason, example_source_ref "
                + "from prompt_inspection_finding_kind where id in (" + placeholders + ")", rs -> {
            kinds.put(rs.getLong("id"), PromptInspectionFinding.builder(rs.getString("check_code"),
                            PromptInspectionOutcome.valueOf(rs.getString("outcome")))
                    .block(blank(rs.getString("block_name")))
                    .entry(blank(rs.getString("entry_name")))
                    .sourceRef(rs.getString("example_source_ref"))
                    .reason(blank(rs.getString("reason")))
                    .build());
        }, ids.toArray());
        return kinds;
    }

    private List<CheckCount> checkCounts(PromptInspectionResult result) {
        return result.checks().stream()
                .map(check -> new CheckCount(check.checkCode(), check.matched(), check.mismatched(),
                        check.unverifiable()))
                .toList();
    }

    private ListedKinds listedKinds(ResultSet rs, int rowNum) throws SQLException {
        String kinds = rs.getString("finding_kinds_json");
        return new ListedKinds(rs.getLong("id"), kinds == null ? List.of() : read(kinds, KIND_LINES));
    }

    private StoredResult storedResult(ResultSet rs, int rowNum) throws SQLException {
        String kinds = rs.getString("finding_kinds_json");
        return new StoredResult(rs.getLong("id"), rs.getString("package_id"), rs.getString("inspector_version"),
                rs.getString("dictionary_version"), rs.getString("layout_version"),
                PromptInspectionVerdict.valueOf(rs.getString("verdict")),
                read(rs.getString("check_counts_json"), CHECK_COUNTS), kinds == null ? null : read(kinds, KIND_LINES),
                PromptInspectionTrigger.valueOf(rs.getString("inspection_trigger")),
                rs.getTimestamp("inspected_at").toInstant(), rs.getString("error_reason"));
    }

    private static PromptInspectionFinding finding(ResultSet rs) throws SQLException {
        return PromptInspectionFinding.builder(rs.getString("check_code"),
                        PromptInspectionOutcome.valueOf(rs.getString("outcome")))
                .block(rs.getString("block_name"))
                .entry(rs.getString("entry_name"))
                .factId(rs.getString("fact_id"))
                .lineNumber(rs.getObject("line_number", Integer.class))
                .expected(rs.getString("expected_value"))
                .actual(rs.getString("actual_value"))
                .sourceRef(rs.getString("source_ref"))
                .reason(rs.getString("reason"))
                .build();
    }

    private String write(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        }
        catch (JsonProcessingException exception) {
            throw new IllegalStateException("An inspection result could not be written", exception);
        }
    }

    private <T> T read(String json, TypeReference<T> type) {
        try {
            return objectMapper.readValue(json, type);
        }
        catch (JsonProcessingException exception) {
            throw new IllegalStateException("A stored inspection result does not read", exception);
        }
    }

    /** The key part of a kind: a finding without a block, entry or reason keeps an empty one. */
    private static String text(String value) {
        return value == null ? "" : value;
    }

    private static String blank(String value) {
        return value == null || value.isEmpty() ? null : value;
    }

    /** A check's counts as the result keeps them. */
    private record CheckCount(String checkCode, int matched, int mismatched, int unverifiable) {
    }

    /** A kind a result row lists, with the lines of it the package showed. */
    private record KindLines(long kind, int lines) {
    }

    private record ListedKinds(long id, List<KindLines> kinds) {
    }

    private record StoredResult(long id, String packageId, String inspectorVersion, String dictionaryVersion,
                                String layoutVersion, PromptInspectionVerdict verdict, List<CheckCount> counts,
                                List<KindLines> kinds, PromptInspectionTrigger trigger, Instant inspectedAt,
                                String errorReason) {

        /** The result with each check's findings in the order they were stored. */
        private PromptInspectionResult with(List<PromptInspectionFinding> findings) {
            Map<String, List<PromptInspectionFinding>> byCheck = new LinkedHashMap<>();
            for (PromptInspectionFinding finding : findings) {
                byCheck.computeIfAbsent(finding.checkCode(), code -> new ArrayList<>()).add(finding);
            }
            List<PromptInspectionCheckResult> checks = counts.stream()
                    .map(count -> new PromptInspectionCheckResult(count.checkCode(), count.matched(),
                            count.mismatched(), count.unverifiable(), byCheck.getOrDefault(count.checkCode(),
                            List.of())))
                    .toList();
            return new PromptInspectionResult(packageId, inspectorVersion, dictionaryVersion, layoutVersion, verdict,
                    checks, errorReason);
        }
    }
}
