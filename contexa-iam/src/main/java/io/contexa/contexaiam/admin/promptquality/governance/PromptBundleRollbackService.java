package io.contexa.contexaiam.admin.promptquality.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * W6-10 (P6-CHANGE-7, version management design 9.3-6): the rollback of a prompt bundle, run by one operator. The
 * active bundle of a scope is switched at once to a rollback target its manifest declares, when the target is in this
 * build, its manifest reads the vocabulary the stored data is in, and the target's policy set is there (a host without
 * policy sets records that the condition does not apply). The source becomes DEPRECATED, the target ACTIVE, the
 * runtime caches are told and the execution is recorded with its conditions. An emergency stop runs the same way and
 * waits for a second operator's approval. A refused rollback is recorded with its reasons and changes nothing.
 */
public class PromptBundleRollbackService {

    private static final Logger log = LoggerFactory.getLogger(PromptBundleRollbackService.class);

    public static final String EXECUTED = "EXECUTED";
    public static final String AWAITING_APPROVAL = "AWAITING_APPROVAL";
    public static final String APPROVED = "APPROVED";
    public static final String REFUSED = "REFUSED";
    public static final String NOT_APPLICABLE = "NOT_APPLICABLE";
    /** W7-14: how many executions of a bundle the version screen lists. */
    private static final int EXECUTION_LIMIT = 20;

    private final JdbcTemplate jdbc;
    private final PromptBundleCatalog catalog;
    private final PromptGovernanceRuntimeCacheInvalidationService invalidation;
    private final PromptPolicySetLookup policySets;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public PromptBundleRollbackService(JdbcTemplate jdbc, PromptBundleCatalog catalog,
                                       PromptGovernanceRuntimeCacheInvalidationService invalidation,
                                       PromptPolicySetLookup policySets, ObjectMapper objectMapper, Clock clock) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.catalog = Objects.requireNonNull(catalog, "catalog");
        this.invalidation = Objects.requireNonNull(invalidation, "invalidation");
        this.policySets = policySets;
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** What the operator asks: the scope's active bundle, the target to switch to, why, and whether it is an emergency. */
    public record Request(String registryScope, String promptKey, String fromVersion, String toVersion, String reason,
                          boolean emergency) {
    }

    /** The conditions the rollback was checked against. */
    public record Conditions(boolean sourceExecuting, boolean targetInBuild, boolean targetDeclared,
                             boolean vocabularyCompatible, boolean targetRegistered, String policySet) {
    }

    /** The recorded execution: its key, its status, the conditions and why it was refused. */
    public record Result(String executionKey, String status, Conditions conditions, List<String> refusals) {
    }

    public Result rollback(Request request, String actor) {
        Objects.requireNonNull(request, "request");
        String scope = request.registryScope();
        String key = request.promptKey();
        PromptBundleManifest source = catalog.find(key, request.fromVersion()).orElse(null);
        PromptBundleManifest target = catalog.find(key, request.toVersion()).orElse(null);
        String sourceStatus = registryStatus(scope, key, request.fromVersion());
        boolean sourceExecuting = sourceStatus != null && (PromptBundleState.is(sourceStatus, PromptBundleState.ACTIVE)
                || PromptBundleState.is(sourceStatus, PromptBundleState.CANARY));
        String policySet = policySets == null ? NOT_APPLICABLE
                : policySets.policySetExists(scope, key, request.toVersion()) ? "PRESENT" : "MISSING";
        Conditions conditions = new Conditions(sourceExecuting, target != null,
                source != null && source.rollbackTargets().contains(request.toVersion()),
                target != null && target.compatibleVocabularyVersions().contains(VocabularyVersion.CURRENT),
                registryStatus(scope, key, request.toVersion()) != null, policySet);
        List<String> refusals = new ArrayList<>();
        if (!conditions.sourceExecuting()) {
            refusals.add("SOURCE_NOT_EXECUTING");
        }
        if (!conditions.targetInBuild()) {
            refusals.add("TARGET_NOT_IN_BUILD");
        }
        if (!conditions.targetDeclared()) {
            refusals.add("TARGET_NOT_DECLARED");
        }
        if (!conditions.vocabularyCompatible()) {
            refusals.add("VOCABULARY_INCOMPATIBLE");
        }
        if (!conditions.targetRegistered()) {
            refusals.add("TARGET_NOT_REGISTERED");
        }
        if ("MISSING".equals(policySet)) {
            refusals.add("POLICY_SET_MISSING");
        }
        String executionKey = "RBX-" + UUID.randomUUID();
        Timestamp now = Timestamp.from(clock.instant());
        if (!refusals.isEmpty()) {
            record(executionKey, request, actor, REFUSED, conditions, refusals, now);
            return new Result(executionKey, REFUSED, conditions, List.copyOf(refusals));
        }
        // N-RBK-1: new writes store the canonical state names (PromptBundleState), as the release gate does.
        setStatus(scope, key, request.fromVersion(), PromptBundleState.DEPRECATED.name(), now);
        setStatus(scope, key, request.toVersion(), PromptBundleState.ACTIVE.name(), now);
        invalidation.publish(scope, key, request.toVersion(),
                "rollback from " + request.fromVersion() + (request.emergency() ? " (emergency stop)" : ""), actor);
        String status = request.emergency() ? AWAITING_APPROVAL : EXECUTED;
        record(executionKey, request, actor, status, conditions, List.of(), now);
        return new Result(executionKey, status, conditions, List.of());
    }

    /** A second operator approves an emergency stop after it ran; the operator who ran it cannot. */
    public Result approve(String executionKey, String approver) {
        List<String[]> rows = jdbc.query(
                "select status, actor from prompt_governance_rollback_execution where execution_key = ?",
                (rs, n) -> new String[] {rs.getString(1), rs.getString(2)}, executionKey);
        if (rows.isEmpty()) {
            return new Result(executionKey, REFUSED, null, List.of("EXECUTION_NOT_FOUND"));
        }
        if (!AWAITING_APPROVAL.equals(rows.get(0)[0])) {
            return new Result(executionKey, REFUSED, null, List.of("NOT_AWAITING_APPROVAL"));
        }
        if (Objects.equals(rows.get(0)[1], approver)) {
            return new Result(executionKey, REFUSED, null, List.of("APPROVER_IS_ACTOR"));
        }
        jdbc.update("update prompt_governance_rollback_execution set status = ?, approved_by = ?, approved_at = ? "
                + "where execution_key = ?", APPROVED, approver, Timestamp.from(clock.instant()), executionKey);
        return new Result(executionKey, APPROVED, null, List.of());
    }

    /** W7-14: a recorded rollback execution as the version screen lists it. */
    public record Execution(String executionKey, String fromVersion, String toVersion, String actor, String reason,
                            boolean emergency, String status, LocalDateTime executedAt, String approvedBy,
                            LocalDateTime approvedAt) {
    }

    /** W7-14: the latest rollback executions from or to a bundle of a scope, newest first. */
    public List<Execution> executions(String registryScope, String promptKey, String bundleVersion) {
        return jdbc.query("select execution_key, from_version, to_version, actor, reason, emergency, status, "
                        + "executed_at, approved_by, approved_at from prompt_governance_rollback_execution "
                        + "where registry_scope = ? and prompt_key = ? and (from_version = ? or to_version = ?) "
                        + "order by executed_at desc, execution_key desc limit " + EXECUTION_LIMIT,
                (rs, n) -> new Execution(rs.getString("execution_key"), rs.getString("from_version"),
                        rs.getString("to_version"), rs.getString("actor"), rs.getString("reason"),
                        rs.getBoolean("emergency"), rs.getString("status"), localDateTime(rs.getTimestamp("executed_at")),
                        rs.getString("approved_by"), localDateTime(rs.getTimestamp("approved_at"))),
                registryScope, promptKey, bundleVersion, bundleVersion);
    }

    private static LocalDateTime localDateTime(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toLocalDateTime();
    }

    /**
     * PV-3: the rollback ledger said READY for every declared target, whether or not the target could run. A target is
     * ready only when its bundle is in this build; the rows that said otherwise are corrected. Returns how many changed.
     */
    public int correctRollbackReadiness() {
        List<String[]> rows = jdbc.query("select id, prompt_key, rollback_target_prompt_version, rollback_readiness_state "
                        + "from prompt_governance_rollback_ledger",
                (rs, n) -> new String[] {rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)});
        int changed = 0;
        for (String[] row : rows) {
            String readiness = catalog.find(row[1], row[2]).isPresent() ? "READY" : "TARGET_NOT_IN_BUILD";
            if (!readiness.equals(row[3])) {
                changed += jdbc.update("update prompt_governance_rollback_ledger set rollback_readiness_state = ?, "
                        + "updated_at = ? where id = ?", readiness, Timestamp.from(clock.instant()), Long.parseLong(row[0]));
            }
        }
        return changed;
    }

    private String registryStatus(String scope, String key, String version) {
        List<String> statuses = jdbc.query("select release_status from prompt_governance_registry "
                        + "where registry_scope = ? and prompt_key = ? and prompt_version = ? order by updated_at desc",
                (rs, n) -> rs.getString(1), scope, key, version);
        return statuses.isEmpty() ? null : statuses.get(0);
    }

    private void setStatus(String scope, String key, String version, String status, Timestamp now) {
        jdbc.update("update prompt_governance_registry set release_status = ?, updated_at = ? "
                + "where registry_scope = ? and prompt_key = ? and prompt_version = ?", status, now, scope, key, version);
    }

    private void record(String executionKey, Request request, String actor, String status, Conditions conditions,
                        List<String> refusals, Timestamp now) {
        Map<String, Object> checked = new LinkedHashMap<>();
        checked.put("conditions", conditions);
        checked.put("refusals", refusals);
        String json;
        try {
            json = objectMapper.writeValueAsString(checked);
        } catch (Exception e) {
            log.error("Rollback conditions could not be written as JSON: executionKey={}", executionKey, e);
            json = String.valueOf(checked);
        }
        jdbc.update("insert into prompt_governance_rollback_execution (execution_key, registry_scope, prompt_key, "
                        + "from_version, to_version, actor, reason, emergency, status, conditions_json, executed_at) "
                        + "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", executionKey, request.registryScope(),
                request.promptKey(), request.fromVersion(), request.toVersion(), actor, request.reason(),
                request.emergency(), status, json, now);
    }
}
