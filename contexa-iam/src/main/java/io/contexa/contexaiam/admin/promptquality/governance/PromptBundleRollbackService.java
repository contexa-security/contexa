package io.contexa.contexaiam.admin.promptquality.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleRunnability;
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
 *
 * <p>Plan 3.9: a rollback to a version of the database ({@code v2.0}) goes to a version of the scope that exists, is
 * not hidden and has its registry row; a target that is missing, hidden or not registered is refused as
 * {@link #TARGET_MISSING_OR_HIDDEN}. Plan 3.4: it goes back only to a version the scope used for decisions before
 * ({@code PromptVersionCatalog.usedForDecisions}); any other target is refused as
 * {@link #TARGET_NOT_USED_FOR_DECISIONS}, so a version nobody measured or used does not reach the decisions this way.
 * Its vocabulary is its reason codes: a security decision version whose reason codes are not the engine's is refused as
 * VOCABULARY_INCOMPATIBLE. The version it replaces, and any other version that was used for decisions, become
 * AVAILABLE.
 */
public class PromptBundleRollbackService {

    private static final Logger log = LoggerFactory.getLogger(PromptBundleRollbackService.class);

    public static final String EXECUTED = "EXECUTED";
    public static final String AWAITING_APPROVAL = "AWAITING_APPROVAL";
    public static final String APPROVED = "APPROVED";
    public static final String REFUSED = "REFUSED";
    /** A request that lacks what a rollback needs: nothing is checked or recorded. */
    public static final String INCOMPLETE = "INCOMPLETE";
    public static final String NOT_APPLICABLE = "NOT_APPLICABLE";
    /**
     * Plan 3.9: the target version is missing, hidden or not registered in the scope (what TARGET_NOT_IN_BUILD,
     * TARGET_NOT_DECLARED and TARGET_NOT_REGISTERED said apart); also the readiness of a rollback ledger row whose
     * target cannot run.
     */
    public static final String TARGET_MISSING_OR_HIDDEN = "TARGET_MISSING_OR_HIDDEN";
    /** Plan 3.4: the target version exists but the scope never used it for decisions. */
    public static final String TARGET_NOT_USED_FOR_DECISIONS = "TARGET_NOT_USED_FOR_DECISIONS";
    /** W7-14: how many executions of a bundle the version screen lists. */
    private static final int EXECUTION_LIMIT = 20;
    /** N-GOV-5: the stored values of an active release, of every vocabulary (decision 1). */
    private static final String ACTIVE_STATES = PromptBundleState.sqlList(PromptBundleState.ACTIVE);

    private final JdbcTemplate jdbc;
    private final PromptBundleCatalog catalog;
    private final PromptGovernanceRuntimeCacheInvalidationService invalidation;
    private final PromptPolicySetLookup policySets;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final PromptGovernanceStatusWriter statusWriter;

    public PromptBundleRollbackService(JdbcTemplate jdbc, PromptBundleCatalog catalog,
                                       PromptGovernanceRuntimeCacheInvalidationService invalidation,
                                       PromptPolicySetLookup policySets, ObjectMapper objectMapper, Clock clock,
                                       PromptGovernanceStatusWriter statusWriter) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.catalog = Objects.requireNonNull(catalog, "catalog");
        this.invalidation = Objects.requireNonNull(invalidation, "invalidation");
        this.policySets = policySets;
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.statusWriter = Objects.requireNonNull(statusWriter, "statusWriter");
    }

    /** What the operator asks: the scope's active bundle, the target to switch to, why, and whether it is an emergency. */
    public record Request(String registryScope, String promptKey, String fromVersion, String toVersion, String reason,
                          boolean emergency) {
    }

    /**
     * The conditions the rollback was checked against; plan 3.4: whether the scope used the target for decisions
     * before (a bundle's declared target is, by its declaration).
     */
    public record Conditions(boolean sourceExecuting, boolean targetInBuild, boolean targetDeclared,
                             boolean vocabularyCompatible, boolean targetRegistered, String policySet,
                             boolean targetUsedForDecisions) {

        public Conditions(boolean sourceExecuting, boolean targetInBuild, boolean targetDeclared,
                          boolean vocabularyCompatible, boolean targetRegistered, String policySet) {
            this(sourceExecuting, targetInBuild, targetDeclared, vocabularyCompatible, targetRegistered, policySet,
                    true);
        }
    }

    /** The recorded execution: its key, its status, the conditions and why it was refused. */
    public record Result(String executionKey, String status, Conditions conditions, List<String> refusals) {
    }

    /**
     * One declared target as the rollback check reads it: in this build, which means the build runs it (K1: a
     * manifest kept only as a record is not in the build), and registered in the scope.
     */
    public record TargetReadiness(String version, boolean inBuild, boolean registered) {
    }

    /**
     * What the version screen needs before it offers a rollback: whether the bundle executes in the scope, and which of
     * its declared targets the rollback check would accept. It is read with the same conditions {@link #rollback} checks.
     */
    public record Readiness(boolean sourceExecuting, List<TargetReadiness> targets) {

        /** Whether a rollback of this bundle can pass the source and target conditions at all. */
        public boolean runnable() {
            return sourceExecuting && targets.stream().anyMatch(target -> target.inBuild() && target.registered());
        }
    }

    public Readiness readiness(String scope, String key, String version, List<String> declaredTargets) {
        boolean executing = executing(registryStatus(scope, key, version));
        List<TargetReadiness> targets = new ArrayList<>();
        for (String target : declaredTargets == null ? List.<String>of() : declaredTargets) {
            targets.add(new TargetReadiness(target, PromptBundleRunnability.runnable(catalog, scope, key, target),
                    registryStatus(scope, key, target) != null));
        }
        return new Readiness(executing, List.copyOf(targets));
    }

    private static boolean executing(String status) {
        return status != null && (PromptBundleState.is(status, PromptBundleState.ACTIVE)
                || PromptBundleState.is(status, PromptBundleState.CANARY));
    }

    public Result rollback(Request request, String actor) {
        List<String> missing = missingFields(request);
        if (!missing.isEmpty()) {
            log.warn("[PromptRollback] Rollback request refused: missing {}", missing);
            return new Result(null, INCOMPLETE, null, missing);
        }
        String scope = request.registryScope().trim();
        String key = request.promptKey().trim();
        String to = request.toVersion().trim();
        boolean sourceExecuting = executing(registryStatus(scope, key, request.fromVersion()));
        // W6-10: the policy set the target runs with, of a host that keeps policy sets; a version is named as v2.0.
        String policySet = policySets == null ? NOT_APPLICABLE
                : policySets.policySetExists(scope, key, to) ? "PRESENT" : "MISSING";
        boolean targetRegistered = registryStatus(scope, key, to) != null;
        Conditions conditions = PromptBundleCatalog.isVersionName(to)
                ? versionConditions(scope, key, to, sourceExecuting, targetRegistered, policySet)
                : bundleConditions(key, request.fromVersion(), to, sourceExecuting, targetRegistered, policySet);
        List<String> refusals = new ArrayList<>();
        if (!conditions.sourceExecuting()) {
            refusals.add("SOURCE_NOT_EXECUTING");
        }
        if (!conditions.targetInBuild() || !conditions.targetDeclared() || !conditions.targetRegistered()) {
            refusals.add(TARGET_MISSING_OR_HIDDEN);
        }
        else if (!conditions.targetUsedForDecisions()) {
            refusals.add(TARGET_NOT_USED_FOR_DECISIONS);
        }
        if (!conditions.vocabularyCompatible()) {
            refusals.add("VOCABULARY_INCOMPATIBLE");
        }
        if ("MISSING".equals(policySet)) {
            refusals.add("POLICY_SET_MISSING");
        }
        String executionKey = "RBX-" + UUID.randomUUID();
        Timestamp now = Timestamp.from(clock.instant());
        if (!refusals.isEmpty()) {
            log.warn("[PromptRollback] Rollback of {} {} -> {} refused: {}", key, request.fromVersion(), to, refusals);
            record(executionKey, request, actor, REFUSED, conditions, refusals, List.of(), now);
            return new Result(executionKey, REFUSED, conditions, List.copyOf(refusals));
        }
        // N-RBK-1: new writes store the canonical state names (PromptBundleState), as the release gate does.
        setStatus(scope, key, request.fromVersion(), replacedState(request.fromVersion()).name(), now);
        setStatus(scope, key, to, PromptBundleState.ACTIVE.name(), now);
        // N-GOV-5: the target is the one active release of its scope, prompt key and template; the other active
        // releases it replaces are deprecated with the source (a version is no longer used: AVAILABLE) and named in
        // the execution's conditions.
        List<String> superseded = otherActiveVersions(scope, key, request.fromVersion(), to);
        superseded.forEach(version -> setStatus(scope, key, version, replacedState(version).name(), now));
        invalidation.publish(scope, key, to,
                "rollback from " + request.fromVersion() + (request.emergency() ? " (emergency stop)" : ""), actor);
        String status = request.emergency() ? AWAITING_APPROVAL : EXECUTED;
        record(executionKey, request, actor, status, conditions, List.of(), superseded, now);
        return new Result(executionKey, status, conditions, List.of());
    }

    /**
     * Plan 3.9: the conditions of a target version. It runs when the version table of the scope has it and it is not
     * hidden; plan 3.4: it is a target when the scope used it for decisions before (it is "used for decisions" again);
     * its vocabulary is its reason codes, which a security decision version must share with the engine (a prompt
     * without reason codes has no vocabulary to differ in). A target that does not run is refused as missing or hidden
     * alone.
     */
    private Conditions versionConditions(String scope, String key, String to, boolean sourceExecuting,
                                         boolean targetRegistered, String policySet) {
        boolean runs = PromptBundleRunnability.runnable(catalog, scope, key, to);
        boolean vocabulary = !runs || !SecurityDecisionPromptDocument.PROMPT.equals(key) || catalog.versions()
                .assembled(scope, key, to).map(SecurityDecisionPromptDocument::reasonCodesOfEngine).orElse(false);
        boolean usedBefore = !runs || catalog.versions().usedForDecisions(scope, key, to);
        return new Conditions(sourceExecuting, runs, runs, vocabulary, targetRegistered, policySet, usedBefore);
    }

    /**
     * The conditions of a target bundle (the prompts that still have manifests, plan 6-7): it runs in this build (K1: a
     * manifest kept only as a record is not), the source's manifest declares it, and its manifest reads the vocabulary
     * the stored data is in.
     */
    private Conditions bundleConditions(String key, String from, String to, boolean sourceExecuting,
                                        boolean targetRegistered, String policySet) {
        PromptBundleManifest source = catalog.find(key, from).orElse(null);
        PromptBundleManifest target = catalog.find(key, to).orElse(null);
        return new Conditions(sourceExecuting, target != null && PromptBundleRunnability.runnable(catalog, key, to),
                source != null && source.rollbackTargets().contains(to),
                target != null && target.compatibleVocabularyVersions().contains(VocabularyVersion.CURRENT),
                targetRegistered, policySet);
    }

    /** The state a replaced release takes: a version is no longer used (AVAILABLE), a bundle is DEPRECATED. */
    private static PromptBundleState replacedState(String release) {
        return PromptBundleCatalog.isVersionName(release) ? PromptBundleState.AVAILABLE : PromptBundleState.DEPRECATED;
    }

    /** The values a rollback cannot be checked without, named as the refusal codes the screen reads. */
    static List<String> missingFields(Request request) {
        List<String> missing = new ArrayList<>();
        if (request == null) {
            missing.add("REQUEST_REQUIRED");
            return missing;
        }
        requireText(missing, request.registryScope(), "REGISTRY_SCOPE_REQUIRED");
        requireText(missing, request.promptKey(), "PROMPT_KEY_REQUIRED");
        requireText(missing, request.fromVersion(), "FROM_VERSION_REQUIRED");
        requireText(missing, request.toVersion(), "TO_VERSION_REQUIRED");
        requireText(missing, request.reason(), "REASON_REQUIRED");
        return missing;
    }

    private static void requireText(List<String> missing, String value, String code) {
        if (value == null || value.isBlank()) {
            missing.add(code);
        }
    }

    /** A second operator approves an emergency stop after it ran; the operator who ran it cannot. */
    public Result approve(String executionKey, String approver) {
        List<String[]> rows = jdbc.query(
                "select status, actor from ctxa_prompt_governance_rollback_execution where execution_key = ?",
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
        jdbc.update("update ctxa_prompt_governance_rollback_execution set status = ?, approved_by = ?, approved_at = ? "
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
                        + "executed_at, approved_by, approved_at from ctxa_prompt_governance_rollback_execution "
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
     * ready only when it runs (plan 3.9: a version of its scope that exists and is not hidden, or a bundle in this
     * build); the rows that said otherwise are corrected. Returns how many changed.
     */
    public int correctRollbackReadiness() {
        List<String[]> rows = jdbc.query("select id, prompt_key, rollback_target_prompt_version, rollback_readiness_state, "
                        + "registry_scope from ctxa_prompt_governance_rollback_ledger",
                (rs, n) -> new String[] {rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5)});
        int changed = 0;
        for (String[] row : rows) {
            String readiness = PromptBundleRunnability.runnable(catalog, row[4], row[1], row[2]) ? "READY"
                    : TARGET_MISSING_OR_HIDDEN;
            if (!readiness.equals(row[3])) {
                // the ledger is a JPA table (persistence-ownership.yml): written through its repository
                statusWriter.rollbackReadiness(Long.parseLong(row[0]), readiness,
                        Timestamp.from(clock.instant()).toLocalDateTime());
                changed++;
            }
        }
        return changed;
    }

    private String registryStatus(String scope, String key, String version) {
        List<String> statuses = jdbc.query("select release_status from ctxa_prompt_governance_registry "
                        + "where registry_scope = ? and prompt_key = ? and prompt_version = ? order by updated_at desc",
                (rs, n) -> rs.getString(1), scope, key, version);
        return statuses.isEmpty() ? null : statuses.get(0);
    }

    /** N-GOV-5: the other active releases of the target's scope, prompt key and template, by version. */
    private List<String> otherActiveVersions(String scope, String key, String fromVersion, String toVersion) {
        return jdbc.queryForList("select prompt_version from ctxa_prompt_governance_registry where registry_scope = ? "
                        + "and prompt_key = ? and prompt_version not in (?, ?) and upper(release_status) in ("
                        + ACTIVE_STATES + ") and template_key in (select template_key from ctxa_prompt_governance_registry "
                        + "where registry_scope = ? and prompt_key = ? and prompt_version = ?) order by prompt_version",
                String.class, scope, key, fromVersion, toVersion, scope, key, toVersion);
    }

    private void setStatus(String scope, String key, String version, String status, Timestamp now) {
        // the registry is a JPA table (persistence-ownership.yml): written through its repository
        statusWriter.releaseStatus(scope, key, version, status, now.toLocalDateTime());
    }

    private void record(String executionKey, Request request, String actor, String status, Conditions conditions,
                        List<String> refusals, List<String> superseded, Timestamp now) {
        Map<String, Object> checked = new LinkedHashMap<>();
        checked.put("conditions", conditions);
        checked.put("refusals", refusals);
        checked.put("superseded", superseded);
        String json;
        try {
            json = objectMapper.writeValueAsString(checked);
        } catch (Exception e) {
            log.error("Rollback conditions could not be written as JSON: executionKey={}", executionKey, e);
            json = String.valueOf(checked);
        }
        jdbc.update("insert into ctxa_prompt_governance_rollback_execution (execution_key, registry_scope, prompt_key, "
                        + "from_version, to_version, actor, reason, emergency, status, conditions_json, executed_at) "
                        + "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", executionKey, request.registryScope(),
                request.promptKey(), request.fromVersion(), request.toVersion(), actor, request.reason(),
                request.emergency(), status, json, now);
    }
}
