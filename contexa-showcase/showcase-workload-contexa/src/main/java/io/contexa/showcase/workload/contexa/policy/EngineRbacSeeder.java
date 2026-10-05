package io.contexa.showcase.workload.contexa.policy;

import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.work.RbacPolicy;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Seeds the role-based policy of the business API into the engine's policy store, from the same table control B
 * enforces ({@link RbacPolicy}), then reloads the engine's URL authorization (docs/showcase/ADR.md ADR-25). Idempotent:
 * roles and groups are created once, and the showcase policies are rewritten on every start.
 * <p>
 * Engine roles are prefixed with ROLE_SC_ so they never meet the engine's own hierarchy (ROLE_ADMIN and below,
 * which opens the engine console). The engine permits a request no policy names, so the business areas end with a
 * deny-all policy, as the plain controls deny anything the table does not name.
 */
public class EngineRbacSeeder implements ApplicationRunner {

    public static final String ROLE_PREFIX = "ROLE_SC_";
    public static final String GROUP_PREFIX = "SC_";
    static final String POLICY_PREFIX = "SC_RBAC_";

    /** Business areas closed by the final deny-all policy; the engine's own sign-in paths stay outside them. */
    static final List<String> BUSINESS_AREAS = List.of("/api/projects", "/api/projects/**", "/api/documents/**",
            "/api/customers/**", "/api/admin/**");

    static final int FIRST_PRIORITY = 200;
    static final int DENY_PRIORITY = 290;

    private final JdbcTemplate engine;
    private final TransactionTemplate transactions;
    private final CustomDynamicAuthorizationManager authorizationManager;

    public EngineRbacSeeder(JdbcTemplate engine, TransactionTemplate transactions,
                            CustomDynamicAuthorizationManager authorizationManager) {
        this.engine = engine;
        this.transactions = transactions;
        this.authorizationManager = authorizationManager;
    }

    public static String engineRole(String roleKey) {
        return ROLE_PREFIX + roleKey;
    }

    public static String engineGroup(String roleKey) {
        return GROUP_PREFIX + roleKey;
    }

    @Override
    public void run(ApplicationArguments args) {
        transactions.executeWithoutResult(status -> {
            // The engine seed inserts rows with explicit ids; move the sequences past them before inserting.
            syncSequences("role", "role_id");
            syncSequences("app_group", "group_id");
            for (String role : List.of(CompanyBlueprint.ROLE_ENGINEER, CompanyBlueprint.ROLE_SALES,
                    CompanyBlueprint.ROLE_PM, CompanyBlueprint.ROLE_PARTNER, CompanyBlueprint.ROLE_FINANCE,
                    CompanyBlueprint.ROLE_ADMIN)) {
                engine.update("insert into role (role_name, role_desc, expression, enabled, created_by) "
                        + "values (?, ?, false, true, 'showcase') on conflict (role_name) do nothing",
                        engineRole(role), "Showcase virtual company role " + role);
                engine.update("insert into app_group (group_name, description, enabled, created_by) "
                        + "values (?, ?, true, 'showcase') on conflict (group_name) do nothing",
                        engineGroup(role), "Showcase virtual company employees with role " + role);
                engine.update("insert into group_roles (group_id, role_id, assigned_by) "
                        + "select g.group_id, r.role_id, 'showcase' from app_group g, role r "
                        + "where g.group_name = ? and r.role_name = ? on conflict (group_id, role_id) do nothing",
                        engineGroup(role), engineRole(role));
            }
            engine.update("delete from policy where name like ?", POLICY_PREFIX + "%");
            for (String table : List.of("policy", "policy_target", "policy_rule", "policy_condition")) {
                syncSequences(table, "id");
            }
            int priority = FIRST_PRIORITY;
            for (RbacPolicy.Rule rule : RbacPolicy.RULES) {
                String roles = rule.roles().stream().sorted()
                        .map(role -> "'" + engineRole(role) + "'")
                        .collect(Collectors.joining(","));
                insertPolicy(POLICY_PREFIX + rule.operation().name(), priority++, rule.pattern(), rule.method(),
                        "hasAnyAuthority(" + roles + ")",
                        "Showcase RBAC: " + rule.method() + " " + rule.pattern() + " for " + rule.roles().stream()
                                .sorted().collect(Collectors.joining(", ")));
            }
            int area = 0;
            for (String pattern : BUSINESS_AREAS) {
                insertPolicy(POLICY_PREFIX + "DENY_" + (area++), DENY_PRIORITY, pattern, "ANY", "denyAll",
                        "Showcase RBAC: anything else under " + pattern + " is denied");
            }
        });
        authorizationManager.reload();
    }

    private void syncSequences(String table, String column) {
        engine.queryForObject("select setval(pg_get_serial_sequence('" + table + "', '" + column + "'), "
                + "greatest((select coalesce(max(" + column + "), 0) from " + table + "), 1))", Long.class);
    }

    private void insertPolicy(String name, int priority, String pattern, String method, String condition,
                              String description) {
        Long policyId = engine.queryForObject("""
                        insert into policy (name, description, effect, priority, is_active, source, approval_status,
                                            friendly_description, created_at)
                        values (?, ?, 'ALLOW', ?, true, 'MANUAL', 'NOT_REQUIRED', ?, current_timestamp)
                        returning id""",
                Long.class, name, description, priority, description);
        engine.update("insert into policy_target (policy_id, target_type, target_identifier, http_method, "
                + "target_order, source_type) values (?, 'URL', ?, ?, 1, 'MANUAL')", policyId, pattern,
                method.toUpperCase(Locale.ROOT));
        Long ruleId = engine.queryForObject("insert into policy_rule (policy_id, description) values (?, ?) returning id",
                Long.class, policyId, description);
        engine.update("insert into policy_condition (rule_id, condition_expression, authorization_phase, description) "
                + "values (?, ?, 'PRE_AUTHORIZE', ?)", ruleId, condition, description);
    }
}
