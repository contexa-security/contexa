package io.contexa.showcase.workload.contexa.principal;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurgeResult;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurger;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.run.RunRegistry;
import io.contexa.showcase.workload.contexa.policy.EngineRbacSeeder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

/**
 * Engine accounts of run principals (docs/showcase/ADR.md ADR-23). Every principal joins the engine group of its
 * employee's role, so a run principal and its template have exactly the same authorities; otherwise the engine
 * would see a permission change on the first request. Deletion purges the engine state through the public purge
 * API and then removes the account rows.
 *
 * <p>An approver is the security administrator of a run who approves the release of a block through the engine's own
 * administrator API (ADR-33). It is a principal of another employee of the IT administration and holds the engine's
 * administrator role besides; only the portal knows its password, and it goes with the run.</p>
 */
public class RunPrincipalService {

    /** The engine's administrator role an approver holds. */
    public static final String ENGINE_ADMIN_ROLE = "ROLE_ADMIN";

    public record Principal(String username, String runId, String employeeKey, String roleKey, String displayName,
                            String department, String organizationId, String tenantId, boolean approver) {

        public String email() {
            return username + "@" + CompanyBlueprint.EMAIL_DOMAIN;
        }
    }

    private final UserRepository users;
    private final JdbcTemplate engine;
    private final PasswordEncoder passwordEncoder;
    private final UserEngineStatePurger purger;
    private final RunRegistry runs;

    public RunPrincipalService(UserRepository users, JdbcTemplate engine, PasswordEncoder passwordEncoder,
                               UserEngineStatePurger purger, RunRegistry runs) {
        this.users = users;
        this.engine = engine;
        this.passwordEncoder = passwordEncoder;
        this.purger = purger;
        this.runs = runs;
    }

    public void create(Principal principal, String password) {
        runs.registerPrincipal(principal.username(), principal.runId(), principal.employeeKey(),
                principal.organizationId(), principal.tenantId());
        Users saved = users.save(Users.builder()
                .username(principal.username())
                .email(principal.email())
                .password(passwordEncoder.encode(password))
                .name(principal.displayName())
                .department(principal.department())
                .position(principal.roleKey())
                .organizationId(principal.organizationId())
                .locale("en")
                .timezone("UTC")
                .build());
        engine.update("insert into user_groups (user_id, group_id, assigned_by) "
                + "select ?, group_id, 'showcase' from app_group where group_name = ? "
                + "on conflict (user_id, group_id) do nothing", saved.getId(),
                EngineRbacSeeder.engineGroup(principal.roleKey()));
        if (principal.approver()) {
            int granted = engine.update("insert into user_roles (role_id, user_id, assigned_at, assigned_by) "
                    + "select role_id, ?, now(), 'showcase' from role where role_name = ? "
                    + "on conflict (role_id, user_id) do nothing", saved.getId(), ENGINE_ADMIN_ROLE);
            if (granted != 1) {
                throw new IllegalStateException("The engine has no " + ENGINE_ADMIN_ROLE + " role to grant an approver");
            }
        }
    }

    /** Purges the engine state of the principal, then deletes its account rows (foreign keys first). */
    public UserEngineStatePurgeResult delete(String username) {
        UserEngineStatePurgeResult result = purger.purge(username);
        Optional<Long> userId = engine.queryForList("select id from users where username = ?", Long.class, username)
                .stream().findFirst();
        userId.ifPresent(id -> {
            engine.update("delete from user_role_permissions where user_id = ?", id);
            engine.update("delete from bridge_user_profile where user_id = ?", id);
            engine.update("delete from user_roles where user_id = ?", id);
            engine.update("delete from user_groups where user_id = ?", id);
            engine.update("delete from users where id = ?", id);
        });
        return result;
    }

    public boolean exists(String username) {
        Integer count = engine.queryForObject("select count(*) from users where username = ?", Integer.class, username);
        return count != null && count > 0;
    }
}
