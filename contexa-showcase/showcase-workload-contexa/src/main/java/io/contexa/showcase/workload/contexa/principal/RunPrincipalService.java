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
 */
public class RunPrincipalService {

    public record Principal(String username, String runId, String employeeKey, String roleKey, String displayName,
                            String department, String organizationId, String tenantId) {

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
