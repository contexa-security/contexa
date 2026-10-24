package io.contexa.showcase.business.context;

import io.contexa.showcase.business.work.WorkDatabase;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The delegations of record in the business database (docs/agent A7-0, A7-1): the work a person delegated to an agent.
 * A run's delegations are seen only through the run's principals, as every other run fact.
 */
public final class AgentDelegations {

    /**
     * One delegation of record.
     *
     * @param delegatorUsername the run principal of the person who delegated the work
     * @param recordedBy        who wrote the record: a run principal for an employee, else the id as recorded (an
     *                          agent's); null when the record does not say (A2-10)
     * @param recordedAt        when the record was written, or null when it does not say (A2-10)
     */
    public record Delegation(String delegationKey, String delegatorUsername, String agentId, String objectiveId,
                             String objectiveFamily, String summary, List<String> operations, List<String> resources,
                             boolean approvalRequired, Instant validFrom, Instant expiresAt, boolean revoked,
                             String recordedBy, Instant recordedAt) {
    }

    private final WorkDatabase database;

    public AgentDelegations(WorkDatabase database) {
        this.database = database;
    }

    /**
     * The latest delegation the person made to the agent, or the one with the given key; ended and revoked ones are
     * returned too, since their end is a fact the decision weighs.
     */
    public Optional<Delegation> find(String delegatorUsername, String agentId, String delegationKey) {
        if (delegatorUsername == null || agentId == null) {
            return Optional.empty();
        }
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("username", delegatorUsername).addValue("agent", agentId)
                .addValue("key", delegationKey);
        List<Delegation> found = database.jdbc().query("""
                select d.delegation_key, p.username, d.agent_id, d.objective_id, d.objective_family, d.summary,
                       d.operations, d.resources, d.approval_required, d.valid_from, d.expires_at, d.revoked,
                       coalesce(r.username, d.recorded_by) as recorded_by, d.recorded_at
                  from agent_delegation d
                  join run_principal p on p.employee_key = d.delegator and p.run_id = d.run_id
                  left join run_principal r on r.employee_key = d.recorded_by and r.run_id = d.run_id
                 where p.username = :username and d.agent_id = :agent
                   and (cast(:key as varchar) is null or d.delegation_key = :key)
                 order by d.valid_from desc, d.delegation_key
                 limit 1""", params, AgentDelegations::delegation);
        return found.stream().findFirst();
    }

    private static Delegation delegation(ResultSet row, int index) throws SQLException {
        return new Delegation(row.getString("delegation_key"), row.getString("username"), row.getString("agent_id"),
                row.getString("objective_id"), row.getString("objective_family"), row.getString("summary"),
                list(row.getString("operations")), list(row.getString("resources")),
                row.getBoolean("approval_required"), instant(row.getTimestamp("valid_from")),
                instant(row.getTimestamp("expires_at")), row.getBoolean("revoked"), row.getString("recorded_by"),
                instant(row.getTimestamp("recorded_at")));
    }

    private static List<String> list(String joined) {
        if (joined == null || joined.isBlank()) {
            return List.of();
        }
        return Arrays.stream(joined.split(",")).map(String::trim).filter(value -> !value.isEmpty()).toList();
    }

    private static Instant instant(Timestamp value) {
        return value == null ? null : value.toInstant();
    }
}
