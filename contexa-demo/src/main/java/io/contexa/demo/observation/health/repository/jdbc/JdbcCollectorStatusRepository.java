package io.contexa.demo.observation.health.repository.jdbc;

import io.contexa.demo.observation.health.dto.CollectorSnapshot;
import io.contexa.demo.observation.health.repository.CollectorStatusRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcCollectorStatusRepository implements CollectorStatusRepository {

    private final JdbcOperations jdbc;

    public JdbcCollectorStatusRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void save(List<CollectorSnapshot> snapshots) {
        List<Object[]> values = snapshots.stream().map(value -> new Object[] {
                value.instanceId(), value.source(), Timestamp.from(value.startedAt()),
                Timestamp.from(value.sampledAt()), value.lifecycle(), value.offered(), value.stored(),
                value.rejected(), value.writeUnconfirmed(), value.abandoned(), value.pending(), value.inFlight()
        }).toList();
        jdbc.batchUpdate("""
                insert into lab.observation_collector_status
                    (instance_id, source, started_at, sampled_at, lifecycle, offered, stored,
                     rejected, write_unconfirmed, abandoned, pending, in_flight)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict (instance_id, source) do update set
                    sampled_at = excluded.sampled_at, lifecycle = excluded.lifecycle,
                    offered = excluded.offered, stored = excluded.stored,
                    rejected = excluded.rejected, write_unconfirmed = excluded.write_unconfirmed,
                    abandoned = excluded.abandoned, pending = excluded.pending, in_flight = excluded.in_flight
                where lab.observation_collector_status.sampled_at <= excluded.sampled_at
                """, values);
    }

    @Override
    public List<CollectorSnapshot> find(UUID instanceId) {
        return jdbc.query("""
                select * from lab.observation_collector_status
                where instance_id = ? order by source limit 4
                """, (rs, row) -> new CollectorSnapshot(rs.getObject("instance_id", UUID.class),
                rs.getString("source"), rs.getTimestamp("started_at").toInstant(),
                rs.getTimestamp("sampled_at").toInstant(), rs.getString("lifecycle"),
                rs.getLong("offered"), rs.getLong("stored"), rs.getLong("rejected"),
                rs.getLong("write_unconfirmed"), rs.getLong("abandoned"), rs.getLong("pending"),
                rs.getLong("in_flight")), instanceId);
    }
}
