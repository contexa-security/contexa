package io.contexa.demo.readiness.repository.jdbc;

import io.contexa.demo.readiness.dto.ReadinessReport;
import io.contexa.demo.readiness.dto.StoredReadiness;
import io.contexa.demo.readiness.repository.ReadinessHistoryRepository;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;

@Repository
public class JdbcReadinessHistoryRepository extends AbstractJsonJdbcRepository implements ReadinessHistoryRepository {

    public JdbcReadinessHistoryRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec codec) {
        super(jdbc, codec);
    }

    public UUID save(ReadinessReport report) {
        UUID id = UUID.randomUUID();
        String json = documents.write(report);
        jdbc.update(
                "insert into lab.readiness_snapshot(id,role,observed_at,snapshot,content_sha256) values(?,?,?,?::jsonb,?)",
                id, report.role(), Timestamp.from(report.observedAt()), json, documents.hash(json));
        return id;
    }

    public List<StoredReadiness> history() {
        return jdbc.query(
                "select id,role,observed_at,snapshot::text,content_sha256 from lab.readiness_snapshot order by observed_at desc limit 30",
                (rs, n) -> new StoredReadiness(rs.getObject("id", UUID.class), rs.getString("role"),
                        rs.getTimestamp("observed_at").toInstant(),
                        documents.read(rs.getString("snapshot"), Object.class), rs.getString("content_sha256")));
    }
}
