package io.contexa.demo.comparison.run.repository.jdbc;

import io.contexa.demo.comparison.run.dto.RunRecord;
import io.contexa.demo.comparison.run.dto.RunSummary;
import io.contexa.demo.comparison.run.dto.RunStep;
import io.contexa.demo.comparison.run.dto.RunEvent;
import io.contexa.demo.comparison.run.dto.RunManifest;
import io.contexa.demo.comparison.run.repository.RunQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public class JdbcRunQuery extends AbstractJsonJdbcRepository implements RunQuery {

    public JdbcRunQuery(@Qualifier("comparisonJdbc") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public List<RunSummary> recent(UUID visitorId) {
        return jdbc.query("""
                select * from lab.comparison_run where visitor_id=? order by created_at desc,id limit 30
                """, (rs, row) -> {
            var run = record(rs);
            var plan = run.manifest().plan();
            return new RunSummary(run.id(), run.createdAt(), run.state(), plan.kind(), plan.path(),
                    plan.requestedAccount(), plan.purpose(), run.manifestSha256());
        }, visitorId);
    }

    @Override
    public RunRecord find(UUID visitorId, UUID runId) {
        return first(jdbc.query("select * from lab.comparison_run where visitor_id=? and id=?",
                (rs, row) -> record(rs), visitorId, runId));
    }

    @Override
    public RunRecord findCommand(UUID visitorId, UUID commandId) {
        return first(jdbc.query("select * from lab.comparison_run where visitor_id=? and command_id=?",
                (rs, row) -> record(rs), visitorId, commandId));
    }

    @Override
    public List<RunStep> steps(UUID runId) {
        return jdbc.query("select * from lab.comparison_run_step where run_id=? order by ordinal,arm",
                (rs, row) -> new RunStep(rs.getObject("id", UUID.class), runId, rs.getString("arm"),
                        rs.getInt("ordinal"), rs.getString("state"), rs.getObject("request_id", UUID.class),
                        instant(rs, "started_at"), instant(rs, "responded_at"),
                        rs.getObject("http_status", Integer.class), rs.getString("failure_type")), runId);
    }

    @Override
    public List<RunEvent> events(UUID runId) {
        return jdbc.query("""
                select sequence,step_id,kind,occurred_at,detail from lab.comparison_run_event
                where run_id=? order by sequence limit 501
                """, (rs, row) -> new RunEvent(rs.getLong("sequence"), rs.getObject("step_id", UUID.class),
                rs.getString("kind"), instant(rs, "occurred_at"), rs.getString("detail")), runId);
    }

    private RunRecord record(ResultSet rs) throws SQLException {
        return new RunRecord(rs.getObject("id", UUID.class), rs.getObject("visitor_id", UUID.class),
                rs.getObject("workspace_id", UUID.class), rs.getObject("command_id", UUID.class),
                rs.getObject("coordinator_instance_id", UUID.class), instant(rs, "created_at"),
                instant(rs, "dispatch_deadline"), rs.getString("input_sha256"), rs.getString("manifest_sha256"),
                documents.read(rs.getString("manifest"), RunManifest.class), rs.getString("state"));
    }

    private Instant instant(ResultSet rs, String column) throws SQLException {
        var value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }
}
