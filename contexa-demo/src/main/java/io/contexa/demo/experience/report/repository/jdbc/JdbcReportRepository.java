package io.contexa.demo.experience.report.repository.jdbc;

import io.contexa.demo.experience.report.dto.ReportPayload;
import io.contexa.demo.experience.report.dto.ReportSummary;
import io.contexa.demo.experience.report.dto.StoredReport;
import io.contexa.demo.experience.report.repository.ReportRepository;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;

@Repository
@Profile("portal")
public class JdbcReportRepository extends AbstractJsonJdbcRepository implements ReportRepository {

    public JdbcReportRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public StoredReport find(UUID visitorId, UUID reportId) {
        return first(jdbc.query("select * from lab.experience_report where visitor_id=? and id=?",
                (rs, row) -> record(rs), visitorId, reportId));
    }

    @Override
    public StoredReport findCommand(UUID visitorId, UUID commandId) {
        return first(jdbc.query("select * from lab.experience_report where visitor_id=? and command_id=?",
                (rs, row) -> record(rs), visitorId, commandId));
    }

    @Override
    public List<ReportSummary> list(UUID visitorId, UUID runId) {
        return jdbc.query("""
                select id,run_id,created_at,content_sha256 from lab.experience_report
                where visitor_id=? and run_id=? order by created_at desc,id limit 50
                """, (rs, row) -> new ReportSummary(rs.getObject("id", UUID.class), runId,
                rs.getTimestamp("created_at").toInstant(), rs.getString("content_sha256")), visitorId, runId);
    }

    @Override
    public StoredReport save(UUID visitorId, UUID commandId, StoredReport report) {
        jdbc.update("""
                insert into lab.experience_report
                    (id,run_id,visitor_id,command_id,created_at,content_sha256,payload)
                values (?,?,?,?,?,?,?) on conflict (visitor_id,command_id) do nothing
                """, report.id(), report.runId(), visitorId, commandId, Timestamp.from(report.createdAt()),
                report.contentSha256(), documents.write(report.payload()));
        return findCommand(visitorId, commandId);
    }

    private StoredReport record(ResultSet rs) throws SQLException {
        return new StoredReport(rs.getObject("id", UUID.class), rs.getObject("run_id", UUID.class),
                rs.getTimestamp("created_at").toInstant(), rs.getString("content_sha256"),
                rs.getString("payload_encoding"),
                documents.read(rs.getString("payload"), ReportPayload.class));
    }
}
