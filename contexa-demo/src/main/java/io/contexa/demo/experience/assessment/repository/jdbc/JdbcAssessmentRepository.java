package io.contexa.demo.experience.assessment.repository.jdbc;

import io.contexa.demo.experience.assessment.dto.AssessmentPosition;
import io.contexa.demo.experience.assessment.dto.StoredAssessment;
import io.contexa.demo.experience.assessment.repository.AssessmentRepository;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
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
public class JdbcAssessmentRepository extends AbstractJdbcRepository implements AssessmentRepository {

    public JdbcAssessmentRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc) {
        super(jdbc);
    }

    @Override
    public StoredAssessment findCommand(UUID visitorId, UUID commandId) {
        return first(jdbc.query("select * from lab.experience_assessment where visitor_id=? and command_id=?",
                (rs, row) -> record(rs), visitorId, commandId));
    }

    @Override
    public StoredAssessment save(UUID visitorId, UUID commandId, StoredAssessment value) {
        jdbc.update("""
                insert into lab.experience_assessment
                    (id,report_id,visitor_id,command_id,created_at,input_sha256,position,request_id,comment)
                values (?,?,?,?,?,?,?,?,?) on conflict (visitor_id,command_id) do nothing
                """, value.id(), value.reportId(), visitorId, commandId, Timestamp.from(value.createdAt()),
                value.inputSha256(), value.position().name(), value.requestId(), value.comment());
        return findCommand(visitorId, commandId);
    }

    @Override
    public List<StoredAssessment> list(UUID visitorId, UUID reportId) {
        return jdbc.query("""
                select * from lab.experience_assessment where visitor_id=? and report_id=?
                order by created_at desc,id limit 100
                """, (rs, row) -> record(rs), visitorId, reportId);
    }

    private StoredAssessment record(ResultSet rs) throws SQLException {
        return new StoredAssessment(rs.getObject("id", UUID.class), rs.getObject("report_id", UUID.class),
                rs.getTimestamp("created_at").toInstant(), rs.getString("input_sha256"),
                AssessmentPosition.valueOf(rs.getString("position")), rs.getObject("request_id", UUID.class),
                rs.getString("comment"));
    }
}
