package io.contexa.demo.experience.journey.repository.jdbc;

import io.contexa.demo.experience.journey.dto.JourneyReadCommand;
import io.contexa.demo.experience.journey.dto.JourneyReadRecord;
import io.contexa.demo.experience.journey.repository.JourneyReadRepository;
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
public class JdbcJourneyReadRepository extends AbstractJsonJdbcRepository implements JourneyReadRepository {

    public JdbcJourneyReadRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public JourneyReadRecord save(UUID visitorId, JourneyReadRecord record) {
        jdbc.update("""
                insert into lab.experience_journey_read
                    (id,journey_id,visitor_id,command_id,created_at,input_sha256,payload)
                values (?,?,?,?,?,?,?) on conflict (visitor_id,command_id) do nothing
                """, record.id(), record.journeyId(), visitorId, record.reported().commandId(),
                Timestamp.from(record.createdAt()), record.inputSha256(), documents.write(record.reported()));
        return first(jdbc.query("select * from lab.experience_journey_read where visitor_id=? and command_id=?",
                (rs, row) -> record(rs), visitorId, record.reported().commandId()));
    }

    @Override
    public List<JourneyReadRecord> list(UUID visitorId, UUID journeyId) {
        return jdbc.query("""
                select * from lab.experience_journey_read where visitor_id=? and journey_id=?
                order by created_at,id limit 100
                """, (rs, row) -> record(rs), visitorId, journeyId);
    }

    private JourneyReadRecord record(ResultSet rs) throws SQLException {
        return new JourneyReadRecord(rs.getObject("id", UUID.class), rs.getObject("journey_id", UUID.class),
                rs.getTimestamp("created_at").toInstant(), rs.getString("input_sha256"),
                documents.read(rs.getString("payload"), JourneyReadCommand.class));
    }
}
