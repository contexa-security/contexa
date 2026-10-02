package io.contexa.demo.experience.journey.repository.jdbc;

import io.contexa.demo.experience.journey.dto.JourneyRecord;
import io.contexa.demo.experience.journey.dto.JourneySnapshot;
import io.contexa.demo.experience.journey.repository.JourneyRepository;
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
public class JdbcJourneyRepository extends AbstractJsonJdbcRepository implements JourneyRepository {

    public JdbcJourneyRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public JourneyRecord find(UUID visitorId, UUID id) {
        return first(jdbc.query("select * from lab.experience_journey where visitor_id=? and id=?",
                (rs, row) -> record(rs), visitorId, id));
    }

    @Override
    public JourneyRecord findCommand(UUID visitorId, UUID commandId) {
        return first(jdbc.query("select * from lab.experience_journey where visitor_id=? and command_id=?",
                (rs, row) -> record(rs), visitorId, commandId));
    }

    @Override
    public JourneyRecord save(UUID visitorId, UUID commandId, JourneyRecord record) {
        jdbc.update("""
                insert into lab.experience_journey
                    (id,visitor_id,command_id,created_at,input_sha256,content_sha256,payload)
                values (?,?,?,?,?,?,?) on conflict (visitor_id,command_id) do nothing
                """, record.id(), visitorId, commandId, Timestamp.from(record.createdAt()), record.inputSha256(),
                record.contentSha256(), documents.write(record.snapshot()));
        return findCommand(visitorId, commandId);
    }

    @Override
    public List<JourneyRecord> recent(UUID visitorId) {
        return jdbc.query("select * from lab.experience_journey where visitor_id=? order by created_at desc,id limit 30",
                (rs, row) -> record(rs), visitorId);
    }

    @Override
    public List<UUID> runIds(UUID visitorId, UUID journeyId) {
        return jdbc.query("""
                select id from lab.comparison_run
                where visitor_id=? and manifest#>>'{plan,journeyStep,journeyId}'=?
                order by created_at desc,id limit 101
                """, (rs, row) -> rs.getObject("id", UUID.class), visitorId, journeyId.toString());
    }

    private JourneyRecord record(ResultSet rs) throws SQLException {
        return new JourneyRecord(rs.getObject("id", UUID.class), rs.getTimestamp("created_at").toInstant(),
                rs.getString("input_sha256"), rs.getString("content_sha256"),
                documents.read(rs.getString("payload"), JourneySnapshot.class));
    }
}
