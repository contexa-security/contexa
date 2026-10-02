package io.contexa.demo.work.participant.repository.jdbc;

import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.participant.repository.WorkMembershipRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcWorkMembershipRepository extends AbstractJdbcRepository implements WorkMembershipRepository {

    public JdbcWorkMembershipRepository(@Qualifier("entryJdbc") JdbcOperations jdbc) {
        super(jdbc);
    }

    public WorkParticipant find(UUID visitorId, String username) {
        return first(jdbc.query("""
                select id, visitor_id from lab.workspace
                where visitor_id=? and expires_at>current_timestamp and jsonb_exists(allowed_accounts,?)
                """, (rs, row) -> new WorkParticipant(rs.getObject("visitor_id", UUID.class),
                rs.getObject("id", UUID.class), username), visitorId, username));
    }
}
