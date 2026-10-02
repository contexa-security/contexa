package io.contexa.demo.comparison.attestation.source.jdbc;

import io.contexa.demo.comparison.attestation.source.PreparationPlanQuery;
import io.contexa.demo.comparison.preparation.dto.PreparedComparison;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcPreparationPlanQuery extends AbstractJsonJdbcRepository implements PreparationPlanQuery {

    public JdbcPreparationPlanQuery(@Qualifier("entryJdbc") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public PreparedComparison find(UUID visitorId, UUID preparationId) {
        return first(jdbc.query("""
                select preparation::text from lab.comparison_preparation
                where visitor_id=? and id=?
                """, (rs, row) -> documents.read(rs.getString(1), PreparedComparison.class),
                visitorId, preparationId));
    }
}
