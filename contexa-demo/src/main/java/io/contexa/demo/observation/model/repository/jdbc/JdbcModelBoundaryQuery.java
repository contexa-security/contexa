package io.contexa.demo.observation.model.repository.jdbc;

import io.contexa.demo.observation.model.dto.ModelBoundaryEvidence;
import io.contexa.demo.observation.model.dto.ModelBoundaryObservation;
import io.contexa.demo.observation.model.repository.ModelBoundaryQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcModelBoundaryQuery extends AbstractJsonJdbcRepository implements ModelBoundaryQuery {

    private static final int VISIBLE_LIMIT = 200;

    public JdbcModelBoundaryQuery(@Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public ModelBoundaryEvidence find(UUID requestId) {
        List<ModelBoundaryObservation> rows = jdbc.query("""
                select payload::text from lab.model_boundary_observation
                where request_id=? and event_id is not null
                  and processing_generation is not null and pipeline_request_id is not null
                order by observed_at,id limit ?
                """, (rs, row) -> documents.read(rs.getString(1), ModelBoundaryObservation.class),
                requestId, VISIBLE_LIMIT + 1);
        boolean limited = rows.size() > VISIBLE_LIMIT;
        return new ModelBoundaryEvidence(rows.isEmpty() ? "NOT_CAPTURED" : "ADVISOR_ONLY", limited,
                List.copyOf(rows.subList(0, Math.min(rows.size(), VISIBLE_LIMIT))));
    }
}
