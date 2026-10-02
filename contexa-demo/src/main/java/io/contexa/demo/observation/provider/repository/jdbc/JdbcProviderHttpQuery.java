package io.contexa.demo.observation.provider.repository.jdbc;

import io.contexa.demo.observation.provider.dto.ProviderHttpEvidence;
import io.contexa.demo.observation.provider.dto.ProviderHttpObservation;
import io.contexa.demo.observation.provider.repository.ProviderHttpQuery;
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
public class JdbcProviderHttpQuery extends AbstractJsonJdbcRepository implements ProviderHttpQuery {

    private static final int LIMIT = 200;

    public JdbcProviderHttpQuery(@Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public ProviderHttpEvidence find(UUID requestId) {
        List<ProviderHttpObservation> rows = jdbc.query("""
                select payload::text from lab.provider_http_observation where request_id=?
                order by observed_at,id limit ?
                """, (rs, row) -> documents.read(rs.getString(1), ProviderHttpObservation.class), requestId, LIMIT + 1);
        return new ProviderHttpEvidence(rows.isEmpty() ? "NOT_CAPTURED" : "HTTP_OBSERVED", rows.size() > LIMIT,
                List.copyOf(rows.subList(0, Math.min(rows.size(), LIMIT))));
    }
}
