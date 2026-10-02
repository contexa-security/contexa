package io.contexa.demo.readiness.repository.jdbc;

import io.contexa.demo.readiness.repository.DiagnosticRepository;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public class JdbcDiagnosticRepository extends AbstractJdbcRepository implements DiagnosticRepository {

    public JdbcDiagnosticRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    public Map<String, Object> database() {
        return jdbc.queryForMap("select current_database() as database,current_schema() as schema");
    }

    public List<Map<String, Object>> migrations() {
        return jdbc.queryForList(
                "select version,description,success from lab.flyway_schema_history where version is not null order by installed_rank");
    }

    public List<Map<String, Object>> identityScope() {
        return jdbc.queryForList(
                "select b.scope_key,s.id,s.content_sha256,s.account_count from lab.identity_scope_binding b "
                        + "join lab.identity_snapshot s on s.id=b.snapshot_id");
    }
}
