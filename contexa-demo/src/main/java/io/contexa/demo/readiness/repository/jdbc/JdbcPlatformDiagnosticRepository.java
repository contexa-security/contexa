package io.contexa.demo.readiness.repository.jdbc;

import io.contexa.demo.readiness.repository.PlatformDiagnosticRepository;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
@Profile("contexa")
public class JdbcPlatformDiagnosticRepository extends AbstractJdbcRepository implements PlatformDiagnosticRepository {

    public JdbcPlatformDiagnosticRepository(@Qualifier("contexaJdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    public Map<String, Object> database() {
        return jdbc.queryForMap("select current_database() as database");
    }

    public List<Map<String, Object>> vectorExtension() {
        return jdbc.queryForList("select extname,extversion from pg_extension where extname='vector'");
    }
}
