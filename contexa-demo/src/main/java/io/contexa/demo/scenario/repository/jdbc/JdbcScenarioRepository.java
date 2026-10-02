package io.contexa.demo.scenario.repository.jdbc;

import io.contexa.demo.scenario.codec.ScenarioCodec;
import io.contexa.demo.scenario.dto.ScenarioDeclaration;
import io.contexa.demo.scenario.dto.ScenarioDefinition;
import io.contexa.demo.scenario.dto.ScenarioEvaluation;
import io.contexa.demo.scenario.dto.ScenarioOracle;
import io.contexa.demo.scenario.dto.ScenarioSummary;
import io.contexa.demo.scenario.dto.StoredScenario;
import io.contexa.demo.scenario.repository.ScenarioRepository;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;

import java.util.List;
import java.util.UUID;

@Repository
@Profile("portal")
public class JdbcScenarioRepository extends AbstractJsonJdbcRepository implements ScenarioRepository {

    private final TransactionOperations transactions;

    public JdbcScenarioRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc, ScenarioCodec codec,
            @Qualifier("applicationTransactions") TransactionOperations transactions) {
        super(jdbc, codec);
        this.transactions = transactions;
    }

    public void saveVersion(ScenarioDeclaration declaration) {
        String definition = documents.write(declaration.definition()), oracle = documents.write(declaration.oracle());
        String hash = documents.hash(definition + "\n" + oracle);
        transactions.executeWithoutResult(status -> {
            jdbc.update(
                    "insert into lab.scenario_version(id,scenario_key,version,definition,oracle,content_sha256) "
                            + "values(?,?,?,?::jsonb,?::jsonb,?) on conflict(scenario_key,version) do nothing",
                    UUID.randomUUID(), declaration.key(), declaration.version(), definition, oracle, hash);
            String existing = jdbc.queryForObject(
                    "select content_sha256 from lab.scenario_version where scenario_key=? and version=?", String.class,
                    declaration.key(), declaration.version());
            if (!hash.equals(existing)) {
                throw new IllegalStateException("Scenario changed without a new version: " + declaration.key());
            }
        });
    }

    public List<ScenarioSummary> list() {
        return jdbc.query(
                "select id,scenario_key,version,definition,content_sha256,created_at "
                        + "from lab.scenario_version order by scenario_key,version desc",
                (rs, n) -> new ScenarioSummary(rs.getObject("id", UUID.class), rs.getString("scenario_key"),
                        rs.getInt("version"),
                        documents.read(rs.getString("definition"), ScenarioDefinition.class).display(),
                        rs.getString("content_sha256"), rs.getTimestamp("created_at").toInstant()));
    }

    public StoredScenario find(UUID id) {
        return first(jdbc.query(
                "select id,scenario_key,version,definition,content_sha256,created_at from lab.scenario_version where id=?",
                (rs, n) -> new StoredScenario(rs.getObject("id", UUID.class), rs.getString("scenario_key"),
                        rs.getInt("version"),
                        documents.read(rs.getString("definition"), ScenarioDefinition.class),
                        rs.getString("content_sha256"), rs.getTimestamp("created_at").toInstant()), id));
    }

    public ScenarioEvaluation evaluation(UUID id) {
        return first(jdbc.query("select id,oracle,content_sha256 from lab.scenario_version where id=?",
                (rs, n) -> new ScenarioEvaluation(rs.getObject("id", UUID.class),
                        documents.read(rs.getString("oracle"), ScenarioOracle.class), rs.getString("content_sha256")),
                id));
    }
}
