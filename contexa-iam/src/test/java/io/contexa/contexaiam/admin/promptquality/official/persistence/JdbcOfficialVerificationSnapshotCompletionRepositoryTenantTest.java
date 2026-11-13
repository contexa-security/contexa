package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IAM-D28: a package stored without a tenant (sealed before the default tenant was written) is found under the
 * deployment default tenant, as it is verified; a package with its own tenant is found only under that tenant.
 */
class JdbcOfficialVerificationSnapshotCompletionRepositoryTenantTest {

    private PostgresTestDatabase database;
    private JdbcOfficialVerificationSnapshotCompletionRepository repository;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        JdbcTemplate jdbc = database.jdbcTemplate();
        jdbc.execute("create table ctxa_sealed_evidence_package (package_id varchar(160), tenant_id varchar(160))");
        jdbc.update("insert into ctxa_sealed_evidence_package values ('pkg-null', null), ('pkg-empty', ''),"
                + " ('pkg-a', 'tenant-a')");
        repository = new JdbcOfficialVerificationSnapshotCompletionRepository(jdbc);
    }

    @AfterEach
    void tearDown() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    void aPackageWithoutATenantIsFoundUnderTheDefaultTenantOnly() {
        assertThat(repository.sealedEvidencePackageExists("pkg-null", "default")).isTrue();
        assertThat(repository.sealedEvidencePackageExists("pkg-empty", "default")).isTrue();
        assertThat(repository.sealedEvidencePackageExists("pkg-null", "tenant-a")).isFalse();
        assertThat(repository.sealedEvidencePackageExists("pkg-a", "tenant-a")).isTrue();
        assertThat(repository.sealedEvidencePackageExists("pkg-a", "default")).isFalse();
    }
}
