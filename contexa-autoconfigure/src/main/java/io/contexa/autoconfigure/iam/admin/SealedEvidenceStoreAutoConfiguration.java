package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.evidence.JdbcSealedEvidencePackageRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcOperations;
import io.contexa.contexacore.verification.evidence.EvidenceSigner;
import org.springframework.beans.factory.ObjectProvider;

import java.time.Clock;
import java.time.Duration;

/**
 * The sealed evidence store, its integrity hashing and the canonical context serializer: what capture, retention and
 * the automatic prompt inspection round need, apart from the old official verification runtime (R4a). Enterprise
 * registers its own integrity and serializer first and uses this store.
 */
@AutoConfiguration(after = CoreDataAutoConfiguration.class,
        afterName = "io.contexa.autoconfigure.enterprise.iam.IamEnterpriseAutoConfiguration")
@ConditionalOnClass(JdbcSealedEvidencePackageRepository.class)
@EnableConfigurationProperties(PqaOssSealedEvidenceCaptureProperties.class)
public class SealedEvidenceStoreAutoConfiguration {

    @Bean(name = "contexaPqaSealedEvidencePackageIntegrity")
    @ConditionalOnMissingBean(SealedEvidencePackageIntegrity.class)
    public SealedEvidencePackageIntegrity pqaSealedEvidencePackageIntegrity(
            ObjectProvider<EvidenceSigner> evidenceSigner) {
        // docs/agent A5-6: a schema 3 package is signed and its signature checked.
        return new SealedEvidencePackageIntegrity(evidenceSigner.getIfAvailable());
    }

    @Bean(name = "contexaPqaSealedEvidencePackageRepository")
    @ConditionalOnMissingBean(SealedEvidencePackageRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public SealedEvidencePackageRepository pqaSealedEvidencePackageRepository(
            @Qualifier("contexaJdbcTemplate") JdbcOperations jdbcOperations,
            ObjectProvider<SealedEvidencePackageIntegrity> integrity,
            PqaOssSealedEvidenceCaptureProperties captureProperties) {
        JdbcSealedEvidencePackageRepository repository = new JdbcSealedEvidencePackageRepository(jdbcOperations);
        PqaOssSealedEvidenceCaptureProperties.Retention retention = captureProperties.getRetention();
        Duration keptAtLeast = retention.getCleanPeriod().compareTo(retention.getPeriod()) < 0
                ? retention.getCleanPeriod() : retention.getPeriod();
        integrity.ifAvailable(found -> {
            // docs/agent A5-6: a schema 3 package is linked after the package stored before it.
            repository.setIntegrity(found);
            // Q-21: the integrity reads what is kept around a package from the store it seals into.
            found.setChain(repository, keptAtLeast, Clock.systemUTC());
        });
        return repository;
    }

    @Bean(name = "contexaPqaCanonicalSecurityContextSerializer")
    @ConditionalOnMissingBean(CanonicalSecurityContextSerializer.class)
    public CanonicalSecurityContextSerializer pqaCanonicalSecurityContextSerializer(@Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        return new CanonicalSecurityContextSerializer(objectMapper);
    }
}
