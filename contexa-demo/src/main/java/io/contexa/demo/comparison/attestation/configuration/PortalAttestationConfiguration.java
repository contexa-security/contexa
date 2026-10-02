package io.contexa.demo.comparison.attestation.configuration;

import io.contexa.demo.comparison.attestation.source.ArmAttestationQuery;
import io.contexa.demo.comparison.attestation.source.jdbc.JdbcArmAttestationQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;

@Configuration(proxyBeanMethods = false)
@Profile("portal")
public class PortalAttestationConfiguration {

    @Bean
    ArmAttestationQuery baselineAttestationQuery(@Qualifier("baselineEvidenceJdbc") JdbcOperations jdbc,
            DocumentCodec documents) {
        return new JdbcArmAttestationQuery("baseline", jdbc, documents);
    }

    @Bean
    ArmAttestationQuery contexaAttestationQuery(@Qualifier("contexaEvidenceJdbc") JdbcOperations jdbc,
            DocumentCodec documents) {
        return new JdbcArmAttestationQuery("contexa", jdbc, documents);
    }
}
