package io.contexa.demo.observation.configuration;

import io.contexa.demo.workspace.evidence.persistence.GenerationEvidenceDataSource;
import io.contexa.demo.workspace.evidence.service.WorkspaceEvidenceScope;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;

import javax.sql.DataSource;

@Configuration(proxyBeanMethods = false)
@Profile("portal")
public class PortalEvidenceDataConfiguration extends AbstractEvidenceDataConfiguration {

    @Bean(name = "baselineEvidenceSource", destroyMethod = "close")
    DataSource baselineEvidenceSource(EvidenceStoreProperties properties, WorkspaceEvidenceScope scope) {
        return new GenerationEvidenceDataSource(source("baseline", properties.baselineUrl(), properties), scope, properties, "baseline");
    }

    @Bean(name = "contexaEvidenceSource", destroyMethod = "close")
    DataSource contexaEvidenceSource(EvidenceStoreProperties properties, WorkspaceEvidenceScope scope) {
        return new GenerationEvidenceDataSource(source("contexa", properties.contexaUrl(), properties), scope, properties, "contexa");
    }

    @Bean(name = "securityEvidenceSource", destroyMethod = "close")
    DataSource securityEvidenceSource(EvidenceStoreProperties properties, WorkspaceEvidenceScope scope) {
        return new GenerationEvidenceDataSource(source("security", properties.securityUrl(), properties), scope, properties, "security");
    }

    @Bean(name = "baselineEvidenceJdbc")
    JdbcOperations baselineEvidenceJdbc(@Qualifier("baselineEvidenceSource") DataSource source) {
        return jdbc(source);
    }

    @Bean(name = "contexaEvidenceJdbc")
    JdbcOperations contexaEvidenceJdbc(@Qualifier("contexaEvidenceSource") DataSource source) {
        return jdbc(source);
    }

    @Bean(name = "securityEvidenceJdbc")
    JdbcOperations securityEvidenceJdbc(@Qualifier("securityEvidenceSource") DataSource source) {
        return jdbc(source);
    }
}
