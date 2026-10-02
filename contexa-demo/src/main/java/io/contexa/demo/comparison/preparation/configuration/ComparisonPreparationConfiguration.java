package io.contexa.demo.comparison.preparation.configuration;

import io.contexa.demo.comparison.preparation.source.ComparisonDocumentSource;
import io.contexa.demo.comparison.preparation.source.ComparisonCustomerSource;
import io.contexa.demo.comparison.preparation.source.impl.StoredComparisonCustomerSource;
import io.contexa.demo.comparison.preparation.source.impl.StoredComparisonDocumentSource;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.document.repository.jdbc.JdbcDocumentRepository;
import io.contexa.demo.work.customer.repository.jdbc.JdbcCustomerRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;

@Configuration(proxyBeanMethods = false)
@Profile("portal")
public class ComparisonPreparationConfiguration {

    @Bean
    ComparisonCustomerSource baselineComparisonCustomerSource(
            @Qualifier("baselineEvidenceJdbc") JdbcOperations jdbc, DocumentCodec documents) {
        return new StoredComparisonCustomerSource("baseline", new JdbcCustomerRepository(jdbc), documents);
    }

    @Bean
    ComparisonCustomerSource contexaComparisonCustomerSource(
            @Qualifier("contexaEvidenceJdbc") JdbcOperations jdbc, DocumentCodec documents) {
        return new StoredComparisonCustomerSource("contexa", new JdbcCustomerRepository(jdbc), documents);
    }

    @Bean
    ComparisonDocumentSource baselineComparisonDocumentSource(
            @Qualifier("baselineEvidenceJdbc") JdbcOperations jdbc, DocumentCodec documents) {
        return new StoredComparisonDocumentSource("baseline", new JdbcDocumentRepository(jdbc), documents);
    }

    @Bean
    ComparisonDocumentSource contexaComparisonDocumentSource(
            @Qualifier("contexaEvidenceJdbc") JdbcOperations jdbc, DocumentCodec documents) {
        return new StoredComparisonDocumentSource("contexa", new JdbcDocumentRepository(jdbc), documents);
    }
}
