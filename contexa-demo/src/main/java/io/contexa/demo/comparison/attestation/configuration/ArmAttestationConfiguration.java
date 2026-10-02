package io.contexa.demo.comparison.attestation.configuration;

import io.contexa.demo.comparison.preparation.source.ComparisonDocumentSource;
import io.contexa.demo.comparison.preparation.source.ComparisonCustomerSource;
import io.contexa.demo.comparison.preparation.source.impl.StoredComparisonCustomerSource;
import io.contexa.demo.comparison.preparation.source.impl.StoredComparisonDocumentSource;
import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.document.repository.DocumentRepository;
import io.contexa.demo.work.customer.repository.CustomerRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration(proxyBeanMethods = false)
@Profile({"baseline", "contexa"})
public class ArmAttestationConfiguration {

    @Bean
    ComparisonCustomerSource localComparisonCustomerSource(LabProperties properties,
            CustomerRepository repository, DocumentCodec documents) {
        return new StoredComparisonCustomerSource(properties.role(), repository, documents);
    }

    @Bean
    ComparisonDocumentSource localComparisonDocumentSource(LabProperties properties,
            DocumentRepository repository, DocumentCodec documents) {
        return new StoredComparisonDocumentSource(properties.role(), repository, documents);
    }
}
