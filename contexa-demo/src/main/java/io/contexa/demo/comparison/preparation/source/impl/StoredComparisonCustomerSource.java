package io.contexa.demo.comparison.preparation.source.impl;

import io.contexa.demo.comparison.preparation.dto.ArmCustomerFingerprint;
import io.contexa.demo.comparison.preparation.source.ComparisonCustomerSource;
import io.contexa.demo.comparison.preparation.source.support.AbstractStoredComparisonSource;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.customer.dto.CustomerDetail;
import io.contexa.demo.work.customer.dto.CustomerSummary;
import io.contexa.demo.work.customer.repository.CustomerRepository;

public class StoredComparisonCustomerSource extends AbstractStoredComparisonSource<ArmCustomerFingerprint>
        implements ComparisonCustomerSource {

    private final CustomerRepository repository;

    public StoredComparisonCustomerSource(String arm, CustomerRepository repository, DocumentCodec documents) {
        super(arm, documents);
        this.repository = repository;
    }

    @Override
    protected ArmCustomerFingerprint read(String customerId) {
        CustomerSummary summary = repository.find(customerId);
        CustomerDetail detail = summary == null ? null : repository.read(customerId, summary.version());
        return detail == null ? null : new ArmCustomerFingerprint(arm, "CAPTURED", customerId,
                summary.version(), summary.projectId(), documents.hash(documents.write(detail)), summary.name());
    }

    @Override
    protected ArmCustomerFingerprint missing(String customerId, String state) {
        return new ArmCustomerFingerprint(arm, state, customerId, null, null, null, null);
    }
}
