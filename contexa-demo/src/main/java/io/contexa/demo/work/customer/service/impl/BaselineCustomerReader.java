package io.contexa.demo.work.customer.service.impl;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.customer.dto.CustomerReadResult;
import io.contexa.demo.work.customer.dto.CustomerRequestSnapshot;
import io.contexa.demo.work.customer.repository.CustomerReadRepository;
import io.contexa.demo.work.customer.repository.CustomerRepository;
import io.contexa.demo.work.customer.service.support.AbstractCustomerReader;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile("baseline")
public class BaselineCustomerReader extends AbstractCustomerReader {

    public BaselineCustomerReader(CustomerRepository customers, CustomerReadRepository reads, DocumentCodec documents,
            ApprovalUsageQuery approvals) {
        super(customers, reads, documents, approvals);
    }

    @Override
    public CustomerReadResult read(CustomerRequestSnapshot snapshot) {
        return readCustomer(snapshot);
    }
}
