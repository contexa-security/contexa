package io.contexa.demo.work.customer.service.support;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.customer.dto.CustomerDetail;
import io.contexa.demo.work.customer.dto.CustomerReadResult;
import io.contexa.demo.work.customer.dto.CustomerRequestSnapshot;
import io.contexa.demo.work.customer.repository.CustomerReadRepository;
import io.contexa.demo.work.customer.repository.CustomerRepository;
import io.contexa.demo.work.customer.service.CustomerReader;
import io.contexa.demo.work.shared.service.support.AbstractBusinessOperation;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

public abstract class AbstractCustomerReader extends AbstractBusinessOperation implements CustomerReader {

    private final CustomerRepository customers;
    private final CustomerReadRepository reads;
    private final DocumentCodec documents;

    protected AbstractCustomerReader(CustomerRepository customers, CustomerReadRepository reads, DocumentCodec documents,
            ApprovalUsageQuery approvals) {
        super(approvals);
        this.customers = customers;
        this.reads = reads;
        this.documents = documents;
    }

    protected CustomerReadResult readCustomer(CustomerRequestSnapshot snapshot) {
        requireApproval(snapshot);
        CustomerDetail detail = customers.read(snapshot.customer().id(), snapshot.customer().version());
        if (detail == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        String content = documents.write(detail);
        CustomerReadResult result = new CustomerReadResult(snapshot.requestId(), detail, documents.hash(content),
                content.getBytes(StandardCharsets.UTF_8).length, Instant.now());
        reads.append(result);
        return result;
    }
}
