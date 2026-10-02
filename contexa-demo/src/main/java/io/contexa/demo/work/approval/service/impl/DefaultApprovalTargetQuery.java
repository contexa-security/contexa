package io.contexa.demo.work.approval.service.impl;

import io.contexa.demo.work.approval.dto.ApprovalResourceType;
import io.contexa.demo.work.approval.dto.ApprovalTarget;
import io.contexa.demo.work.approval.service.ApprovalTargetQuery;
import io.contexa.demo.work.catalog.service.WorkCatalog;
import io.contexa.demo.work.customer.service.CustomerCatalog;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
@Profile({"baseline", "contexa"})
public class DefaultApprovalTargetQuery implements ApprovalTargetQuery {

    private final WorkCatalog documents;
    private final CustomerCatalog customers;

    public DefaultApprovalTargetQuery(WorkCatalog documents, CustomerCatalog customers) {
        this.documents = documents;
        this.customers = customers;
    }

    @Override
    public List<ApprovalTarget> resolve(ApprovalResourceType type, List<String> ids) {
        if (ids.stream().distinct().count() != ids.size()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "DUPLICATE_TARGET");
        }
        return ids.stream().sorted().map(id -> resolve(type, id)).toList();
    }

    private ApprovalTarget resolve(ApprovalResourceType type, String id) {
        if (type == ApprovalResourceType.DOCUMENT) {
            var document = documents.document(id);
            return new ApprovalTarget(document.id(), document.version(), document.projectId(), document.title());
        }
        var customer = customers.customer(id);
        return new ApprovalTarget(customer.id(), customer.version(), customer.projectId(), customer.name());
    }
}
