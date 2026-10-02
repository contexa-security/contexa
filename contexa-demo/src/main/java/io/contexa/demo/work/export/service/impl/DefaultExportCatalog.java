package io.contexa.demo.work.export.service.impl;

import io.contexa.demo.work.catalog.service.WorkCatalog;
import io.contexa.demo.work.customer.service.CustomerCatalog;
import io.contexa.demo.work.export.dto.ExportResourceType;
import io.contexa.demo.work.export.dto.ExportTarget;
import io.contexa.demo.work.export.service.ExportCatalog;
import io.contexa.demo.work.shared.dto.BusinessResourceFacts;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
@Profile({"baseline", "contexa"})
public class DefaultExportCatalog implements ExportCatalog {

    private final WorkCatalog documents;
    private final CustomerCatalog customers;

    public DefaultExportCatalog(WorkCatalog documents, CustomerCatalog customers) {
        this.documents = documents;
        this.customers = customers;
    }

    @Override
    public List<ExportTarget> resolve(ExportResourceType type, List<String> ids) {
        if (ids == null || ids.isEmpty() || ids.size() > 50 || ids.stream().distinct().count() != ids.size()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_EXPORT_SELECTION");
        }
        return ids.stream().sorted().map(id -> resolve(type, id)).toList();
    }

    private ExportTarget resolve(ExportResourceType type, String id) {
        if (type == ExportResourceType.DOCUMENT) {
            var document = documents.document(id);
            return new ExportTarget(new BusinessResourceFacts(document.id(), "DOCUMENT", document.title().en(),
                    document.sensitivity(), document.projectId(), document.version(), List.of("READ", "DOWNLOAD", "EXPORT")),
                    document.title());
        }
        var customer = customers.customer(id);
        return new ExportTarget(new BusinessResourceFacts(customer.id(), "CUSTOMER", customer.name().en(),
                customer.sensitivity(), customer.projectId(), customer.version(), List.of("READ", "EXPORT")),
                customer.name());
    }
}
