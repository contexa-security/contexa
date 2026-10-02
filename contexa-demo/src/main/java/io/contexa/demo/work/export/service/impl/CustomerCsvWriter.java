package io.contexa.demo.work.export.service.impl;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.customer.dto.CustomerDetail;
import io.contexa.demo.work.customer.repository.CustomerRepository;
import io.contexa.demo.work.download.dto.DocumentLanguage;
import io.contexa.demo.work.export.dto.ExportContent;
import io.contexa.demo.work.export.dto.ExportItem;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;
import io.contexa.demo.work.export.dto.ExportResourceType;
import io.contexa.demo.work.export.dto.ExportTarget;
import io.contexa.demo.work.export.service.support.AbstractExportContentWriter;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Profile({"baseline", "contexa"})
public class CustomerCsvWriter extends AbstractExportContentWriter {

    private final CustomerRepository repository;

    public CustomerCsvWriter(CustomerRepository repository, DocumentCodec documents) {
        super(documents);
        this.repository = repository;
    }

    @Override
    public ExportResourceType resourceType() {
        return ExportResourceType.CUSTOMER;
    }

    @Override
    public ExportContent write(ExportRequestSnapshot snapshot, DocumentLanguage language) {
        StringBuilder csv = new StringBuilder("\uFEFFid,version,project,name,industry,region,contact,email,service_plan\r\n");
        List<ExportItem> items = new ArrayList<>();
        int originalSize = 0;
        for (ExportTarget target : snapshot.targets()) {
            CustomerDetail detail = repository.read(target.resource().id(), target.resource().version());
            if (detail == null) {
                throw new IllegalStateException("Fixed customer version is unavailable");
            }
            var customer = detail.customer();
            String row = List.of(customer.id(), Integer.toString(customer.version()), customer.projectId(),
                    text(customer.name(), language), text(customer.industry(), language), text(customer.region(), language),
                    detail.contactName(), detail.contactEmail(), text(detail.servicePlan(), language)).stream()
                    .map(this::cell).collect(Collectors.joining(",")) + "\r\n";
            byte[] encoded = row.getBytes(StandardCharsets.UTF_8);
            originalSize += encoded.length;
            requireSize(originalSize);
            csv.append(row);
            items.add(item(target, encoded));
        }
        byte[] bytes = csv.toString().getBytes(StandardCharsets.UTF_8);
        requireSize(bytes.length);
        return new ExportContent("csv", "text/csv;charset=UTF-8", bytes, items);
    }

    private String cell(String value) {
        String safe = value;
        if (!safe.isEmpty() && "=+-@\t\r\n".indexOf(safe.charAt(0)) >= 0) {
            safe = "'" + safe;
        }
        return "\"" + safe.replace("\"", "\"\"") + "\"";
    }
}
