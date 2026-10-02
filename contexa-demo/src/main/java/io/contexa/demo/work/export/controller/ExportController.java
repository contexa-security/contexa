package io.contexa.demo.work.export.controller;

import io.contexa.demo.work.export.dto.ExportDownloadResult;
import io.contexa.demo.work.export.dto.ExportInput;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;
import io.contexa.demo.work.export.dto.ExportResourceType;
import io.contexa.demo.work.export.dto.ExportTarget;
import io.contexa.demo.work.export.service.BusinessExporter;
import io.contexa.demo.work.export.service.ExportCatalog;
import io.contexa.demo.work.export.service.ExportRequestPreparation;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.request.web.BusinessContextAttributes;
import io.contexa.demo.work.shared.web.AbstractFileDownloadController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@Profile({"baseline", "contexa"})
@RequestMapping("/api/work/exports")
public class ExportController extends AbstractFileDownloadController {

    private final ExportCatalog catalog;
    private final ExportRequestPreparation preparation;
    private final BusinessExporter exporter;

    public ExportController(WorkParticipantQuery participants, ExportCatalog catalog,
            ExportRequestPreparation preparation, BusinessExporter exporter) {
        super(participants);
        this.catalog = catalog;
        this.preparation = preparation;
        this.exporter = exporter;
    }

    @GetMapping("/preview")
    public ResponseEntity<List<ExportTarget>> preview(@RequestParam ExportResourceType type,
            @RequestParam List<String> ids, HttpServletRequest request, Authentication authentication) {
        participant(request, authentication);
        return result(catalog.resolve(type, ids));
    }

    @PostMapping("/download")
    public ResponseEntity<byte[]> download(@Valid @RequestBody ExportInput input,
            HttpServletRequest request, Authentication authentication) {
        ExportRequestSnapshot snapshot = preparation.prepare(BusinessContextAttributes.requestId(request),
                participant(request, authentication), input);
        BusinessContextAttributes.attach(request, snapshot);
        ExportDownloadResult result = exporter.export(snapshot, input);
        return file(result.file(), result.contentType(), result.preparedItems(), result.reused());
    }
}
