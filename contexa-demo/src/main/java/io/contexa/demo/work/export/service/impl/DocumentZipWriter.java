package io.contexa.demo.work.export.service.impl;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.document.dto.DocumentBody;
import io.contexa.demo.work.document.repository.DocumentRepository;
import io.contexa.demo.work.download.dto.DocumentLanguage;
import io.contexa.demo.work.export.dto.ExportContent;
import io.contexa.demo.work.export.dto.ExportItem;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;
import io.contexa.demo.work.export.dto.ExportResourceType;
import io.contexa.demo.work.export.dto.ExportTarget;
import io.contexa.demo.work.export.service.support.AbstractExportContentWriter;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Component
@Profile({"baseline", "contexa"})
public class DocumentZipWriter extends AbstractExportContentWriter {

    private final DocumentRepository repository;

    public DocumentZipWriter(DocumentRepository repository, DocumentCodec documents) {
        super(documents);
        this.repository = repository;
    }

    @Override
    public ExportResourceType resourceType() {
        return ExportResourceType.DOCUMENT;
    }

    @Override
    public ExportContent write(ExportRequestSnapshot snapshot, DocumentLanguage language) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        List<ExportItem> items = new ArrayList<>();
        int originalSize = 0;
        try (ZipOutputStream zip = new ZipOutputStream(bytes, StandardCharsets.UTF_8)) {
            for (ExportTarget target : snapshot.targets()) {
                DocumentBody body = repository.read(target.resource().id(), target.resource().version());
                if (body == null) {
                    throw new IllegalStateException("Fixed document version is unavailable");
                }
                byte[] content = text(body.content(), language).getBytes(StandardCharsets.UTF_8);
                originalSize += content.length;
                requireSize(originalSize);
                String filename = target.resource().id().replaceAll("[^a-zA-Z0-9-]", "_")
                        + "-v" + target.resource().version() + ".txt";
                add(zip, filename, content);
                items.add(item(target, content));
            }
            add(zip, "manifest.json", documents.write(items).getBytes(StandardCharsets.UTF_8));
        } catch (IOException failure) {
            throw new IllegalStateException("Document archive could not be prepared", failure);
        }
        requireSize(bytes.size());
        return new ExportContent("zip", "application/zip", bytes.toByteArray(), items);
    }

    private void add(ZipOutputStream zip, String filename, byte[] content) throws IOException {
        ZipEntry entry = new ZipEntry(filename);
        entry.setTime(0);
        zip.putNextEntry(entry);
        zip.write(content);
        zip.closeEntry();
    }
}
