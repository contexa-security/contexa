package io.contexa.demo.work.export.service.support;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.download.dto.DocumentLanguage;
import io.contexa.demo.work.export.dto.ExportItem;
import io.contexa.demo.work.export.dto.ExportTarget;
import io.contexa.demo.work.export.service.ExportContentWriter;
import io.contexa.demo.work.shared.dto.WorkText;

public abstract class AbstractExportContentWriter implements ExportContentWriter {

    protected final DocumentCodec documents;

    protected AbstractExportContentWriter(DocumentCodec documents) {
        this.documents = documents;
    }

    protected String text(WorkText value, DocumentLanguage language) {
        return language == DocumentLanguage.KO ? value.ko() : value.en();
    }

    protected ExportItem item(ExportTarget target, byte[] content) {
        return new ExportItem(target.resource().id(), target.resource().version(), documents.hash(content), content.length);
    }

    protected void requireSize(int size) {
        if (size > 5 * 1024 * 1024) {
            throw new IllegalStateException("Export exceeds the bounded file size");
        }
    }
}
