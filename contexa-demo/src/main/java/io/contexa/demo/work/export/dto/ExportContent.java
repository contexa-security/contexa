package io.contexa.demo.work.export.dto;

import java.util.List;

public record ExportContent(String extension, String contentType, byte[] bytes, List<ExportItem> items) {

    public ExportContent {
        bytes = bytes.clone();
        items = List.copyOf(items);
    }

    @Override
    public byte[] bytes() {
        return bytes.clone();
    }
}
