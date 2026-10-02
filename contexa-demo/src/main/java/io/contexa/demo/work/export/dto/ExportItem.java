package io.contexa.demo.work.export.dto;

public record ExportItem(String resourceId, int version, String contentSha256, int contentBytes) {
}
