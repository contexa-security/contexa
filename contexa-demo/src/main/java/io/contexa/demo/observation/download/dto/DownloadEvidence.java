package io.contexa.demo.observation.download.dto;

import java.time.Instant;
import java.util.UUID;

public record DownloadEvidence(
        UUID fileId,
        String filename,
        String contentSha256,
        int preparedBytes,
        String language,
        Instant filePreparedAt,
        boolean reused,
        int preparedItems) {
}
