package io.contexa.demo.work.shared.dto;

import java.time.Instant;
import java.util.UUID;

public record BusinessFile(
        UUID id,
        String inputSha256,
        String filename,
        String contentSha256,
        byte[] content,
        Instant preparedAt) {

    public BusinessFile {
        content = content.clone();
    }

    @Override
    public byte[] content() {
        return content.clone();
    }
}
