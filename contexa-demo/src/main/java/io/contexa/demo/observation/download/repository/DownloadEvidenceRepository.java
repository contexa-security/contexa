package io.contexa.demo.observation.download.repository;

import io.contexa.demo.observation.download.dto.DownloadEvidence;

import java.util.Optional;
import java.util.UUID;

public interface DownloadEvidenceRepository {

    Optional<DownloadEvidence> find(UUID requestId);
}
