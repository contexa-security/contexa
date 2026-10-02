package io.contexa.demo.workspace.evidence.service;

import java.util.UUID;
import java.util.function.Supplier;

public interface WorkspaceEvidenceScope {

    <T> T withOwner(UUID visitorId, Supplier<T> query);

    String currentUrl(String role);
}
