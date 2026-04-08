package io.contexa.contexacore.autonomous.saas.learning.registry;

import java.util.List;
import java.util.Optional;

/**
 * Storage abstraction for the latest state of tenant-scoped learning artifacts.
 */
public interface LearningArtifactRegistryStore {

    LearningArtifactRegistryEntry save(LearningArtifactRegistryEntry entry);

    Optional<LearningArtifactRegistryEntry> findCurrent(String tenantId, String artifactType, String artifactKey);

    List<LearningArtifactRegistryEntry> findCurrentByArtifact(String artifactType, String artifactKey);

    List<LearningArtifactRegistryEntry> findCurrentByTenant(String tenantId);
}