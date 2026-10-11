package io.contexa.contexacore.repository.prompt;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceModelCompatibilityRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PromptGovernanceModelCompatibilityRepository extends JpaRepository<PromptGovernanceModelCompatibilityRecord, Long> {

    Optional<PromptGovernanceModelCompatibilityRecord> findFirstByRegistryScopeAndPromptKeyAndPromptVersionAndModelProfileKeyOrderByUpdatedAtDesc(
            String registryScope,
            String promptKey,
            String promptVersion,
            String modelProfileKey);

    List<PromptGovernanceModelCompatibilityRecord> findByRegistryScopeOrderByUpdatedAtDesc(String registryScope);

    List<PromptGovernanceModelCompatibilityRecord> findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
            String registryScope,
            String promptKey,
            String promptVersion);
}
