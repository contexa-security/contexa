package io.contexa.contexacore.repository.prompt;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PromptGovernanceRegistryRepository extends JpaRepository<PromptGovernanceRegistryRecord, Long> {

    Optional<PromptGovernanceRegistryRecord> findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
            String registryScope,
            String promptKey,
            String promptVersion);

    Optional<PromptGovernanceRegistryRecord> findFirstByRegistryScopeAndPromptKeyOrderByUpdatedAtDesc(
            String registryScope,
            String promptKey);

    List<PromptGovernanceRegistryRecord> findByRegistryScopeOrderByUpdatedAtDesc(String registryScope);

    List<PromptGovernanceRegistryRecord> findByRegistryScopeAndPromptKeyOrderByUpdatedAtDesc(String registryScope, String promptKey);
}
