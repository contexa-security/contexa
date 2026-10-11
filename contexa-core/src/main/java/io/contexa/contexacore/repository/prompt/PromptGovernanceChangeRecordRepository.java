package io.contexa.contexacore.repository.prompt;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceChangeRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PromptGovernanceChangeRecordRepository extends JpaRepository<PromptGovernanceChangeRecord, Long> {

    Optional<PromptGovernanceChangeRecord> findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
            String registryScope,
            String promptKey,
            String promptVersion);

    List<PromptGovernanceChangeRecord> findByRegistryScopeOrderByUpdatedAtDesc(String registryScope);
}
