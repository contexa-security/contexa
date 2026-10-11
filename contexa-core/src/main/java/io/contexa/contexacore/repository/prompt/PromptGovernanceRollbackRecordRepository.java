package io.contexa.contexacore.repository.prompt;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRollbackRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PromptGovernanceRollbackRecordRepository extends JpaRepository<PromptGovernanceRollbackRecord, Long> {

    Optional<PromptGovernanceRollbackRecord> findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
            String registryScope,
            String promptKey,
            String promptVersion);

    List<PromptGovernanceRollbackRecord> findByRegistryScopeOrderByUpdatedAtDesc(String registryScope);
}
