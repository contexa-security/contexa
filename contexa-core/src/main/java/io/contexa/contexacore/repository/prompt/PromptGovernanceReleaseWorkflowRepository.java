package io.contexa.contexacore.repository.prompt;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseWorkflowRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PromptGovernanceReleaseWorkflowRepository extends JpaRepository<PromptGovernanceReleaseWorkflowRecord, Long> {

    List<PromptGovernanceReleaseWorkflowRecord> findByRegistryScopeOrderByCreatedAtDesc(String registryScope);

    List<PromptGovernanceReleaseWorkflowRecord> findByRegistryScopeAndPromptKeyOrderByCreatedAtDesc(String registryScope, String promptKey);
}
