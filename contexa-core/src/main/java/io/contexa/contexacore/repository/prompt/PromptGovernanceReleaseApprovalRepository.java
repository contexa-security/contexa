package io.contexa.contexacore.repository.prompt;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseApprovalRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PromptGovernanceReleaseApprovalRepository extends JpaRepository<PromptGovernanceReleaseApprovalRecord, Long> {

    Optional<PromptGovernanceReleaseApprovalRecord> findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
            String registryScope,
            String promptKey,
            String templateKey,
            String promptVersion,
            String contractVersion);

    List<PromptGovernanceReleaseApprovalRecord> findByRegistryScopeOrderByUpdatedAtDesc(String registryScope);
}
