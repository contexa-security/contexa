package io.contexa.contexacore.repository.prompt;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PromptGovernanceEvaluationRecordRepository extends JpaRepository<PromptGovernanceEvaluationRecord, Long> {

    Optional<PromptGovernanceEvaluationRecord> findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
            String registryScope,
            String promptKey,
            String promptVersion);

    Optional<PromptGovernanceEvaluationRecord> findFirstByEvaluationReferenceOrderByUpdatedAtDesc(String evaluationReference);

    List<PromptGovernanceEvaluationRecord> findByRegistryScopeOrderByUpdatedAtDesc(String registryScope);
}
