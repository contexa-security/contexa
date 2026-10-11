package io.contexa.contexacore.repository.prompt;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceBudgetProfileRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PromptGovernanceBudgetProfileRepository extends JpaRepository<PromptGovernanceBudgetProfileRecord, Long> {

    Optional<PromptGovernanceBudgetProfileRecord> findFirstByRegistryScopeAndPromptKeyAndPromptVersionAndBudgetProfileKeyOrderByUpdatedAtDesc(
            String registryScope,
            String promptKey,
            String promptVersion,
            String budgetProfileKey);

    List<PromptGovernanceBudgetProfileRecord> findByRegistryScopeOrderByUpdatedAtDesc(String registryScope);

    List<PromptGovernanceBudgetProfileRecord> findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
            String registryScope,
            String promptKey,
            String promptVersion);
}
