package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.WizardSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface WizardSessionRepository extends JpaRepository<WizardSession, String> {
}
