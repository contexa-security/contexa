package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.PasswordPolicy;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PasswordPolicyRepository extends JpaRepository<PasswordPolicy, Long> {
}
