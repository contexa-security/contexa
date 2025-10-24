package io.contexa.contexaiam.repository;

import io.contexa.contexacommon.entity.behavior.BehaviorBasedPermission;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BehaviorBasedPermissionRepository extends JpaRepository<BehaviorBasedPermission, Long> {

    List<BehaviorBasedPermission> findByActiveTrue(Sort sort);

    List<BehaviorBasedPermission> findByApplicableTo(String applicableTo);
}
