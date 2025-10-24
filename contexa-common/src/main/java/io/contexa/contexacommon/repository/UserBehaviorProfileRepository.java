package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.behavior.UserBehaviorProfile;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UserBehaviorProfileRepository extends JpaRepository<UserBehaviorProfile, Long> {

    List<UserBehaviorProfile> findByUserId(String userId);

    List<UserBehaviorProfile> findByUserIdAndProfileType(String userId, String profileType);
}
