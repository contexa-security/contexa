package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexaiam.admin.web.auth.controller.BlacklistApiController;
import io.contexa.contexaiam.admin.web.auth.controller.BlacklistController;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAdminBlacklistAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public BlockedUserService blockedUserService(
            BlockedUserJpaRepository blockedUserJpaRepository,
            AdminOverrideService adminOverrideService,
            ZeroTrustActionRedisRepository actionRedisRepository) {
        return new BlockedUserService(
                blockedUserJpaRepository, adminOverrideService, actionRedisRepository);
    }

    @Bean
    @ConditionalOnMissingBean(IBlockedUserRecorder.class)
    public IBlockedUserRecorder blockedUserRecorder(BlockedUserService blockedUserService) {
        return blockedUserService;
    }

    @Bean
    @ConditionalOnMissingBean
    public BlacklistController blacklistController(BlockedUserService blockedUserService) {
        return new BlacklistController(blockedUserService);
    }

    @Bean
    @ConditionalOnMissingBean
    public BlacklistApiController blacklistApiController(BlockedUserService blockedUserService) {
        return new BlacklistApiController(blockedUserService);
    }
}
