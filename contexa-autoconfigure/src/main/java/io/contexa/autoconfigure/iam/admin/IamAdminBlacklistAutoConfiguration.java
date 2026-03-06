package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexaiam.admin.web.auth.controller.BlacklistApiController;
import io.contexa.contexaiam.admin.web.auth.controller.BlacklistController;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import io.contexa.contexacommon.soar.event.SecurityActionEventPublisher;
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
            ZeroTrustActionRepository actionRedisRepository,
            SecurityActionEventPublisher securityActionEventPublisher) {
        return new BlockedUserService(
                blockedUserJpaRepository, adminOverrideService, actionRedisRepository, securityActionEventPublisher);
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
