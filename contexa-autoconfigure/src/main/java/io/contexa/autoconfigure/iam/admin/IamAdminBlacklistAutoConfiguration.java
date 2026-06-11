/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexaiam.admin.web.auth.controller.BlacklistApiController;
import io.contexa.contexaiam.admin.web.auth.controller.BlacklistController;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import io.contexa.contexacommon.soar.event.SecurityActionEventPublisher;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAdminBlacklistAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public BlockedUserService blockedUserService(
            BlockedUserJpaRepository blockedUserJpaRepository,
            AdminOverrideService adminOverrideService,
            ZeroTrustActionRepository actionRedisRepository,
            ApplicationEventPublisher eventPublisher,
            CentralAuditFacade centralAuditFacade,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            MessageSource messageSource) {
        return new BlockedUserService(
                blockedUserJpaRepository, adminOverrideService, actionRedisRepository,
                eventPublisher, centralAuditFacade, blockingDecisionRegistry, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean(IBlockedUserRecorder.class)
    public IBlockedUserRecorder blockedUserRecorder(BlockedUserService blockedUserService) {
        return blockedUserService;
    }

    @Bean
    @ConditionalOnMissingBean
    public BlacklistController blacklistController(BlockedUserService blockedUserService, BlockedUserJpaRepository blockedUserJpaRepository, MessageSource messageSource) {
        return new BlacklistController(blockedUserService, blockedUserJpaRepository, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public BlacklistApiController blacklistApiController(BlockedUserService blockedUserService, MessageSource messageSource) {
        return new BlacklistApiController(blockedUserService, messageSource);
    }
}

