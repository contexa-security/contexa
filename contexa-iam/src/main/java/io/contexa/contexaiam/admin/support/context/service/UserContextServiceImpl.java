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
package io.contexa.contexaiam.admin.support.context.service;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.admin.support.context.dto.RecentActivityDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class UserContextServiceImpl implements UserContextService {

    private final AuditLogRepository auditLogRepository;


    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<RecentActivityDto> getRecentActivities(String username) {
        return auditLogRepository.findTop5ByPrincipalNameOrderByIdDesc(username).stream()
                .map(log -> new RecentActivityDto(log.getAction(), log.getResourceIdentifier(), log.getTimestamp()))
                .collect(Collectors.toList());
    }
}