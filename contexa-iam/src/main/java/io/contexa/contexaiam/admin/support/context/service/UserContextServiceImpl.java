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
    @Transactional(readOnly = true)
    public List<RecentActivityDto> getRecentActivities(String username) {
        return auditLogRepository.findTop5ByPrincipalNameOrderByIdDesc(username).stream()
                .map(log -> new RecentActivityDto(log.getAction(), log.getResourceIdentifier(), log.getTimestamp()))
                .collect(Collectors.toList());
    }
}