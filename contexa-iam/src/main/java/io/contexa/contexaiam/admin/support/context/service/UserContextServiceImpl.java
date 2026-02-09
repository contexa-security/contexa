package io.contexa.contexaiam.admin.support.context.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.support.context.dto.RecentActivityDto;
import io.contexa.contexaiam.domain.entity.WizardSession;
import io.contexa.contexaiam.repository.WizardSessionRepository;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.repository.WizardSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class UserContextServiceImpl implements UserContextService {

    private final AuditLogRepository auditLogRepository;
    private final WizardSessionRepository wizardSessionRepository;
    private final ObjectMapper objectMapper;

    @Override
    @Transactional
    public void saveWizardProgress(String userSessionId, String ownerUserId, WizardContext context) {
        try {
            String contextAsJson = objectMapper.writeValueAsString(context);
            WizardSession session = WizardSession.create(userSessionId, contextAsJson, ownerUserId, 60);
            wizardSessionRepository.save(session);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize WizardContext for session: {}", userSessionId, e);
            throw new RuntimeException("마법사 진행 상태 저장에 실패했습니다.", e);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public WizardContext getWizardProgress(String userSessionId) {
        WizardSession session = wizardSessionRepository.findById(userSessionId)
                .orElseThrow(() -> new IllegalStateException("Wizard session not found or expired for ID: " + userSessionId));

        try {
            return objectMapper.readValue(session.getContextData(), WizardContext.class);
        } catch (IOException e) {
            log.error("Failed to deserialize WizardContext for session: {}", userSessionId, e);
            throw new RuntimeException("마법사 진행 상태를 불러오는 데 실패했습니다.", e);
        }
    }

    @Override
    @Transactional
    public void clearWizardProgress(String userSessionId) {
        if (wizardSessionRepository.existsById(userSessionId)) {
            wizardSessionRepository.deleteById(userSessionId);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<RecentActivityDto> getRecentActivities(String username) {
        return auditLogRepository.findTop5ByPrincipalNameOrderByIdDesc(username).stream()
                .map(log -> new RecentActivityDto(log.getAction(), log.getResourceIdentifier(), log.getTimestamp()))
                .collect(Collectors.toList());
    }
}