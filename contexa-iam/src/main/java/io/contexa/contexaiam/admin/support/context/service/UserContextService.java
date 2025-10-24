package io.contexa.contexaiam.admin.support.context.service;

import io.contexa.contexaiam.admin.support.context.dto.RecentActivityDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;
import java.util.List;

public interface UserContextService {

    /**
     * [오류 수정] 마법사 진행 상태 저장 시, 소유자(ownerUserId)를 명확히 받도록 시그니처를 수정합니다.
     */
    void saveWizardProgress(String userSessionId, Long ownerUserId, WizardContext context);

    WizardContext getWizardProgress(String userSessionId);

    void clearWizardProgress(String userSessionId);

    List<RecentActivityDto> getRecentActivities(String username);
}