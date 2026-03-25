package io.contexa.contexaiam.admin.support.context.service;

import io.contexa.contexaiam.admin.support.context.dto.RecentActivityDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.WizardContext;
import java.util.List;

public interface UserContextService {

    List<RecentActivityDto> getRecentActivities(String username);
}