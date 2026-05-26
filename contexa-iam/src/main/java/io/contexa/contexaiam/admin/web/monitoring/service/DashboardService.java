package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexaiam.admin.web.monitoring.dto.DashboardDto;

public interface DashboardService {

    default DashboardDto getDashboardData() {
        return getDashboardData(1);
    }

    DashboardDto getDashboardData(int days);
}