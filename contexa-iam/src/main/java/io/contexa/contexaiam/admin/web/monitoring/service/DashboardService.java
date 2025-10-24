package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexaiam.admin.web.monitoring.dto.DashboardDto;

/**
 * [최종 리팩토링] 관리자용 통합 대시보드에 필요한 모든 데이터를 조회하여
 * 단일 DTO로 반환하는 책임을 가집니다.
 */
public interface DashboardService {
    /**
     * 대시보드에 필요한 모든 데이터를 조회하여 단일 DTO로 반환합니다.
     * @return DashboardDto
     */
    DashboardDto getDashboardData();
}