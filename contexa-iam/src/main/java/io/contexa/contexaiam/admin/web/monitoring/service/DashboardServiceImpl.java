package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexaiam.admin.web.monitoring.dto.DashboardDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.RiskIndicatorDto;
import io.contexa.contexaiam.admin.support.context.service.UserContextService;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

@RequiredArgsConstructor
public class DashboardServiceImpl implements DashboardService {

    private final UserRepository userRepository;
    private final UserContextService userContextService;
    private final SecurityScoreCalculator securityScoreCalculator;
    private final PermissionMatrixService permissionMatrixService;

    /**
     * [최종 구현] 대시보드에 필요한 모든 데이터를 각 서비스와 리포지토리에서 취합하여
     * 최종 DashboardDto를 구성합니다.
     */
    @Override
    @Transactional(readOnly = true)
    public DashboardDto getDashboardData() {
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();

        return new DashboardDto(
                userRepository.count(),
                ThreadLocalRandom.current().nextLong(10, 51), // 활성 세션은 임시 랜덤값
                userRepository.countByMfaEnabled(false),
                userRepository.findAdminsWithMfaDisabled().size(),
                userContextService.getRecentActivities(currentUsername),
                analyzeRiskIndicators(),
                securityScoreCalculator.calculate(),
                permissionMatrixService.getPermissionMatrix(null)
        );
    }

    private List<RiskIndicatorDto> analyzeRiskIndicators() {
        List<RiskIndicatorDto> risks = new ArrayList<>();
        long mfaDisabledAdmins = userRepository.findAdminsWithMfaDisabled().size();
        if (mfaDisabledAdmins > 0) {
            risks.add(new RiskIndicatorDto("CRITICAL", "MFA 미사용 관리자 계정 발견",
                    mfaDisabledAdmins + "명의 관리자 계정에 2단계 인증(MFA)이 설정되지 않아 탈취 위험이 높습니다.", "/admin/users"));
        }
        return risks;
    }
}