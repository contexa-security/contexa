package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexaiam.admin.web.monitoring.dto.SecurityScoreDto;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component
@RequiredArgsConstructor
public class SecurityScoreCalculatorImpl implements SecurityScoreCalculator {

    private final UserRepository userRepository;

    @Override
    public SecurityScoreDto calculate() {
        long adminCount = userRepository.countByRoles("ADMIN");
        if (adminCount == 0) return new SecurityScoreDto(100, "관리자 계정이 없어 안전합니다.", Collections.emptyList());
        long mfaDisabledAdminCount = userRepository.countByMfaEnabledAndRoles(false, "ADMIN");
        double mfaAdminRate = (double)(adminCount - mfaDisabledAdminCount) / adminCount;
        int score = (int) (mfaAdminRate * 100);
        List<SecurityScoreDto.ScoreFactor> factors = List.of(
                new SecurityScoreDto.ScoreFactor("관리자 MFA 활성화율", (int)(mfaAdminRate*100), 1.0, "가장 중요한 보안 지표입니다.")
        );
        String summary = score >= 80 ? "시스템 보안이 양호합니다." : "보안 설정 강화가 필요합니다.";
        return new SecurityScoreDto(score, summary, factors);
    }
}
