package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexaiam.admin.web.monitoring.dto.SecurityScoreDto;

public interface SecurityScoreCalculator {
    SecurityScoreDto calculate();
}