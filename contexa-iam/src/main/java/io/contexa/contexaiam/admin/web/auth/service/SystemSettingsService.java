package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacommon.repository.SystemSettingsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
public class SystemSettingsService {

    private final SystemSettingsRepository repository;

    @Transactional(transactionManager = "contexaTransactionManager")
    public SystemSettings getSettings() {
        return repository.findAll().stream()
                .findFirst()
                .orElseGet(() -> repository.save(SystemSettings.builder().build()));
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public SystemSettings updateSettings(SystemSettings settings) {
        SystemSettings existing = getSettings();
        existing.setAuditLogRetentionDays(settings.getAuditLogRetentionDays());
        existing.setDefaultRole(settings.getDefaultRole());
        existing.setPolicyCombiningAlgorithm(settings.getPolicyCombiningAlgorithm());
        existing.setRegistrationEnabled(settings.isRegistrationEnabled());
        return repository.save(existing);
    }
}
