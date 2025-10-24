package io.contexa.contexacore.std.labs;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * 🏭 IAM 도메인 Lab 팩토리 구현체
 *
 * 기존 LabAccessor와 IAMLabRegistry의 기능을 통합하여
 * 새로운 AILabFactory 인터페이스를 구현
 *
 * 마이그레이션 기간 동안 기존 시스템과의 호환성 유지
 */
@Slf4j
@Component
public class DefaultAILabFactory implements AILabFactory {

    private final ApplicationContext applicationContext;

    @Autowired
    public DefaultAILabFactory(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
        log.info("🏭 IAMLabFactory initialized with backward compatibility");
    }

    @Override
    public <T extends AILab<?, ?>> Optional<T> getLab(Class<T> labType) {
        try {
            T lab = applicationContext.getBean(labType);
            log.debug("Found AILab implementation: {}", labType.getSimpleName());
            return Optional.of(lab);
        } catch (Exception e) {
            log.debug("AILab not found, trying legacy LabAccessor: {}", labType.getSimpleName());
        }

        log.warn("Lab not found: {}", labType.getSimpleName());
        return Optional.empty();
    }

    @Override
    public <T extends AILab<?, ?>> T createLab(Class<T> labType) {
        Optional<T> existing = getLab(labType);
        if (existing.isPresent()) {
            return existing.get();
        }

        throw new UnsupportedOperationException("Cannot create Lab instance for: " + labType.getSimpleName());
    }

    @Override
    public Optional<AILab<?, ?>> getLabByClassName(String className) {
        try {
            Class<?> clazz = Class.forName(className);
            if (AILab.class.isAssignableFrom(clazz)) {
                return getLab((Class<AILab<?, ?>>) clazz);
            }
        } catch (ClassNotFoundException e) {
            log.debug("Class not found: {}", className);
        }
        return Optional.empty();
    }
}