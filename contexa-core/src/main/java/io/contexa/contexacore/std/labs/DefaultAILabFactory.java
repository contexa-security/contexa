package io.contexa.contexacore.std.labs;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Slf4j
public class DefaultAILabFactory implements AILabFactory {

    private final ApplicationContext applicationContext;

    @Autowired
    public DefaultAILabFactory(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public <T extends AILab<?, ?>> Optional<T> getLab(Class<T> labType) {
        try {
            T lab = applicationContext.getBean(labType);
            return Optional.of(lab);
        } catch (Exception e) {
            log.error("Lab not found: {}", labType.getSimpleName());
        }

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
        }
        return Optional.empty();
    }
}