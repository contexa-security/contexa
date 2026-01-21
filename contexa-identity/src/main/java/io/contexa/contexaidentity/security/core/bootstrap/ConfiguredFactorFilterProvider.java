package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.mfa.context.FactorIdentifier;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class ConfiguredFactorFilterProvider {

    private final Map<FactorIdentifier, Filter> configuredFiltersByFactorId = new ConcurrentHashMap<>();

    public ConfiguredFactorFilterProvider() {
            }

    public void registerFilter(FactorIdentifier factorIdentifier, Filter filterInstance) {
        Objects.requireNonNull(factorIdentifier, "factorIdentifier cannot be null");
        Objects.requireNonNull(filterInstance, "filterInstance cannot be null");

        if (configuredFiltersByFactorId.containsKey(factorIdentifier)) {
            log.warn("Overwriting configured filter for FactorIdentifier: {}. Old: {}, New: {}",
                    factorIdentifier,
                    configuredFiltersByFactorId.get(factorIdentifier).getClass().getName(),
                    filterInstance.getClass().getName());
        }
        configuredFiltersByFactorId.put(factorIdentifier, filterInstance);
            }

    @Nullable
    public Filter getFilter(FactorIdentifier factorIdentifier) {
        Objects.requireNonNull(factorIdentifier, "factorIdentifier cannot be null");
        Filter filter = configuredFiltersByFactorId.get(factorIdentifier);
        if (filter == null) {
            log.warn("No configured filter found for FactorIdentifier: {}", factorIdentifier);
        } else {
                    }
        return filter;
    }

    public int getRegisteredFilterCount() {
        return configuredFiltersByFactorId.size();
    }
}
