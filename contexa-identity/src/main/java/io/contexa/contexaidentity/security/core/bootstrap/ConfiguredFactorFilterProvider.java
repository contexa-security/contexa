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
        log.info("ConfiguredFactorFilterProvider initialized.");
    }

    /**
     * 구성된 Factor 인증 필터를 등록합니다.
     * SecurityFilterChainRegistrar가 SecurityFilterChain 빌드 후 호출합니다.
     *
     * @param factorIdentifier 고유한 Factor 식별자 (flowName + stepId)
     * @param filterInstance   실제 구성된 Filter 인스턴스
     */
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
        log.debug("Registered configured filter for FactorIdentifier: {}, Filter: {}",
                factorIdentifier, filterInstance.getClass().getName());
    }

    /**
     * 주어진 FactorIdentifier에 해당하는 구성된 Filter 인스턴스를 반환합니다.
     * MfaStepFilterWrapper 에서 사용됩니다.
     *
     * @param factorIdentifier 조회할 Factor 식별자
     * @return 해당 Filter 인스턴스, 없으면 null
     */
    @Nullable
    public Filter getFilter(FactorIdentifier factorIdentifier) {
        Objects.requireNonNull(factorIdentifier, "factorIdentifier cannot be null");
        Filter filter = configuredFiltersByFactorId.get(factorIdentifier);
        if (filter == null) {
            log.warn("No configured filter found for FactorIdentifier: {}", factorIdentifier);
        } else {
            log.debug("Retrieved configured filter for FactorIdentifier: {}, Filter: {}",
                    factorIdentifier, filter.getClass().getName());
        }
        return filter;
    }

    public int getRegisteredFilterCount() {
        return configuredFiltersByFactorId.size();
    }
}
