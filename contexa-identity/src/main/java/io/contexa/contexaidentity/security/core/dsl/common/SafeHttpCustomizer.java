package io.contexa.contexaidentity.security.core.dsl.common;

import org.springframework.security.config.Customizer;

@FunctionalInterface
public interface SafeHttpCustomizer<T> {

    void customize(T t) throws Exception;

    static <T> Customizer<T> withDefaults() {
        return (t) -> {
        };
    }
}
