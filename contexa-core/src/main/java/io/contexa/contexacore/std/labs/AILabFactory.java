package io.contexa.contexacore.std.labs;

import java.util.Optional;

public interface AILabFactory {

    <T extends AILab<?, ?>> Optional<T> getLab(Class<T> labType);

    <T extends AILab<?, ?>> T createLab(Class<T> labType);

    Optional<AILab<?, ?>> getLabByClassName(String className);

    default boolean hasLab(Class<? extends AILab<?, ?>> labType) {
        return getLab(labType).isPresent();
    }

    default boolean hasLab(String className) {
        return getLabByClassName(className).isPresent();
    }
}
