package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.core.type.TypeReference;

import java.util.function.Supplier;


public interface ContexaCacheService {

    <T> T get(String key, Supplier<T> loader, TypeReference<T> typeRef, String domain);

    <T> void put(String key, T value, String domain);

    void invalidate(String key);

    void invalidateAll();

    void invalidateLocalOnly(String key);

    ContexaCacheProperties.CacheType getCacheType();
}
