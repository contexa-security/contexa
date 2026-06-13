package io.contexa.contexacore.verification.capture;

import java.util.Collection;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiConsumer;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class LazyDelegatingMap implements Map<String, Object> {
    private final CompletableFuture<Map<String, Object>> future;
    private volatile Map<String, Object> resolvedMap;

    public LazyDelegatingMap(CompletableFuture<Map<String, Object>> future) {
        // 예외가 발생하더라도 CompletionException으로 전체 호출부가 깨지는 것을 방지
        this.future = future.exceptionally(ex -> {
            Map<String, Object> errMap = new HashMap<>();
            errMap.put("error", "Failed to resolve metadata asynchronously");
            errMap.put("errorMessage", ex.getMessage());
            return errMap;
        });
    }

    private Map<String, Object> getDelegate() {
        if (resolvedMap == null) {
            synchronized (this) {
                if (resolvedMap == null) {
                    resolvedMap = future.join();
                }
            }
        }
        return resolvedMap;
    }

    @Override
    public int size() {
        return getDelegate().size();
    }

    @Override
    public boolean isEmpty() {
        return getDelegate().isEmpty();
    }

    @Override
    public boolean containsKey(Object key) {
        return getDelegate().containsKey(key);
    }

    @Override
    public boolean containsValue(Object value) {
        return getDelegate().containsValue(value);
    }

    @Override
    public Object get(Object key) {
        return getDelegate().get(key);
    }

    @Override
    public Object put(String key, Object value) {
        throw new UnsupportedOperationException("LazyDelegatingMap is immutable");
    }

    @Override
    public Object remove(Object key) {
        throw new UnsupportedOperationException("LazyDelegatingMap is immutable");
    }

    @Override
    public void putAll(Map<? extends String, ?> m) {
        throw new UnsupportedOperationException("LazyDelegatingMap is immutable");
    }

    @Override
    public void clear() {
        throw new UnsupportedOperationException("LazyDelegatingMap is immutable");
    }

    @Override
    public Set<String> keySet() {
        return getDelegate().keySet();
    }

    @Override
    public Collection<Object> values() {
        return getDelegate().values();
    }

    @Override
    public Set<Entry<String, Object>> entrySet() {
        return getDelegate().entrySet();
    }

    @Override
    public Object getOrDefault(Object key, Object defaultValue) {
        return getDelegate().getOrDefault(key, defaultValue);
    }

    @Override
    public void forEach(BiConsumer<? super String, ? super Object> action) {
        getDelegate().forEach(action);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (o instanceof Map<?, ?> otherMap) {
            return getDelegate().equals(otherMap);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return getDelegate().hashCode();
    }

    @Override
    public String toString() {
        return getDelegate().toString();
    }
}
