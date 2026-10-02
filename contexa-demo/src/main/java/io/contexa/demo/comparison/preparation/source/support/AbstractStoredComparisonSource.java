package io.contexa.demo.comparison.preparation.source.support;

import io.contexa.demo.comparison.preparation.dto.ComparisonResourceFingerprint;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.dao.DataAccessException;

public abstract class AbstractStoredComparisonSource<T extends ComparisonResourceFingerprint> {

    protected final String arm;
    protected final DocumentCodec documents;

    protected AbstractStoredComparisonSource(String arm, DocumentCodec documents) {
        this.arm = arm;
        this.documents = documents;
    }

    public final T capture(String resourceId) {
        try {
            T resource = read(resourceId);
            return resource == null ? missing(resourceId, "NOT_FOUND") : resource;
        } catch (DataAccessException unavailable) {
            return missing(resourceId, "UNAVAILABLE");
        }
    }

    protected abstract T read(String resourceId);

    protected abstract T missing(String resourceId, String state);
}
