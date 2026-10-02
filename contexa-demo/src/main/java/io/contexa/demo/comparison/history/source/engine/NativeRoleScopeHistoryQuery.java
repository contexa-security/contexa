package io.contexa.demo.comparison.history.source.engine;

import io.contexa.contexacore.autonomous.context.collector.RoleScopeCollector;
import io.contexa.demo.comparison.history.dto.RoleScopeHistorySnapshot;
import io.contexa.demo.comparison.history.source.RoleScopeHistoryQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.time.Instant;

@Component
@Profile("contexa")
public class NativeRoleScopeHistoryQuery implements RoleScopeHistoryQuery {

    private static final String BOUNDARY =
            "NATIVE_STORED_SCOPE_SEPARATE_READS_NO_TTL_REFRESH_EMPTY_LIST_NOT_ABSENCE_PROOF";

    private final RoleScopeCollector collector;
    private final DocumentCodec documents;

    public NativeRoleScopeHistoryQuery(RoleScopeCollector collector, DocumentCodec documents) {
        this.collector = collector;
        this.documents = documents;
    }

    @Override
    public RoleScopeHistorySnapshot capture(String tenantId, String username) {
        Instant start = Instant.now();
        try {
            var source = collector.inspectStoredHistory(tenantId, username);
            if (source == null) {
                return unavailable("UNAVAILABLE", start);
            }
            boolean observed = "API_RETURN_OBSERVED".equals(source.state());
            String state = observed && source.observations().size() >= source.scanLimit()
                    ? "SCAN_LIMIT_REACHED" : source.state();
            return new RoleScopeHistorySnapshot(state, start, Instant.now(),
                    hash(source.authorizationState()), hash(source.scopeKey()),
                    observed ? source.observations().size() : null, source.scanLimit(),
                    observed ? documents.hash(documents.write(source.observations())) : null, BOUNDARY);
        } catch (UnsupportedOperationException unsupported) {
            return unavailable("UNSUPPORTED", start);
        } catch (RuntimeException unavailable) {
            return unavailable("UNAVAILABLE", start);
        }
    }

    private RoleScopeHistorySnapshot unavailable(String state, Instant start) {
        return new RoleScopeHistorySnapshot(state, start, Instant.now(), null, null, null, null, null, BOUNDARY);
    }

    private String hash(String value) {
        return value == null ? null : documents.hash(value);
    }
}
