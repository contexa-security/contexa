package io.contexa.showcase.portal.template;

import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Which template a run may clone now: the employee's READY template learned under the versions in force
 * ({@link TemplateVersions}). The current key is read from the workloads at most every 30 seconds. A template learned
 * under other versions (another commit, engine, mode, protection, model, time zone or company data) is never cloned,
 * so a recording or a live run never mixes a template with versions it was not learned under
 * (docs/showcase/계획대조-검수.md N-8).
 */
public class TemplateCurrency {

    static final Duration KEY_CACHE = Duration.ofSeconds(30);

    private final WorkloadAdmin admin;
    private final TemplateStore templates;
    private final Clock clock;
    private String cachedKey;
    private Instant cachedUntil = Instant.MIN;

    public TemplateCurrency(WorkloadAdmin admin, TemplateStore templates, Clock clock) {
        this.admin = admin;
        this.templates = templates;
        this.clock = clock;
    }

    /** The {@link TemplateVersions} key of the versions in force now. */
    public synchronized String currentKey() throws IOException {
        Instant now = clock.instant();
        if (cachedKey == null || !now.isBefore(cachedUntil)) {
            cachedKey = TemplateVersions.key(admin.engine(), admin.company());
            cachedUntil = now.plus(KEY_CACHE);
        }
        return cachedKey;
    }

    /** The employee's template that runs may clone now, if one was learned under the versions in force. */
    public Optional<TemplateStore.ReadyTemplate> current(String employeeKey) throws IOException {
        return templates.current(employeeKey, currentKey());
    }

    /** {@link #current} for callers that cannot handle a workload that is unreachable. */
    public Optional<TemplateStore.ReadyTemplate> currentOrFail(String employeeKey) {
        try {
            return current(employeeKey);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
