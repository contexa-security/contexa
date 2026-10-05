package io.contexa.showcase.portal.replay;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Startup consistency check of the recordings (plan P2 step 3: checked at startup). A recording that is not consistent
 * with its execution specification and runs is never served; the operator API shows why and re-checks with the
 * engine's original decision records.
 */
public class ReplayGuard implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ReplayGuard.class);

    private final ReplayConsistency consistency;
    private final Set<String> blocked = ConcurrentHashMap.newKeySet();

    public ReplayGuard(ReplayConsistency consistency) {
        this.consistency = consistency;
    }

    @Override
    public void run(ApplicationArguments args) throws IOException {
        apply(consistency.check(null));
    }

    /** Replaces the set of blocked recordings with the inconsistent ones of the findings. */
    public void apply(List<ReplayConsistency.Finding> findings) {
        blocked.clear();
        for (ReplayConsistency.Finding finding : findings) {
            if (!finding.consistent()) {
                blocked.add(finding.recordId());
                log.error("Recording is inconsistent and is not served: recordId={}, problems={}", finding.recordId(),
                        finding.problems());
            }
        }
    }

    public boolean blocked(String recordId) {
        return blocked.contains(recordId);
    }
}
