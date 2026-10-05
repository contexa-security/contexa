package io.contexa.showcase.workload.contexa.observation;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.ai.embedding.observation.EmbeddingModelObservationContext;

import java.time.Clock;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Measures the embedding calls of the vector store. A retrieval query of the engine carries {@code user: <userId>}
 * in its text, so it is attributed to that run principal; stored documents carry no user and are unattributed
 * (engine-spi 6).
 */
public class EmbeddingUsageMeter implements ObservationHandler<EmbeddingModelObservationContext> {

    private static final Pattern USER = Pattern.compile("user:\\s*(v[0-9a-f]{12}-[a-z0-9-]+)");

    private final UsageLedger ledger;
    private final Clock clock;

    public EmbeddingUsageMeter(UsageLedger ledger, Clock clock) {
        this.ledger = ledger;
        this.clock = clock;
    }

    @Override
    public boolean supportsContext(Observation.Context context) {
        return context instanceof EmbeddingModelObservationContext;
    }

    @Override
    public void onStop(EmbeddingModelObservationContext context) {
        EmbeddingResponse response = context.getResponse();
        long tokens = 0;
        if (response != null && response.getMetadata() != null && response.getMetadata().getUsage() != null) {
            Integer total = response.getMetadata().getUsage().getTotalTokens();
            tokens = total == null ? 0 : total;
        }
        String principal = null;
        List<String> inputs = context.getRequest() == null ? List.of() : context.getRequest().getInstructions();
        for (String input : inputs) {
            Matcher matcher = USER.matcher(input == null ? "" : input);
            if (matcher.find()) {
                principal = matcher.group(1);
                break;
            }
        }
        ledger.record(principal == null ? null : "user:" + principal, new UsageLedger.ModelCall("EMBEDDING",
                response == null || response.getMetadata() == null ? null : response.getMetadata().getModel(),
                tokens, 0, tokens, 0, response != null, clock.instant(), null, Set.of(), null));
    }
}
