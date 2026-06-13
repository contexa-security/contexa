package io.contexa.contexacore.verification.runtime.longhorizon;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

@Transactional(transactionManager = "contexaTransactionManager")
public abstract class AbstractOfficialVerificationLongHorizonMetricExecutionService<
        R extends OfficialVerificationRunView,
        P,
        S,
        C extends OfficialVerificationCheckResultView,
        E extends OfficialVerificationEventItemView>
        extends AbstractOfficialVerificationMetricExecutionService<R>
        implements OfficialVerificationLongHorizonMetricExecutor<R> {

    protected record LongHorizonExecutionState<S, C extends OfficialVerificationCheckResultView, E extends OfficialVerificationEventItemView>(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int requestedRunCount,
            int horizonRounds,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request,
            String runId,
            int runOrdinal,
            Instant startedAt,
            Instant completedAt,
            long processingTimeMs,
            OfficialVerificationContractMetadataSupport.ContractStatus contractStatus,
            List<S> rounds,
            List<C> checks,
            List<E> aggregatedEvents,
            int passedChecks,
            int totalChecks,
            double score,
            boolean success
    ) {
    }

    protected AbstractOfficialVerificationLongHorizonMetricExecutionService(
            String notFoundMetricCode,
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            WebClient.Builder webClientBuilder,
            ObjectMapper objectMapper,
            Function<R, String> runIdExtractor,
            Function<R, String> startedAtExtractor
    ) {
        super(
                notFoundMetricCode,
                decisionOutboxRepository,
                promptAuditOutboxRepository,
                analysisEventStore,
                webClientBuilder,
                objectMapper,
                runIdExtractor,
                startedAtExtractor
        );
    }

    protected final synchronized R executeLongHorizonRunTemplate(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request,
            String runId,
            int runOrdinal
    ) {
        int horizonRounds = Math.max(minimumRounds(), requestedRunCount);
        Instant startedAt = Instant.now();
        List<P> roundPlans = buildRoundPlans(userId, endpointKey, resourceId, requestPath, horizonRounds);
        OfficialVerificationContractMetadataSupport.ContractStatus contractStatus = buildContractStatus(
                endpointKey,
                resourceId,
                requestPath,
                horizonRounds
        );
        List<S> rounds = new ArrayList<>(roundPlans.size());
        List<E> aggregatedEvents = new ArrayList<>();

        for (int roundIndex = 0; roundIndex < roundPlans.size(); roundIndex++) {
            P plan = roundPlans.get(roundIndex);
            if (roundIndex > 0) {
                sleep(interRoundDelayMs(plan));
            }
            S round = executeRound(
                    plan,
                    roundIndex,
                    horizonRounds,
                    contaminationSeed,
                    baselineSeedRequested,
                    request
            );
            rounds.add(round);
            aggregatedEvents.addAll(toEventItems(round));
        }

        List<C> checks = buildChecks(rounds);
        int totalChecks = checks.size();
        int passedChecks = (int) checks.stream().filter(OfficialVerificationCheckResultView::pass).count();
        double score = totalChecks == 0 ? 0.0d : (passedChecks * 100.0d) / totalChecks;
        boolean success = score >= successThreshold();
        Instant completedAt = Instant.now();
        LongHorizonExecutionState<S, C, E> state = new LongHorizonExecutionState<>(
                userId,
                endpointKey,
                resourceId,
                requestPath,
                requestedRunCount,
                horizonRounds,
                rerun,
                contaminationSeed,
                baselineSeedRequested,
                request,
                runId,
                runOrdinal,
                startedAt,
                completedAt,
                Math.max(0L, Duration.between(startedAt, completedAt).toMillis()),
                contractStatus,
                List.copyOf(rounds),
                List.copyOf(checks),
                List.copyOf(aggregatedEvents),
                passedChecks,
                totalChecks,
                score,
                success
        );
        R run = buildRunRecord(state);
        storeRun(userId, run);
        return run;
    }

    protected long successThreshold() {
        return 95L;
    }

    protected void sleep(long millis) {
        if (millis <= 0L) {
            return;
        }
        try {
            Thread.sleep(millis);
        }
        catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }

    protected long interRoundDelayMs(P plan) {
        return 0L;
    }

    protected abstract int minimumRounds();

    protected abstract OfficialVerificationContractMetadataSupport.ContractStatus buildContractStatus(
            String endpointKey,
            String resourceId,
            String requestPath,
            int horizonRounds
    );

    protected abstract List<P> buildRoundPlans(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int horizonRounds
    );

    protected abstract S executeRound(
            P plan,
            int roundIndex,
            int horizonRounds,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request
    );

    protected abstract List<E> toEventItems(S round);

    protected abstract List<C> buildChecks(List<S> rounds);

    protected abstract R buildRunRecord(LongHorizonExecutionState<S, C, E> state);
}