package io.contexa.contexacore.verification.runtime.longhorizon;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import io.contexa.contexacore.verification.runtime.OfficialVerificationExecutionRequest;

import java.util.List;
import java.util.function.Function;

@Transactional(transactionManager = "contexaTransactionManager")
public abstract class AbstractOfficialVerificationPromptLongHorizonExecutionService<
        R extends OfficialVerificationRunView,
        S,
        C extends OfficialVerificationCheckResultView,
        E extends OfficialVerificationEventItemView>
        extends AbstractOfficialVerificationLongHorizonMetricExecutionService<
                R,
                OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan,
                S,
                C,
                E> {

    protected AbstractOfficialVerificationPromptLongHorizonExecutionService(
            String notFoundMetricCode,
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            OfficialVerificationProbeClient probeClient,
            ObjectMapper objectMapper,
            Function<R, String> runIdExtractor,
            Function<R, String> startedAtExtractor
    ) {
        super(
                notFoundMetricCode,
                decisionOutboxRepository,
                promptAuditOutboxRepository,
                analysisEventStore,
                probeClient,
                objectMapper,
                runIdExtractor,
                startedAtExtractor
        );
    }

    protected final synchronized R executeLongHorizonRunTemplate(
            String userId,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request,
            String runId,
            int runOrdinal
    ) {
        return super.executeLongHorizonRunTemplate(
                userId,
                null,
                null,
                null,
                requestedRunCount,
                rerun,
                contaminationSeed,
                baselineSeedRequested,
                request,
                runId,
                runOrdinal
        );
    }

    @Override
    protected final OfficialVerificationContractMetadataSupport.ContractStatus buildContractStatus(
            String endpointKey,
            String resourceId,
            String requestPath,
            int horizonRounds
    ) {
        return buildContractStatus(horizonRounds);
    }

    @Override
    protected final List<OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan> buildRoundPlans(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int horizonRounds
    ) {
        return buildRoundPlans(userId, horizonRounds);
    }

    protected abstract OfficialVerificationContractMetadataSupport.ContractStatus buildContractStatus(int horizonRounds);

    protected abstract List<OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan> buildRoundPlans(
            String userId,
            int horizonRounds
    );
}