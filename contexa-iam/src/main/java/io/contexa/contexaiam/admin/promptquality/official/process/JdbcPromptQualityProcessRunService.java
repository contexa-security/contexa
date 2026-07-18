package io.contexa.contexaiam.admin.promptquality.official.process;

import java.util.Objects;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunStore.RunState;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunStore.StepHandle;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunStore.StepState;


import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessScope;

import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessCodes;

import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessEventSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessHistorySnapshot;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessStepSnapshot;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class JdbcPromptQualityProcessRunService implements PromptQualityProcessRunService {

    private static final int BUSINESS_KEY_LIMIT = 128;
    private static final int STATE_LIMIT = 32;
    private static final int STEP_CODE_LIMIT = 96;
    private static final int STATE_DIMENSION_LIMIT = 96;
    private static final int STATE_CODE_LIMIT = 128;
    private static final int TENANT_ID_LIMIT = 128;
    private static final int RESOURCE_ID_LIMIT = 500;
    private static final int RESOURCE_URL_LIMIT = 1000;
    private static final int HTTP_METHOD_LIMIT = 24;
    private static final int ACTOR_LIMIT = 128;
    private static final int EVENT_TYPE_LIMIT = 96;
    private static final int EVIDENCE_REF_LIMIT = 500;
    private static final int ROUTE_LIMIT = 1000;
    private static final int SUMMARY_LIMIT = 3000;

    private final PromptQualityProcessRunStore store;
    private final PromptQualityProcessRunQueryRepository queryRepository;

    public JdbcPromptQualityProcessRunService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        Objects.requireNonNull(objectMapper, "objectMapper");
        this.store = new PromptQualityProcessRunStore(jdbcTemplate, objectMapper);
        this.queryRepository = new PromptQualityProcessRunQueryRepository(jdbcTemplate);
    }
    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void startStep(
            PromptQualityProcessScope scope,
            String stepCode,
            String domainStateDimension,
            String domainStateCode,
            String evidenceRef,
            String route,
            String actor,
            String reason) {
        long runId = store.ensureRun(scope, actor);
        StepHandle step = store.ensureStepRun(runId, stepCode, actor);
        if (!store.sequentialTransitionAllowed(runId, stepCode)) {
            store.recordSequenceBlocked(runId, step.id(), stepCode, actor, reason);
            return;
        }
        StepState previous = step.created()
                ? new StepState(null, null, null)
                : store.stepState(step.id());
        boolean transitionChanged = changed(previous, PromptQualityProcessCodes.RUNNING, domainStateDimension, domainStateCode);
        store.updateRun(runId, PromptQualityProcessCodes.RUNNING, stepCode, domainStateDimension, domainStateCode, null);
        store.updateStep(
                step.id(),
                PromptQualityProcessCodes.RUNNING,
                domainStateDimension,
                domainStateCode,
                evidenceRef,
                route,
                null,
                null,
                null,
                null);
        if (transitionChanged) {
            store.recordHistory(runId, step.id(), stepCode, previous.executionState(), PromptQualityProcessCodes.RUNNING,
                    previous.domainStateDimension(), previous.domainStateCode(),
                    domainStateDimension, domainStateCode, evidenceRef, actor, reason);
            store.recordEvent(runId, step.id(), "STEP_STARTED",
                    store.eventPayload(stepCode, PromptQualityProcessCodes.RUNNING, domainStateDimension, domainStateCode,
                            evidenceRef, reason));
        }
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void completeStep(
            PromptQualityProcessScope scope,
            String stepCode,
            String domainStateDimension,
            String domainStateCode,
            String evidenceRef,
            String route,
            String summary,
            String nextAction,
            Map<String, Object> result,
            String actor,
            String reason) {
        long runId = store.ensureRun(scope, actor);
        StepHandle step = store.ensureStepRun(runId, stepCode, actor);
        if (!store.sequentialTransitionAllowed(runId, stepCode)) {
            store.recordSequenceBlocked(runId, step.id(), stepCode, actor, reason);
            return;
        }
        StepState previous = step.created()
                ? new StepState(null, null, null)
                : store.stepState(step.id());
        boolean transitionChanged = changed(previous, PromptQualityProcessCodes.COMPLETED, domainStateDimension, domainStateCode);
        boolean synthesizeStart = transitionChanged && shouldSynthesizeStart(previous);
        store.updateRun(runId, PromptQualityProcessCodes.RUNNING, stepCode, domainStateDimension, domainStateCode, null);
        if (synthesizeStart) {
            store.recordHistory(runId, step.id(), stepCode, previous.executionState(), PromptQualityProcessCodes.RUNNING,
                    previous.domainStateDimension(), previous.domainStateCode(), domainStateDimension, domainStateCode, evidenceRef, actor,
                    "Step process started before completion.");
            store.recordEvent(runId, step.id(), "STEP_STARTED",
                    store.eventPayload(stepCode, PromptQualityProcessCodes.RUNNING, domainStateDimension, domainStateCode,
                            evidenceRef, "Step process started before completion."));
        }
        StepState completionPrevious = synthesizeStart
                ? new StepState(PromptQualityProcessCodes.RUNNING, domainStateDimension, domainStateCode)
                : previous;
        store.updateStep(
                step.id(),
                PromptQualityProcessCodes.COMPLETED,
                domainStateDimension,
                domainStateCode,
                evidenceRef,
                route,
                summary,
                nextAction,
                store.json(result),
                null);
        if (transitionChanged) {
            store.recordHistory(runId, step.id(), stepCode, completionPrevious.executionState(), PromptQualityProcessCodes.COMPLETED,
                    completionPrevious.domainStateDimension(), completionPrevious.domainStateCode(),
                    domainStateDimension, domainStateCode, evidenceRef, actor, reason);
            store.recordEvent(runId, step.id(), "STEP_COMPLETED",
                    store.eventPayload(stepCode, PromptQualityProcessCodes.COMPLETED, domainStateDimension, domainStateCode,
                            evidenceRef, reason));
        }
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void failStep(
            PromptQualityProcessScope scope,
            String stepCode,
            String domainStateDimension,
            String domainStateCode,
            String evidenceRef,
            String route,
            String errorMessage,
            String actor,
            String reason) {
        long runId = store.ensureRun(scope, actor);
        StepHandle step = store.ensureStepRun(runId, stepCode, actor);
        if (!store.sequentialTransitionAllowed(runId, stepCode)) {
            store.recordSequenceBlocked(runId, step.id(), stepCode, actor, reason);
            return;
        }
        StepState previous = step.created()
                ? new StepState(null, null, null)
                : store.stepState(step.id());
        boolean transitionChanged = changed(previous, PromptQualityProcessCodes.FAILED, domainStateDimension, domainStateCode);
        boolean synthesizeStart = transitionChanged && shouldSynthesizeStart(previous);
        store.updateRun(runId, PromptQualityProcessCodes.RUNNING, stepCode, domainStateDimension, domainStateCode, errorMessage);
        if (synthesizeStart) {
            store.recordHistory(runId, step.id(), stepCode, previous.executionState(), PromptQualityProcessCodes.RUNNING,
                    previous.domainStateDimension(), previous.domainStateCode(), domainStateDimension, domainStateCode, evidenceRef, actor,
                    "Step process started before failure.");
            store.recordEvent(runId, step.id(), "STEP_STARTED",
                    store.eventPayload(stepCode, PromptQualityProcessCodes.RUNNING, domainStateDimension, domainStateCode,
                            evidenceRef, "Step process started before failure."));
        }
        StepState failurePrevious = synthesizeStart
                ? new StepState(PromptQualityProcessCodes.RUNNING, domainStateDimension, domainStateCode)
                : previous;
        store.updateStep(
                step.id(),
                PromptQualityProcessCodes.FAILED,
                domainStateDimension,
                domainStateCode,
                evidenceRef,
                route,
                errorMessage,
                null,
                null,
                errorMessage);
        if (transitionChanged) {
            store.recordHistory(runId, step.id(), stepCode, failurePrevious.executionState(), PromptQualityProcessCodes.FAILED,
                    failurePrevious.domainStateDimension(), failurePrevious.domainStateCode(),
                    domainStateDimension, domainStateCode, evidenceRef, actor, reason);
            store.recordEvent(runId, step.id(), "STEP_FAILED",
                    store.eventPayload(stepCode, PromptQualityProcessCodes.FAILED, domainStateDimension, domainStateCode,
                            evidenceRef, reason));
        }
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void completeMain(
            PromptQualityProcessScope scope,
            String domainStateDimension,
            String domainStateCode,
            String evidenceRef,
                String actor,
                String reason) {
        long runId = store.ensureRun(scope, actor);
        if (!store.allStepsCompleted(runId)) {
            store.recordSequenceBlocked(runId, null, PromptQualityProcessCodes.MAIN, actor, reason);
            return;
        }
        RunState previous = store.runState(runId);
        boolean transitionChanged = changed(previous, PromptQualityProcessCodes.COMPLETED, domainStateDimension, domainStateCode);
        store.updateRun(runId, PromptQualityProcessCodes.COMPLETED, PromptQualityProcessCodes.CERTIFICATES_PROMOTION,
                domainStateDimension, domainStateCode, null);
        if (transitionChanged) {
            store.recordHistory(runId, null, null, previous.executionState(), PromptQualityProcessCodes.COMPLETED,
                    previous.domainStateDimension(), previous.domainStateCode(),
                    domainStateDimension, domainStateCode, evidenceRef, actor, reason);
            store.recordEvent(runId, null, "PROCESS_COMPLETED",
                    store.eventPayload(PromptQualityProcessCodes.MAIN, PromptQualityProcessCodes.COMPLETED,
                            domainStateDimension, domainStateCode, evidenceRef, reason));
        }
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void recordEvent(
            PromptQualityProcessScope scope,
            String stepCode,
            String type,
            Map<String, Object> payload,
            String actor,
            String reason) {
        long runId = store.ensureRun(scope, actor);
        Long stepRunId = null;
        if (StringUtils.hasText(stepCode)) {
            stepRunId = store.ensureStepRun(runId, stepCode, actor).id();
        }
        Map<String, Object> eventPayload = new LinkedHashMap<>();
        if (payload != null) {
            eventPayload.putAll(payload);
        }
        eventPayload.putIfAbsent("stepCode", store.value(stepCode));
        eventPayload.putIfAbsent("reason", store.value(reason));
        eventPayload.putIfAbsent("actor", store.value(actor));
        store.recordEvent(runId, stepRunId, store.value(type), eventPayload);
    }

    @Override
    public List<PromptQualityProcessStepSnapshot> steps(PromptQualityProcessScope scope) {
        return queryRepository.steps(scope);
    }

    @Override
    public List<PromptQualityProcessHistorySnapshot> history(PromptQualityProcessScope scope) {
        return queryRepository.history(scope);
    }

    @Override
    public List<PromptQualityProcessEventSnapshot> events(PromptQualityProcessScope scope) {
        return queryRepository.events(scope);
    }
    private boolean changed(
            StepState previous,
            String executionState,
            String domainStateDimension,
            String domainStateCode) {
        return previous == null
                || !same(previous.executionState(), executionState)
                || !same(previous.domainStateDimension(), store.normalize(domainStateDimension))
                || !same(previous.domainStateCode(), store.normalize(domainStateCode));
    }

    private boolean changed(
            RunState previous,
            String executionState,
            String domainStateDimension,
            String domainStateCode) {
        return previous == null
                || !same(previous.executionState(), executionState)
                || !same(previous.domainStateDimension(), store.normalize(domainStateDimension))
                || !same(previous.domainStateCode(), store.normalize(domainStateCode));
    }

    private boolean same(String first, String second) {
        String left = store.value(first);
        String right = store.value(second);
        if (left == null) {
            return right == null;
        }
        return left.equalsIgnoreCase(right);
    }

    private boolean shouldSynthesizeStart(StepState previous) {
        return previous == null
                || (!same(previous.executionState(), PromptQualityProcessCodes.RUNNING)
                && !same(previous.executionState(), PromptQualityProcessCodes.COMPLETED)
                && !same(previous.executionState(), PromptQualityProcessCodes.FAILED));
    }

}
