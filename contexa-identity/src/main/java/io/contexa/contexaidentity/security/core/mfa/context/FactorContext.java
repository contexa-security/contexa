package io.contexa.contexaidentity.security.core.mfa.context;

import io.contexa.contexaidentity.domain.dto.UserDto;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

@Getter
@Slf4j
@Setter
public class FactorContext implements FactorContextExtensions,Serializable{

    private String mfaSessionId;
    private AtomicReference<MfaState> currentMfaState;
    private final AtomicInteger version = new AtomicInteger(0);

    // 읽기 전용 플래그 (Single Source of Truth 패턴)
    private boolean readOnly = false;

    // 동시성 제어를 위한 ReadWriteLock 추가
    private transient ReadWriteLock stateLock;
    private transient ReadWriteLock factorsLock;

    private Authentication primaryAuthentication;
    private String username;
    private volatile int retryCount = 0;
    private volatile String lastError;
    private final long createdAt = System.currentTimeMillis();

    private volatile String flowTypeName;
    private volatile AuthType currentProcessingFactor;
    private volatile String currentStepId;
    private volatile boolean mfaRequiredAsPerPolicy = false;

    private final List<AuthenticationStepConfig> completedFactors = new CopyOnWriteArrayList<>();
    private final Map<String, Integer> failedAttempts = new ConcurrentHashMap<>();
    private volatile Instant lastActivityTimestamp;
    private final Map<AuthType, Integer> factorAttemptCounts = new ConcurrentHashMap<>();
    private final List<MfaAttemptDetail> mfaAttemptHistory = new CopyOnWriteArrayList<>();
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();

    public FactorContext() {
        this.stateLock = new ReentrantReadWriteLock();
        this.factorsLock = new ReentrantReadWriteLock();
    }

    public FactorContext(String mfaSessionId, Authentication primaryAuthentication, MfaState initialState, @Nullable String flowTypeName) {
        Assert.hasText(mfaSessionId, "mfaSessionId cannot be empty");
        Assert.notNull(primaryAuthentication, "primaryAuthentication cannot be null");
        Assert.notNull(initialState, "initialState cannot be null");

        this.mfaSessionId = mfaSessionId;
        this.primaryAuthentication = primaryAuthentication;
        this.username = ((UserDto)primaryAuthentication.getPrincipal()).getUsername();
        this.currentMfaState = new AtomicReference<>(initialState);
        this.flowTypeName = flowTypeName;
        this.lastActivityTimestamp = Instant.now();
        this.stateLock = new ReentrantReadWriteLock();
        this.factorsLock = new ReentrantReadWriteLock();

        log.debug("FactorContext (ID: {}) created for user '{}' with initial state: {}. Flow type: {}",
                mfaSessionId, this.username, initialState, flowTypeName);
    }

    public MfaState getCurrentState() {
        return this.currentMfaState.get();
    }

    /**
     * 상태 변경 - 동시성 안전 보장
     * Single Source of Truth 패턴: State Machine을 통해서만 상태 변경 권장
     *
     * <p>
     * <strong>Phase 5 개선:</strong> 버전 관리는 MfaStateMachineService에서 단독으로 수행합니다.
     * 이 메서드는 상태 변경만 담당하며, 버전 증가는 수행하지 않습니다.
     * </p>
     */
    public void changeState(MfaState newState) {
        if (readOnly) {
            throw new IllegalStateException(
                "FactorContext is read-only. Use MfaStateMachineIntegrator to change state through State Machine."
            );
        }

        stateLock.writeLock().lock();
        try {
            MfaState previousState = this.currentMfaState.getAndSet(newState);
            if (previousState != newState) {
                // Phase 5: 버전 자동 증가 제거 - MfaStateMachineService에서 명시적으로 관리
                log.info("FactorContext (ID: {}) state changed from {} to {} for user '{}'. Version: {} (버전 증가는 MfaStateMachineService에서 수행)",
                        mfaSessionId, previousState, newState, this.username, this.version.get());
                updateLastActivityTimestamp();
            }
        } finally {
            stateLock.writeLock().unlock();
        }
    }

    /**
     * 버전 증가 - 스레드 안전
     * @return 증가된 버전 번호
     */
    public int incrementVersion() {
        int newVersion = this.version.incrementAndGet();
        log.debug("FactorContext (ID: {}) version incremented to {} for user '{}'",
                mfaSessionId, newVersion, this.username);
        updateLastActivityTimestamp();
        return newVersion;
    }

    /**
     * 현재 버전 조회 - 스레드 안전
     * @return 현재 버전 번호
     */
    public int getVersion() {
        return this.version.get();
    }

    /**
     * 버전을 특정 값으로 설정 (테스트 또는 복원 시 사용)
     * @param newVersion 설정할 버전 번호
     */
    public void setVersion(int newVersion) {
        if (newVersion < 0) {
            throw new IllegalArgumentException("Version cannot be negative");
        }
        int oldVersion = this.version.getAndSet(newVersion);
        if (oldVersion != newVersion) {
            log.debug("FactorContext (ID: {}) version set from {} to {} for user '{}'",
                    mfaSessionId, oldVersion, newVersion, this.username);
            updateLastActivityTimestamp();
        }
    }

    /**
     * 버전을 원자적으로 비교하고 설정
     * @param expectedVersion 예상 버전
     * @param newVersion 새 버전
     * @return 성공 여부
     */
    public boolean compareAndSetVersion(int expectedVersion, int newVersion) {
        boolean success = this.version.compareAndSet(expectedVersion, newVersion);
        if (success) {
            log.debug("FactorContext (ID: {}) version CAS succeeded: {} -> {} for user '{}'",
                    mfaSessionId, expectedVersion, newVersion, this.username);
            updateLastActivityTimestamp();
        } else {
            log.debug("FactorContext (ID: {}) version CAS failed: expected {} but was {} for user '{}'",
                    mfaSessionId, expectedVersion, this.version.get(), this.username);
        }
        return success;
    }

    /**
     * 완료된 팩터 추가 - 개선된 동시성 제어
     */
    public void addCompletedFactor(AuthenticationStepConfig completedFactor) {
        if (readOnly) {
            throw new IllegalStateException(
                "FactorContext is read-only. Cannot add completed factors."
            );
        }

        Assert.notNull(completedFactor, "completedFactor cannot be null");

        factorsLock.writeLock().lock();
        try {
            boolean alreadyExists = this.completedFactors.stream()
                    .anyMatch(step -> step.getStepId().equals(completedFactor.getStepId()));

            if (!alreadyExists) {
                this.completedFactors.add(completedFactor);
                // Phase 1.1: 버전 증가는 MfaStateMachineService에서만 수행
                log.debug("FactorContext (ID: {}): Factor '{}' (StepId: {}) marked as completed for user {}. Total completed: {}",
                        mfaSessionId, completedFactor.getType(), completedFactor.getStepId(), this.username, this.completedFactors.size());
                updateLastActivityTimestamp();
            } else {
                log.debug("FactorContext (ID: {}): Factor '{}' (StepId: {}) already completed for user {}. Not adding again.",
                        mfaSessionId, completedFactor.getType(), completedFactor.getStepId(), this.username);
            }
        } finally {
            factorsLock.writeLock().unlock();
        }
    }

    public int getNumberOfCompletedFactors() {
        factorsLock.readLock().lock();
        try {
            return this.completedFactors.size();
        } finally {
            factorsLock.readLock().unlock();
        }
    }

    public int getLastCompletedFactorOrder() {
        factorsLock.readLock().lock();
        try {
            if (completedFactors.isEmpty()) {
                log.debug("FactorContext for user '{}': No completed factors, returning order 0.", username);
                return 0;
            }

            int maxOrder = completedFactors.stream()
                    .mapToInt(AuthenticationStepConfig::getOrder)
                    .max()
                    .orElse(0);

            log.debug("FactorContext for user '{}': Last completed factor order is {}.", username, maxOrder);
            return maxOrder;
        } finally {
            factorsLock.readLock().unlock();
        }
    }

    public int incrementAttemptCount(@Nullable AuthType factorType) {
        if (factorType == null) {
            log.warn("FactorContext (ID: {}): Attempted to increment attempt count for a null factorType for user {}.",
                    mfaSessionId, this.username);
            return 0;
        }

        int newCount = factorAttemptCounts.compute(factorType, (key, val) -> (val == null) ? 1 : val + 1);
        updateLastActivityTimestamp();
        // Phase 1.1: 버전 증가는 MfaStateMachineService에서만 수행

        log.debug("FactorContext (ID: {}): Attempt count for {} incremented to {} for user {}.",
                mfaSessionId, factorType, newCount, this.username);
        return newCount;
    }

    public int getAttemptCount(@Nullable AuthType factorType) {
        if (factorType == null) return 0;
        return factorAttemptCounts.getOrDefault(factorType, 0);
    }

    public void recordAttempt(@Nullable AuthType factorType, boolean success, String detail) {
        this.mfaAttemptHistory.add(new MfaAttemptDetail(factorType, success, detail));
        updateLastActivityTimestamp();
        // Phase 1.1: 버전 증가는 MfaStateMachineService에서만 수행
        log.info("FactorContext (ID: {}): MFA attempt recorded: Factor={}, Success={}, Detail='{}' for user {}",
                mfaSessionId, factorType, success, detail, this.username);
    }

    public int incrementFailedAttempts(String factorTypeOrStepId) {
        Assert.hasText(factorTypeOrStepId, "factorTypeOrStepId cannot be empty");

        int attempts = this.failedAttempts.compute(factorTypeOrStepId,
                (key, currentAttempts) -> (currentAttempts == null) ? 1 : currentAttempts + 1);

        log.debug("FactorContext (ID: {}): Failed attempt for factor/step '{}' incremented to {}. User: {}",
                mfaSessionId, factorTypeOrStepId, attempts, this.username);
        updateLastActivityTimestamp();
        // Phase 1.1: 버전 증가는 MfaStateMachineService에서만 수행
        return attempts;
    }

    public int getFailedAttempts(String factorTypeOrStepId) {
        return this.failedAttempts.getOrDefault(factorTypeOrStepId, 0);
    }

    public void resetFailedAttempts(String factorTypeOrStepId) {
        this.failedAttempts.remove(factorTypeOrStepId);
        log.debug("FactorContext (ID: {}): Failed attempts for factor/step '{}' reset. User: {}",
                mfaSessionId, factorTypeOrStepId, this.username);
        updateLastActivityTimestamp();
        // Phase 1.1: 버전 증가는 MfaStateMachineService에서만 수행
    }

    public void resetAllFailedAttempts() {
        this.failedAttempts.clear();
        log.debug("FactorContext (ID: {}): All failed attempts reset. User: {}", mfaSessionId, this.username);
        updateLastActivityTimestamp();
        // Phase 1.1: 버전 증가는 MfaStateMachineService에서만 수행
    }

    public void setAttribute(String name, Object value) {
        if (readOnly) {
            throw new IllegalStateException(
                "FactorContext is read-only. Cannot modify attributes."
            );
        }
        this.attributes.put(name, value);
        // Phase 1.1: 버전 증가는 MfaStateMachineService에서만 수행
    }

    @Nullable
    public Object getAttribute(String name) {
        return this.attributes.get(name);
    }

    public void removeAttribute(String name) {
        if (readOnly) {
            throw new IllegalStateException(
                "FactorContext is read-only. Cannot remove attributes."
            );
        }
        this.attributes.remove(name);
        // Phase 1.1: 버전 증가는 MfaStateMachineService에서만 수행
    }

    public boolean isFullyAuthenticated() {
        return MfaState.ALL_FACTORS_COMPLETED == this.currentMfaState.get() ||
                MfaState.MFA_SUCCESSFUL == this.currentMfaState.get();
    }

    public void updateLastActivityTimestamp() {
        this.lastActivityTimestamp = Instant.now();
        log.trace("FactorContext (ID: {}) lastActivityTimestamp updated to: {} for user {}",
                mfaSessionId, this.lastActivityTimestamp, this.username);
    }

    @Override
    public int getRetryCount() {
        return this.retryCount;
    }

    /**
     * DSL에서 정의된 사용 가능한 팩터를 반환합니다.
     * @return DSL 정의 팩터 집합
     */
    @Override
    public Set<AuthType> getAvailableFactors() {
        Object availableFactorsObj = getAttribute("availableFactors");
        if (availableFactorsObj instanceof Set) {
            @SuppressWarnings("unchecked")
            Set<AuthType> factors = (Set<AuthType>) availableFactorsObj;
            return new HashSet<>(factors);
        }
        return Collections.emptySet();
    }

    /**
     * 특정 팩터가 DSL에 정의되어 있는지 확인합니다.
     * @param factorType 확인할 팩터 타입
     * @return DSL에 정의되어 있으면 true
     */
    public boolean isFactorAvailable(AuthType factorType) {
        return getAvailableFactors().contains(factorType);
    }

    /**
     * 완료된 팩터 목록 조회 - 읽기 전용 복사본 반환
     */
    @Override
    public List<AuthenticationStepConfig> getCompletedFactors() {
        factorsLock.readLock().lock();
        try {
            return List.copyOf(this.completedFactors);
        } finally {
            factorsLock.readLock().unlock();
        }
    }


    @Override
    public String getLastError() {
        return this.lastError;
    }

    @Override
    public long getCreatedAt() {
        return this.createdAt;
    }

    /**
     * 상태 및 주요 정보 변경 감지를 위한 해시 계산
     * @return 현재 상태의 해시값
     */
    public String calculateStateHash() {
        StringBuilder sb = new StringBuilder();
        sb.append(mfaSessionId).append(":");
        sb.append(currentMfaState.get()).append(":");
        sb.append(version.get()).append(":");
        sb.append(completedFactors.size()).append(":");
        sb.append(currentProcessingFactor != null ? currentProcessingFactor : "null").append(":");
        sb.append(currentStepId != null ? currentStepId : "null");

        return Integer.toHexString(sb.toString().hashCode());
    }

    /**
     * 디버깅을 위한 상태 스냅샷
     * @return 현재 상태의 스냅샷
     */
    public Map<String, Object> getStateSnapshot() {
        Map<String, Object> snapshot = new HashMap<>();
        snapshot.put("mfaSessionId", mfaSessionId);
        snapshot.put("username", username);
        snapshot.put("currentState", currentMfaState.get());
        snapshot.put("version", version.get());
        snapshot.put("completedFactorsCount", completedFactors.size());
        snapshot.put("currentProcessingFactor", currentProcessingFactor);
        snapshot.put("currentStepId", currentStepId);
        snapshot.put("retryCount", retryCount);
        snapshot.put("lastActivityTimestamp", lastActivityTimestamp);
        snapshot.put("createdAt", createdAt);
        return Collections.unmodifiableMap(snapshot);
    }

    @Getter
    public static class MfaAttemptDetail implements Serializable {
        private static final long serialVersionUID = 20250522_02L;
        @Nullable
        private final AuthType factorType;
        private final boolean success;
        private final Instant timestamp;
        private final String detail;

        public MfaAttemptDetail(@Nullable AuthType factorType, boolean success, String detail) {
            this.factorType = factorType;
            this.success = success;
            this.timestamp = Instant.now();
            this.detail = detail;
        }
    }

    public boolean isCompleted() {
        MfaState currentState = this.currentMfaState.get();
        return currentState == MfaState.ALL_FACTORS_COMPLETED ||
                currentState == MfaState.MFA_SUCCESSFUL;
    }

    public boolean isTerminal() {
        return this.currentMfaState.get().isTerminal();
    }

    @Nullable
    public AuthenticationStepConfig getNextStepToProcess(AuthenticationFlowConfig flowConfig,
                                                         List<AuthType> userAvailableFactors) {
        if (flowConfig == null || CollectionUtils.isEmpty(flowConfig.getStepConfigs())) {
            return null;
        }
        return flowConfig.getStepConfigs().stream()
                .filter(step -> userAvailableFactors.contains(AuthType.valueOf(step.getType().toUpperCase())))
                .filter(step -> !isFactorCompleted(step.getStepId()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder))
                .orElse(null);
    }


    public void clearCurrentFactorProcessingState() {
        if (readOnly) {
            throw new IllegalStateException(
                "FactorContext is read-only. Cannot clear factor processing state."
            );
        }

        log.debug("FactorContext for user '{}', flow '{}': Clearing current factor processing state.", username, flowTypeName);
        this.currentProcessingFactor = null;
        this.currentStepId = null;
        this.version.incrementAndGet();
    }

    /**
     * 팩터 완료 여부 확인 - 스레드 안전
     */
    public boolean isFactorCompleted(String stepId) {
        if (!StringUtils.hasText(stepId)) {
            return false;
        }

        factorsLock.readLock().lock();
        try {
            return this.completedFactors.stream()
                    .anyMatch(cf -> stepId.equals(cf.getStepId()));
        } finally {
            factorsLock.readLock().unlock();
        }
    }

    @Getter
    public static class CompletedFactorInfo implements Serializable {
        private static final long serialVersionUID = 1L;
        private final AuthType factorType;
        private final String stepId;
        private final Instant completionTime;
        @Nullable private final transient AuthenticationProcessingOptions factorOptions;

        public CompletedFactorInfo(AuthType factorType, String stepId, Instant completionTime,
                                   @Nullable AuthenticationProcessingOptions factorOptions) {
            this.factorType = factorType;
            this.stepId = stepId;
            this.completionTime = completionTime;
            this.factorOptions = factorOptions;
        }

        @Override
        public String toString() {
            return "CompletedFactorInfo{" +
                    "factorType=" + factorType +
                    ", stepId='" + stepId + '\'' +
                    ", completionTime=" + completionTime +
                    '}';
        }
    }

    /**
     * 읽기 전용 스냅샷 생성 (Single Source of Truth 패턴)
     * State Machine에서 로드한 FactorContext를 읽기 전용으로 변환
     *
     * @param source 원본 FactorContext
     * @return 읽기 전용 복사본
     */
    public static FactorContext readOnlySnapshot(FactorContext source) {
        if (source == null) {
            return null;
        }

        FactorContext snapshot = new FactorContext();

        // 기본 정보 복사
        snapshot.mfaSessionId = source.mfaSessionId;
        snapshot.currentMfaState = new AtomicReference<>(source.getCurrentState());
        snapshot.version.set(source.getVersion());

        // 인증 정보 복사
        snapshot.primaryAuthentication = source.primaryAuthentication;
        snapshot.username = source.username;

        // 상태 정보 복사
        snapshot.flowTypeName = source.flowTypeName;
        snapshot.currentProcessingFactor = source.currentProcessingFactor;
        snapshot.currentStepId = source.currentStepId;
        snapshot.mfaRequiredAsPerPolicy = source.mfaRequiredAsPerPolicy;
        snapshot.retryCount = source.retryCount;
        snapshot.lastError = source.lastError;
        snapshot.lastActivityTimestamp = source.lastActivityTimestamp;

        // 컬렉션 복사 (deep copy)
        source.completedFactors.forEach(snapshot.completedFactors::add);
        snapshot.failedAttempts.putAll(source.failedAttempts);
        snapshot.factorAttemptCounts.putAll(source.factorAttemptCounts);
        snapshot.mfaAttemptHistory.addAll(source.mfaAttemptHistory);
        snapshot.attributes.putAll(source.attributes);

        // 읽기 전용 플래그 설정
        snapshot.readOnly = true;

        log.debug("Created read-only snapshot of FactorContext (ID: {}) for user '{}', state: {}, version: {}",
                snapshot.mfaSessionId, snapshot.username, snapshot.getCurrentState(), snapshot.getVersion());

        return snapshot;
    }
}