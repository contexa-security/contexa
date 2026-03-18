package io.contexa.contexaidentity.security.core.mfa.context;

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@Getter
@Slf4j
@Setter
public class FactorContext implements FactorContextExtensions, Serializable {

    private String mfaSessionId;
    private AtomicReference<MfaState> currentMfaState;
    private final AtomicInteger version = new AtomicInteger(0);

    private boolean readOnly = false;

    private transient ReadWriteLock stateLock;
    private transient ReadWriteLock factorsLock;

    private Authentication primaryAuthentication;
    private String username;
    private volatile int retryCount = 0;
    private volatile String lastError;
    private final long createdAt = System.currentTimeMillis();

    private volatile String flowTypeName;
    private volatile StateConfig stateConfig;
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
        this.username = primaryAuthentication.getName();
        this.currentMfaState = new AtomicReference<>(initialState);
        this.flowTypeName = flowTypeName;
        this.lastActivityTimestamp = Instant.now();
        this.stateLock = new ReentrantReadWriteLock();
        this.factorsLock = new ReentrantReadWriteLock();

    }

    public MfaState getCurrentState() {
        return this.currentMfaState.get();
    }

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

                updateLastActivityTimestamp();
            }
        } finally {
            stateLock.writeLock().unlock();
        }
    }

    public int incrementVersion() {

        if (readOnly) {
            throw new IllegalStateException(
                    "FactorContext is read-only. Cannot increment version."
            );
        }
        int newVersion = this.version.incrementAndGet();
        updateLastActivityTimestamp();
        return newVersion;
    }

    public int getVersion() {
        return this.version.get();
    }

    public void setVersion(int newVersion) {

        if (readOnly) {
            throw new IllegalStateException(
                    "FactorContext is read-only. Cannot set version."
            );
        }
        if (newVersion < 0) {
            throw new IllegalArgumentException("Version cannot be negative");
        }
        int oldVersion = this.version.getAndSet(newVersion);
        if (oldVersion != newVersion) {
            updateLastActivityTimestamp();
        }
    }

    public boolean compareAndSetVersion(int expectedVersion, int newVersion) {
        boolean success = this.version.compareAndSet(expectedVersion, newVersion);
        if (success) {
            updateLastActivityTimestamp();
        } else {
        }
        return success;
    }

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

                updateLastActivityTimestamp();
            } else {
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
                return 0;
            }

            return completedFactors.stream()
                    .mapToInt(AuthenticationStepConfig::getOrder)
                    .max()
                    .orElse(0);
        } finally {
            factorsLock.readLock().unlock();
        }
    }

    public int incrementAttemptCount(@Nullable AuthType factorType) {

        if (readOnly) {
            throw new IllegalStateException(
                    "FactorContext is read-only. Cannot increment attempt count."
            );
        }

        if (factorType == null) {
            log.error("FactorContext (ID: {}): Attempted to increment attempt count for a null factorType for user {}.",
                    mfaSessionId, this.username);
            return 0;
        }

        int newCount = factorAttemptCounts.compute(factorType, (key, val) -> (val == null) ? 1 : val + 1);
        updateLastActivityTimestamp();

        return newCount;
    }

    public int getAttemptCount(@Nullable AuthType factorType) {
        if (factorType == null) return 0;
        return factorAttemptCounts.getOrDefault(factorType, 0);
    }

    public void recordAttempt(@Nullable AuthType factorType, boolean success, String detail) {

        if (readOnly) {
            throw new IllegalStateException(
                    "FactorContext is read-only. Cannot record attempt."
            );
        }
        this.mfaAttemptHistory.add(new MfaAttemptDetail(factorType, success, detail));
        updateLastActivityTimestamp();

    }

    public int incrementFailedAttempts(String factorTypeOrStepId) {

        if (readOnly) {
            throw new IllegalStateException(
                    "FactorContext is read-only. Cannot increment failed attempts."
            );
        }
        Assert.hasText(factorTypeOrStepId, "factorTypeOrStepId cannot be empty");

        int attempts = this.failedAttempts.compute(factorTypeOrStepId,
                (key, currentAttempts) -> (currentAttempts == null) ? 1 : currentAttempts + 1);

        updateLastActivityTimestamp();

        return attempts;
    }

    public int getFailedAttempts(String factorTypeOrStepId) {
        return this.failedAttempts.getOrDefault(factorTypeOrStepId, 0);
    }

    public void resetFailedAttempts(String factorTypeOrStepId) {

        if (readOnly) {
            throw new IllegalStateException(
                    "FactorContext is read-only. Cannot reset failed attempts."
            );
        }
        this.failedAttempts.remove(factorTypeOrStepId);
        updateLastActivityTimestamp();

    }

    public void resetAllFailedAttempts() {

        if (readOnly) {
            throw new IllegalStateException(
                    "FactorContext is read-only. Cannot reset all failed attempts."
            );
        }
        this.failedAttempts.clear();
        updateLastActivityTimestamp();

    }

    public void setAttribute(String name, Object value) {
        if (readOnly) {
            throw new IllegalStateException(
                    "FactorContext is read-only. Cannot modify attributes."
            );
        }

        if (value == null) {
            this.attributes.remove(name);
            return;
        }

        if (!(value instanceof Serializable)) {
            throw new IllegalArgumentException(
                    "Attribute must be Serializable for Redis persistence: " +
                            name + " (" + value.getClass().getName() + ")"
            );
        }

        this.attributes.put(name, value);
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

    }

    public boolean isFullyAuthenticated() {
        return MfaState.ALL_FACTORS_COMPLETED == this.currentMfaState.get() ||
                MfaState.MFA_SUCCESSFUL == this.currentMfaState.get();
    }

    public void updateLastActivityTimestamp() {
        this.lastActivityTimestamp = Instant.now();
    }

    @Override
    public int getRetryCount() {
        return this.retryCount;
    }

    @Override
    public Set<AuthType> getAvailableFactors() {
        Object availableFactorsObj = getAttribute("availableFactors");

        if (availableFactorsObj == null) {
            log.error("[FactorContext] availableFactors attribute is NULL for session: {} - not initialized yet?", mfaSessionId);
            return null;
        }

        if (availableFactorsObj instanceof Set) {
            try {
                Set<AuthType> factors = (Set<AuthType>) availableFactorsObj;
                return new LinkedHashSet<>(factors);
            } catch (ClassCastException e) {
                log.error("[FactorContext] availableFactors type cast failed for session: {}, type: {}",
                        mfaSessionId, availableFactorsObj.getClass(), e);
                return null;
            }
        }

        log.error("[FactorContext] availableFactors attribute type mismatch: {} for session: {}",
                availableFactorsObj.getClass().getName(), mfaSessionId);
        return null;
    }

    public boolean isFactorAvailable(AuthType factorType) {
        Set<AuthType> factors = getAvailableFactors();
        return factors != null && factors.contains(factorType);
    }

    public Set<AuthType> getRemainingFactors() {
        Set<AuthType> available = getAvailableFactors();
        if (available == null || available.isEmpty()) {
            return Collections.emptySet();
        }
        factorsLock.readLock().lock();
        try {
            Set<String> completedTypes = this.completedFactors.stream()
                    .map(AuthenticationStepConfig::getType)
                    .map(String::toUpperCase)
                    .collect(Collectors.toSet());
            return available.stream()
                    .filter(f -> !completedTypes.contains(f.name()))
                    .collect(Collectors.toCollection(LinkedHashSet::new));
        } finally {
            factorsLock.readLock().unlock();
        }
    }

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

    @Getter
    public static class MfaAttemptDetail implements Serializable {
        private static final long serialVersionUID = 20250522_02L;
        @Nullable
        private AuthType factorType;
        private boolean success;
        private Instant timestamp;
        private String detail;

        @SuppressWarnings("unused")
        private MfaAttemptDetail() {}

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

    @Nullable
    public Boolean getBooleanAttribute(String key) {
        Object value = getAttribute(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value != null) {
            log.error("[FactorContext] Attribute '{}' is not a Boolean: {}", key, value.getClass().getName());
        }
        return null;
    }

    public <T> Set<T> getSetAttribute(String key) {
        Object value = getAttribute(key);
        if (value instanceof Set) {
            try {
                return new HashSet<>((Set<T>) value);
            } catch (ClassCastException e) {
                log.error("[FactorContext] Failed to cast Set attribute '{}': {}", key, e.getMessage());
                return new HashSet<>();
            }
        }
        if (value != null) {
            log.error("[FactorContext] Attribute '{}' is not a Set: {}", key, value.getClass().getName());
        }
        return new HashSet<>();
    }

    public <T> List<T> getListAttribute(String key) {
        Object value = getAttribute(key);
        if (value instanceof List) {
            try {
                return new ArrayList<>((List<T>) value);
            } catch (ClassCastException e) {
                log.error("[FactorContext] Failed to cast List attribute '{}': {}", key, e.getMessage());
                return new ArrayList<>();
            }
        }
        if (value != null) {
            log.error("[FactorContext] Attribute '{}' is not a List: {}", key, value.getClass().getName());
        }
        return new ArrayList<>();
    }

    public <K, V> Map<K, V> getMapAttribute(String key) {
        Object value = getAttribute(key);
        if (value instanceof Map) {
            try {
                return new HashMap<>((Map<K, V>) value);
            } catch (ClassCastException e) {
                log.error("[FactorContext] Failed to cast Map attribute '{}': {}", key, e.getMessage());
                return new HashMap<>();
            }
        }
        if (value != null) {
            log.error("[FactorContext] Attribute '{}' is not a Map: {}", key, value.getClass().getName());
        }
        return new HashMap<>();
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        this.stateLock = new ReentrantReadWriteLock();
        this.factorsLock = new ReentrantReadWriteLock();
    }
}