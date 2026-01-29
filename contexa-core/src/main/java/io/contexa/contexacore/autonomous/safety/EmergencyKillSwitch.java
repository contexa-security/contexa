package io.contexa.contexacore.autonomous.safety;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import jakarta.annotation.PostConstruct;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class EmergencyKillSwitch {
    
    private static final Logger logger = LoggerFactory.getLogger(EmergencyKillSwitch.class);
    
    @Autowired
    private PolicyProposalRepository proposalRepository;
    
    @Autowired
    private PolicyVersionManager versionManager;
    
    @Autowired
    private ApplicationEventPublisher eventPublisher;

    private final AtomicBoolean isActivated = new AtomicBoolean(false);

    private final AtomicBoolean isSafeMode = new AtomicBoolean(false);

    private final Map<Long, CircuitBreaker> circuitBreakers = new ConcurrentHashMap<>();

    private final List<KillSwitchEvent> activationHistory = Collections.synchronizedList(new ArrayList<>());

    private static final int ERROR_THRESHOLD = 5;
    private static final int TIME_WINDOW_SECONDS = 60;
    private static final double ERROR_RATE_THRESHOLD = 0.3;
    
    @PostConstruct
    public void initialize() {
        logger.info("Emergency Kill Switch initialized");
        
        performSafetyCheck();
    }

    @Transactional
    public boolean activate(String reason, Long targetProposalId) {
        logger.error("EMERGENCY KILL SWITCH ACTIVATED! Reason: {}, Target: {}", 
            reason, targetProposalId != null ? targetProposalId : "ALL");
        
        try {
            
            isActivated.set(true);
            
            if (targetProposalId != null) {
                
                return killSpecificPolicy(targetProposalId, reason);
            } else {
                
                return killAllPolicies(reason);
            }
            
        } catch (Exception e) {
            logger.error("Failed to activate kill switch", e);
            
            enterSafeMode();
            return false;
        }
    }

    @Transactional
    public boolean deactivate(String authorizedBy) {
        logger.info("Attempting to deactivate kill switch. Authorized by: {}", authorizedBy);
        
        if (!isActivated.get()) {
            logger.warn("Kill switch is not activated");
            return false;
        }
        
        try {
            
            if (!performSafetyCheck()) {
                logger.error("Safety check failed. Cannot deactivate kill switch");
                return false;
            }

            isActivated.set(false);

            exitSafeMode();

            publishKillSwitchEvent(KillSwitchEventType.DEACTIVATED, null, 
                "Deactivated by " + authorizedBy);
            
            logger.info("Kill switch successfully deactivated");
            return true;
            
        } catch (Exception e) {
            logger.error("Failed to deactivate kill switch", e);
            return false;
        }
    }

    public void monitorExecution(Long proposalId, boolean success) {
        CircuitBreaker breaker = circuitBreakers.computeIfAbsent(proposalId, 
            id -> new CircuitBreaker(id));
        
        if (success) {
            breaker.recordSuccess();
        } else {
            breaker.recordFailure();

            if (breaker.shouldTrip()) {
                logger.error("Circuit breaker tripped for proposal: {}", proposalId);
                activate("Circuit breaker threshold exceeded", proposalId);
            }
        }

        checkSystemHealth();
    }

    public void enterSafeMode() {
        if (isSafeMode.compareAndSet(false, true)) {
            logger.warn("System entering SAFE MODE");

            publishKillSwitchEvent(KillSwitchEventType.SAFE_MODE_ENTERED, null,
                "System protection activated");
        }
    }

    public void exitSafeMode() {
        if (isSafeMode.compareAndSet(true, false)) {
            logger.info("System exiting safe mode");

            publishKillSwitchEvent(KillSwitchEventType.SAFE_MODE_EXITED, null,
                "Normal operation resumed");
        }
    }

    public KillSwitchStatus getStatus() {
        return KillSwitchStatus.builder()
            .isActivated(isActivated.get())
            .isSafeMode(isSafeMode.get())
            .activeCircuitBreakers(getActiveCircuitBreakers())
            .recentEvents(getRecentEvents(10))
            .systemHealth(calculateSystemHealth())
            .build();
    }

    @Transactional
    public boolean rollbackPolicy(Long proposalId, Long targetVersion) {
        logger.info("Rolling back policy {} to version {}", proposalId, targetVersion);
        
        try {
            
            Long rolledBackVersion = versionManager.rollback(proposalId, targetVersion);

            publishKillSwitchEvent(KillSwitchEventType.POLICY_ROLLED_BACK, proposalId,
                "Rolled back to version " + rolledBackVersion);
            
            return true;
            
        } catch (Exception e) {
            logger.error("Failed to rollback policy: {}", proposalId, e);
            return false;
        }
    }

    private boolean killSpecificPolicy(Long proposalId, String reason) {
        logger.info("Killing specific policy: {}", proposalId);
        
        try {
            
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found"));
            
            proposal.setStatus(ProposalStatus.DEACTIVATED);
            proposal.setDeactivatedAt(LocalDateTime.now());
            proposal.addMetadata("deactivation_reason", reason);
            
            proposalRepository.save(proposal);

            recordActivation(proposalId, reason);

            publishKillSwitchEvent(KillSwitchEventType.POLICY_KILLED, proposalId, reason);
            
            return true;
            
        } catch (Exception e) {
            logger.error("Failed to kill policy: {}", proposalId, e);
            return false;
        }
    }
    
    private boolean killAllPolicies(String reason) {
        logger.info("Killing all active policies");
        
        List<PolicyEvolutionProposal> activeProposals = proposalRepository.findActiveProposals();
        int killedCount = 0;
        
        for (PolicyEvolutionProposal proposal : activeProposals) {
            if (killSpecificPolicy(proposal.getId(), reason)) {
                killedCount++;
            }
        }
        
        logger.info("Killed {} out of {} active policies", killedCount, activeProposals.size());

        enterSafeMode();

        publishKillSwitchEvent(KillSwitchEventType.ALL_POLICIES_KILLED, null, 
            String.format("Killed %d policies: %s", killedCount, reason));
        
        return killedCount > 0;
    }
    
    private boolean performSafetyCheck() {
        logger.debug("Performing safety check");
        
        try {
            
            List<PolicyEvolutionProposal> activeProposals = proposalRepository.findActiveProposals();
            
            for (PolicyEvolutionProposal proposal : activeProposals) {
                
                if (proposal.getRiskLevel() == PolicyEvolutionProposal.RiskLevel.CRITICAL) {
                    CircuitBreaker breaker = circuitBreakers.get(proposal.getId());
                    if (breaker != null && breaker.getErrorRate() > ERROR_RATE_THRESHOLD) {
                        logger.warn("High-risk policy {} has high error rate", proposal.getId());
                        return false;
                    }
                }
            }

            SystemHealth health = calculateSystemHealth();
            if (health == SystemHealth.CRITICAL) {
                logger.warn("System health is critical");
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            logger.error("Safety check failed", e);
            return false;
        }
    }
    
    private void checkSystemHealth() {
        SystemHealth health = calculateSystemHealth();
        
        if (health == SystemHealth.CRITICAL && !isActivated.get()) {
            logger.error("System health critical. Activating kill switch");
            activate("System health critical", null);
        }
    }
    
    private SystemHealth calculateSystemHealth() {
        double totalErrorRate = circuitBreakers.values().stream()
            .mapToDouble(CircuitBreaker::getErrorRate)
            .average()
            .orElse(0.0);
        
        if (totalErrorRate > 0.5) {
            return SystemHealth.CRITICAL;
        } else if (totalErrorRate > 0.3) {
            return SystemHealth.WARNING;
        } else {
            return SystemHealth.HEALTHY;
        }
    }
    
    private void recordActivation(Long proposalId, String reason) {
        KillSwitchEvent event = KillSwitchEvent.builder()
            .eventType(KillSwitchEventType.ACTIVATED)
            .proposalId(proposalId)
            .reason(reason)
            .timestamp(LocalDateTime.now())
            .build();
        
        activationHistory.add(event);
    }
    
    private void publishKillSwitchEvent(KillSwitchEventType type, Long proposalId, String details) {
        KillSwitchEvent event = KillSwitchEvent.builder()
            .eventType(type)
            .proposalId(proposalId)
            .reason(details)
            .timestamp(LocalDateTime.now())
            .build();
        
        activationHistory.add(event);

        eventPublisher.publishEvent(event);
    }
    
    private List<Long> getActiveCircuitBreakers() {
        return circuitBreakers.entrySet().stream()
            .filter(entry -> entry.getValue().isOpen())
            .map(Map.Entry::getKey)
            .collect(ArrayList::new, (list, id) -> list.add(id), ArrayList::addAll);
    }
    
    private List<KillSwitchEvent> getRecentEvents(int count) {
        int size = activationHistory.size();
        int fromIndex = Math.max(0, size - count);
        return new ArrayList<>(activationHistory.subList(fromIndex, size));
    }

    private static class CircuitBreaker {
        private final Long proposalId;
        private final AtomicInteger successCount = new AtomicInteger(0);
        private final AtomicInteger failureCount = new AtomicInteger(0);
        
        private final ConcurrentLinkedQueue<Long> errorTimestamps = new ConcurrentLinkedQueue<>();
        private volatile boolean isOpen = false;
        
        public CircuitBreaker(Long proposalId) {
            this.proposalId = proposalId;
        }
        
        public void recordSuccess() {
            successCount.incrementAndGet();
            
            if (isOpen && getErrorRate() < 0.1) {
                reset();
            }
        }
        
        public void recordFailure() {
            failureCount.incrementAndGet();
            errorTimestamps.add(System.currentTimeMillis());

            long cutoff = System.currentTimeMillis() - (TIME_WINDOW_SECONDS * 1000);
            errorTimestamps.removeIf(ts -> ts < cutoff);
        }
        
        public boolean shouldTrip() {
            if (errorTimestamps.size() >= ERROR_THRESHOLD) {
                isOpen = true;
                return true;
            }
            
            if (getErrorRate() > ERROR_RATE_THRESHOLD) {
                isOpen = true;
                return true;
            }
            
            return false;
        }
        
        public double getErrorRate() {
            int total = successCount.get() + failureCount.get();
            if (total == 0) return 0.0;
            return (double) failureCount.get() / total;
        }
        
        public boolean isOpen() {
            return isOpen;
        }
        
        public void reset() {
            successCount.set(0);
            failureCount.set(0);
            errorTimestamps.clear();
            isOpen = false;
        }
    }

    @lombok.Builder
    @lombok.Data
    public static class KillSwitchStatus {
        private boolean isActivated;
        private boolean isSafeMode;
        private List<Long> activeCircuitBreakers;
        private List<KillSwitchEvent> recentEvents;
        private SystemHealth systemHealth;
    }

    @lombok.Builder
    @lombok.Data
    public static class KillSwitchEvent {
        private KillSwitchEventType eventType;
        private Long proposalId;
        private String reason;
        private LocalDateTime timestamp;
    }

    public enum KillSwitchEventType {
        ACTIVATED,
        DEACTIVATED,
        POLICY_KILLED,
        ALL_POLICIES_KILLED,
        POLICY_ROLLED_BACK,
        SAFE_MODE_ENTERED,
        SAFE_MODE_EXITED
    }

    public enum SystemHealth {
        HEALTHY,
        WARNING,
        CRITICAL
    }
}