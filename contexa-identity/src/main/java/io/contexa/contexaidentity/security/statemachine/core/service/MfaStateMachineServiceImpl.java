package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.messaging.Message;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachineEventResult;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;


@Slf4j
public class MfaStateMachineServiceImpl implements MfaStateMachineService {

    private final StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;
    private final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;
    private final RedissonClient redissonClient;
    private final StateMachineProperties properties; 

    public MfaStateMachineServiceImpl(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            RedissonClient redissonClient,
            StateMachineProperties properties) {
        this.stateMachineFactory = stateMachineFactory;
        this.stateMachinePersister = stateMachinePersister;
        this.redissonClient = redissonClient;
        this.properties = properties;
    }

    private static final long LOCK_WAIT_TIME_SECONDS = 10;
    private static final long LOCK_LEASE_TIME_SECONDS = 30;
    private static final MfaState FALLBACK_INITIAL_MFA_STATE = MfaState.NONE; 

    

    private String getLockKey(String sessionId) {
        return "mfa_lock:session:" + sessionId;
    }

    
    private StateMachine<MfaState, MfaEvent> acquireStateMachine(String sessionId) {
        StateMachine<MfaState, MfaEvent> sm = stateMachineFactory.getStateMachine(sessionId);
        log.debug("[MFA SM Service] [{}] StateMachine 인스턴스 생성 완료 (Factory)", sessionId);
        return sm;
    }

    
    private void releaseStateMachineInstance(StateMachine<MfaState, MfaEvent> sm, String sessionId) {
        if (sm != null) {
            try {
                
                sm.stopReactively().block(Duration.ofSeconds(5));
                log.debug("[MFA SM Service] [{}] StateMachine 인스턴스 정리 완료", sessionId);
            } catch (Exception e) {
                log.warn("[MFA SM Service] [{}] StateMachine 정리 중 오류 (무시됨): {}", sessionId, e.getMessage());
            }
            
        }
    }

    
    private StateMachine<MfaState, MfaEvent> getAndPrepareStateMachine(String machineId, MfaState initialStateIfNotRestored, FactorContext initialFactorContextForReset) {
        StateMachine<MfaState, MfaEvent> stateMachine = acquireStateMachine(machineId);
        try {
            stateMachinePersister.restore(stateMachine, machineId);
            log.debug("[MFA SM Service] [{}] 풀에서 가져온 SM에 상태 복원 완료. 현재 상태: {}", machineId, stateMachine.getState() != null ? stateMachine.getState().getId() : "N/A");

            
            ExtendedState restoredExtendedState = stateMachine.getExtendedState();
            FactorContext restoredContext = StateContextHelper.getFactorContext(stateMachine);
            log.warn("[VERIFY-3] restore() 직후 [{}] - ExtendedState 변수 개수: {}, FactorContext: {}",
                     machineId, restoredExtendedState.getVariables().size(),
                     restoredContext != null ? "존재 (version " + restoredContext.getVersion() + ")" : "NULL");

            
            if (stateMachine.getState() == null || stateMachine.getState().getId() == null) {
                log.warn("[MFA SM Service] [{}] 복원 후 SM 상태가 null. initialStateIfNotRestored({})로 업데이트 및 시작 시도.", machineId, initialStateIfNotRestored);
                log.warn("[VERIFY-3] 복원 후 State는 null이지만 FactorContext는 [{}]: {}",
                         machineId, restoredContext != null ? "존재 (version " + restoredContext.getVersion() + ")" : "NULL");
                updateAndStartStateMachine(stateMachine, machineId, initialStateIfNotRestored, initialFactorContextForReset);
            } else {
                
                
                
            }
        } catch (Exception e) {
            log.warn("[MFA SM Service] [{}] 상태 머신 복원 실패 또는 새 세션. 초기 상태({})로 설정. 오류: {}", machineId, initialStateIfNotRestored, e.getMessage());
            updateAndStartStateMachine(stateMachine, machineId, initialStateIfNotRestored, initialFactorContextForReset);
        }
        return stateMachine;
    }

    
    private void updateAndStartStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String machineId, MfaState targetState, FactorContext factorContext) {
        if (stateMachine.getState() != null) {
            stateMachine.stopReactively().block();
            log.debug("[MFA SM Service] [{}] SM 업데이트 전 중지 완료.", machineId);
        }

        
        ExtendedState extendedState = stateMachine.getExtendedState();

        if (factorContext != null) {
            StateContextHelper.setFactorContext(extendedState, factorContext);
            log.debug("[MFA SM Service] [{}] FactorContext (버전:{})를 ExtendedState에 업데이트 (기존 데이터 보존).", machineId, factorContext.getVersion());
        }

        StateMachineContext<MfaState, MfaEvent> newContext = new DefaultStateMachineContext<>(
                targetState, null, null, extendedState, null, machineId
        );
        stateMachine.getStateMachineAccessor()
                .doWithAllRegions(access -> access.resetStateMachineReactively(newContext).block());
        log.debug("[MFA SM Service] [{}] SM 상태({})로 업데이트 완료 (ExtendedState 보존).", machineId, targetState);

        stateMachine.startReactively().block();
        log.debug("[MFA SM Service] [{}] 업데이트된 SM 시작 완료.", machineId);

        
        ExtendedState finalExtendedState = stateMachine.getExtendedState();
        FactorContext finalContext = StateContextHelper.getFactorContext(stateMachine);
        log.debug("[MFA SM Service] [{}] updateAndStartStateMachine 완료 - ExtendedState 변수 개수: {}, FactorContext: {}",
                 machineId, finalExtendedState.getVariables().size(),
                 finalContext != null ? "존재 (version " + finalContext.getVersion() + ")" : "NULL");
    }

    
    private void resetAndStartStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String machineId, MfaState targetState, FactorContext factorContext) {
        if (stateMachine.getState() != null) { 
            stateMachine.stopReactively().block();
            log.debug("[MFA SM Service] [{}] SM 리셋 전 중지 완료.", machineId);
        }

        ExtendedState extendedState = stateMachine.getExtendedState();
        extendedState.getVariables().clear();

        if (factorContext != null) {
            StateContextHelper.setFactorContext(extendedState, factorContext);
            log.debug("[MFA SM Service] [{}] 리셋 전 FactorContext (버전:{})를 ExtendedState에 설정.", machineId, factorContext.getVersion());
        }

        StateMachineContext<MfaState, MfaEvent> newContext = new DefaultStateMachineContext<>(
                targetState, null, null, extendedState, null, machineId
        );
        stateMachine.getStateMachineAccessor()
                .doWithAllRegions(access -> access.resetStateMachineReactively(newContext).block());
        log.debug("[MFA SM Service] [{}] SM 상태({})로 리셋 완료. FactorContext 포함: {}", machineId, targetState, (factorContext != null));
        stateMachine.startReactively().block(); 
        log.debug("[MFA SM Service] [{}] 리셋된 SM 시작 완료.", machineId);

        
        ExtendedState finalExtendedState = stateMachine.getExtendedState();
        FactorContext finalContext = StateContextHelper.getFactorContext(stateMachine);
        log.warn("[VERIFY-1] resetAndStartStateMachine 완료 후 [{}] - ExtendedState 변수 개수: {}, FactorContext: {}",
                 machineId, finalExtendedState.getVariables().size(),
                 finalContext != null ? "존재 (version " + finalContext.getVersion() + ")" : "NULL");
    }

    

    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            log.debug("[MFA SM Service] [{}] SM 초기화 위한 락 획득 시도.", sessionId);
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);

            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] SM 초기화 위한 락 획득 실패.", sessionId);
                throw new MfaStateMachineException("Failed to acquire lock for State Machine initialization: " + sessionId);
            }
            log.debug("[MFA SM Service] [{}] SM 초기화 위한 락 획득.", sessionId);

            stateMachine = acquireStateMachine(sessionId);

            
            resetAndStartStateMachine(stateMachine, sessionId, context.getCurrentState(), context);
            log.info("[MFA SM Service] [{}] SM 초기화 완료. SM 상태: {}, FactorContext 버전: {}",
                    sessionId, stateMachine.getState().getId(), context.getVersion());

            
            

            
            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context); 

            persistStateMachine(stateMachine, sessionId); 
            log.debug("[MFA SM Service] [{}] SM 영속화 완료 (initialize). 최종 FactorContext 버전: {}", sessionId, context.getVersion());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] SM 초기화 중 인터럽트 발생.", sessionId, e);
            throw new MfaStateMachineException("State Machine initialization interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] SM 초기화 중 오류 발생.", sessionId, e);
            throw new MfaStateMachineException("Error during State Machine initialization for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] SM 초기화 락 해제.", sessionId);
            }
        }
    }


    @Override
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        return sendEvent(event, context, request, null);
    }

    
    @Override
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request, Map<String, Object> additionalHeaders) {
        String sessionId = context.getMfaSessionId();
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;
        Result eventProcessingResult;

        try {
            log.debug("[MFA SM Service] [{}] 이벤트 ({}) 처리 위한 락 획득 시도.", sessionId, event);
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] 이벤트 ({}) 처리 위한 락 획득 실패.", sessionId, event);
                return false; 
            }
            log.debug("[MFA SM Service] [{}] 이벤트 ({}) 처리 위한 락 획득.", sessionId, event);

            
            stateMachine = getAndPrepareStateMachine(sessionId, context.getCurrentState(), context);

            
            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context); 
            log.debug("[MFA SM Service] [{}] 이벤트 ({}) 처리 전 외부 FactorContext (버전:{}) SM에 설정.", sessionId, event, context.getVersion());

            Message<MfaEvent> message = createEventMessage(event, context, request, additionalHeaders);
            log.debug("[MFA SM Service] [{}] 이벤트 전송: {}", sessionId, message.getPayload());

            eventProcessingResult = sendEventInternal(stateMachine, message, context);

            if (eventProcessingResult.eventAccepted()) {
                log.info("[MFA SM Service] [{}] 이벤트 {} 처리 후 SM 상태: {}", sessionId, message.getPayload(), eventProcessingResult.smCurrentStateAfterEvent());
            } else {
                log.warn("[MFA SM Service] [{}] 이벤트 ({})가 현재 SM 상태 ({})에서 수락되지 않음.", sessionId, event, eventProcessingResult.smCurrentStateAfterEvent());
            }

            
            synchronizeExternalContext(context, eventProcessingResult.contextFromSmAfterEvent(), eventProcessingResult.smCurrentStateAfterEvent());

            
            StateContextHelper.setFactorContext(stateMachine, context);

            persistStateMachine(stateMachine, sessionId); 
            log.debug("[MFA SM Service] [{}] 상태 머신 영속화 완료. 최종 FactorContext 버전: {}", sessionId, context.getVersion());

            return eventProcessingResult.eventAccepted();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] 이벤트 ({}) 처리 중 인터럽트 발생.", sessionId, event, e);
            throw new MfaStateMachineException("MFA event processing interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] 이벤트 ({}) 처리 중 오류 발생.", sessionId, event, e);
            throw new MfaStateMachineException("Error during MFA event processing for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] 이벤트 ({}) 처리 락 해제.", sessionId, event);
            }
        }
    }

    
    
    private Result sendEventInternal(StateMachine<MfaState, MfaEvent> stateMachine, Message<MfaEvent> message, FactorContext originalExternalContext) {
        String sessionId = originalExternalContext.getMfaSessionId();
        MfaEvent event = message.getPayload();
        MfaState currentState = stateMachine.getState() != null ? stateMachine.getState().getId() : null;

        
        int timeoutSeconds = properties.getMfa().getTransitionTimeoutSeconds() != null ?
            properties.getMfa().getTransitionTimeoutSeconds() : 5;

        log.debug("[SM Internal] 이벤트 전송 시작 - Event: {}, CurrentState: {}, Session: {}, Timeout: {}초",
                 event, currentState, sessionId, timeoutSeconds);

        
        Boolean accepted = stateMachine.sendEvent(Mono.just(message))
                .doOnNext(result -> log.debug("[SM Internal] 이벤트 결과 수신 - ResultType: {}, Session: {}",
                                              result.getResultType(), sessionId))
                .doOnError(error -> log.error("[SM Internal] 이벤트 처리 중 에러 발생 - Event: {}, Session: {}",
                                             event, sessionId, error))
                .doOnComplete(() -> log.debug("[SM Internal] Reactive Stream 완료 - Event: {}, Session: {}",
                                             event, sessionId))
                .map(result -> result.getResultType() == StateMachineEventResult.ResultType.ACCEPTED)
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .doOnNext(isAccepted -> log.debug("[SM Internal] 이벤트 수락 여부: {} - Event: {}, Session: {}",
                                                 isAccepted, event, sessionId))
                .blockFirst(Duration.ofSeconds(timeoutSeconds + 1));

        log.debug("[SM Internal] blockFirst() 반환 완료 - accepted: {}, Event: {}, Session: {}",
                 accepted, event, sessionId);

        
        if (accepted == null) {
            log.error("[SM Internal] ⚠️ 이벤트 처리 타임아웃 발생 - Event: {}, State: {}, Session: {}, Timeout: {}초",
                     event, currentState, sessionId, timeoutSeconds);
            log.error("[SM Internal] State Machine이 응답하지 않음. 이벤트 거부로 처리.");

            
            MfaState fallbackState = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
            FactorContext fallbackContext = StateContextHelper.getFactorContext(stateMachine);

            return new Result(false, fallbackState, fallbackContext != null ? fallbackContext : originalExternalContext);
        }

        boolean eventAccepted = Boolean.TRUE.equals(accepted);
        MfaState smStateAfterEvent = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
        FactorContext contextFromSmAfterEvent = StateContextHelper.getFactorContext(stateMachine);

        
        if (contextFromSmAfterEvent != null) {
            Object factorsObj = contextFromSmAfterEvent.getAttribute("availableFactors");
            log.debug("[sendEventInternal] contextFromSm retrieved - availableFactors: {}, state: {}, session: {}",
                     factorsObj, smStateAfterEvent, originalExternalContext.getMfaSessionId());

            if (factorsObj == null) {
                log.warn("[sendEventInternal] availableFactors is NULL in contextFromSm for session: {}",
                        originalExternalContext.getMfaSessionId());
            }
        } else {
            log.error("[sendEventInternal] contextFromSm is NULL for session: {}",
                     originalExternalContext.getMfaSessionId());
        }

        return new Result(eventAccepted, smStateAfterEvent, contextFromSmAfterEvent);
    }

    
    private void synchronizeExternalContext(FactorContext externalContext, FactorContext contextFromSm, MfaState smActualState) {
        if (externalContext == null) {
            log.warn("[MFA SM Service] External context is null, skipping synchronization");
            return;
        }

        if (contextFromSm != null) {
            externalContext.changeState(smActualState); 
            externalContext.setVersion(contextFromSm.getVersion()); 

            
            
            if (contextFromSm.getAttributes() != null) {
                log.debug("[MFA SM Service] [{}] Merging {} attributes from SM to external context",
                         externalContext.getMfaSessionId(), contextFromSm.getAttributes().size());
                contextFromSm.getAttributes().forEach((key, value) -> {
                    
                    Object copiedValue = deepCopyIfNeeded(key, value);
                    externalContext.setAttribute(key, copiedValue);
                    if ("availableFactors".equals(key)) {
                        log.info("[MFA SM Service] [{}] Synced availableFactors: {}",
                                externalContext.getMfaSessionId(), copiedValue);
                    }
                });
            }

            
            
            externalContext.setCurrentProcessingFactor(contextFromSm.getCurrentProcessingFactor());
            externalContext.setCurrentStepId(contextFromSm.getCurrentStepId());
            externalContext.setMfaRequiredAsPerPolicy(contextFromSm.isMfaRequiredAsPerPolicy());
            externalContext.setRetryCount(contextFromSm.getRetryCount());
            externalContext.setLastError(contextFromSm.getLastError());

            
            
            

            
            if (contextFromSm.getLastActivityTimestamp() != null) {
                externalContext.updateLastActivityTimestamp();
            }
        } else {
            
            log.warn("[MFA SM Service] [{}] SM 내부에서 FactorContext를 찾을 수 없음. 외부 context의 상태만 SM 실제 상태로 업데이트.", externalContext.getMfaSessionId());
            externalContext.changeState(smActualState);
        }
    }


    
    private void persistStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String sessionId) throws Exception {
        stateMachinePersister.persist(stateMachine, sessionId);
        log.debug("[MFA SM Service] [{}] StateMachine 영속화 완료", sessionId);
    }

    
    

    @Override
    public FactorContext getFactorContext(String sessionId) {
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;
        try {
            log.debug("[MFA SM Service] [{}] FactorContext 조회 위한 락 획득 시도.", sessionId);
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS / 2, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] FactorContext 조회 위한 락 획득 실패. null 반환.", sessionId);
                return null;
            }
            log.debug("[MFA SM Service] [{}] FactorContext 조회 위한 락 획득.", sessionId);

            
            
            stateMachine = getAndPrepareStateMachine(sessionId, FALLBACK_INITIAL_MFA_STATE, null);
            FactorContext factorContext = StateContextHelper.getFactorContext(stateMachine);

            if (factorContext == null) {
                log.info("[MFA SM Service] [{}] SM 복원 후 FactorContext 없음.", sessionId);
            } else {
                log.debug("[MFA SM Service] [{}] FactorContext 조회 성공. 버전: {}", sessionId, factorContext.getVersion());
            }
            return factorContext;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] FactorContext 조회 중 인터럽트 발생.", sessionId, e);
            throw new MfaStateMachineException("Get FactorContext interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] FactorContext 조회 중 오류 발생.", sessionId, e);
            throw new MfaStateMachineException("Error during getFactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] FactorContext 조회 락 해제.", sessionId);
            }
        }
    }

    @Override
    public void saveFactorContext(FactorContext context) {
        String sessionId = context.getMfaSessionId();
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            log.debug("[MFA SM Service] [{}] FactorContext 저장 위한 락 획득 시도.", sessionId);
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] FactorContext 저장 위한 락 획득 실패.", sessionId);
                throw new MfaStateMachineException("Failed to acquire lock for saving FactorContext: " + sessionId);
            }
            log.debug("[MFA SM Service] [{}] FactorContext 저장 위한 락 획득.", sessionId);

            
            String redisKey = "spring:statemachine:context:" + sessionId;
            long keyExists = redissonClient.getKeys().countExists(redisKey);

            if (keyExists == 0) {
                log.info("[MFA SM Service] [{}] State Machine context does not exist (likely released). Skipping save.", sessionId);
                return; 
            }
            log.debug("[MFA SM Service] [{}] State Machine context exists. Proceeding with save.", sessionId);

            stateMachine = acquireStateMachine(sessionId);

            
            
            boolean restored = false;
            try {
                stateMachinePersister.restore(stateMachine, sessionId);
                if (stateMachine.getState() != null && stateMachine.getState().getId() != null) {
                    log.debug("[MFA SM Service] [{}] 기존 SM 복원 성공. 현재 상태: {}", sessionId, stateMachine.getState().getId());
                    restored = true;
                } else {
                    log.warn("[MFA SM Service] [{}] SM 복원 후 상태가 null. 새로 시작.", sessionId);
                }
            } catch (Exception e) {
                log.warn("[MFA SM Service] [{}] SM 복원 실패. 새로 시작. 오류: {}", sessionId, e.getMessage());
            }

            
            if (!restored) {
                stateMachine.startReactively().block();
                log.debug("[MFA SM Service] [{}] SM 새로 시작 완료.", sessionId);
            }

            
            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context);
            log.debug("[MFA SM Service] [{}] 외부 FactorContext (버전:{}) SM에 동기화 완료.", sessionId, context.getVersion());

            
            FactorContext beforePersist = StateContextHelper.getFactorContext(stateMachine);
            log.warn("[VERIFY-2] persistStateMachine 호출 전 [{}] - FactorContext: {}",
                     sessionId, beforePersist != null ? "존재 (version " + beforePersist.getVersion() + ")" : "NULL");

            persistStateMachine(stateMachine, sessionId);
            log.info("[MFA SM Service] [{}] FactorContext 명시적 저장 및 SM 영속화 완료. 버전: {}", sessionId, context.getVersion());

            
            try {
                StateMachine<MfaState, MfaEvent> testMachine = acquireStateMachine(sessionId);
                try {
                    stateMachinePersister.restore(testMachine, sessionId);
                    FactorContext afterPersist = StateContextHelper.getFactorContext(testMachine);
                    log.warn("[VERIFY-2] persistStateMachine 호출 후 복원 [{}] - FactorContext: {}",
                             sessionId, afterPersist != null ? "존재 (version " + afterPersist.getVersion() + ")" : "NULL");
                } finally {
                    releaseStateMachineInstance(testMachine, sessionId);
                }
            } catch (Exception e) {
                log.error("[VERIFY-2] persistStateMachine 후 복원 실패 [{}]", sessionId, e);
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] FactorContext 저장 중 인터럽트 발생.", sessionId, e);
            throw new MfaStateMachineException("Saving FactorContext interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] FactorContext 저장 중 오류 발생.", sessionId, e);
            throw new MfaStateMachineException("Error during saving FactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] FactorContext 저장 락 해제.", sessionId);
            }
        }
    }

    @Override
    public MfaState getCurrentState(String sessionId) {
        FactorContext context = getFactorContext(sessionId);
        if (context != null) {
            return context.getCurrentState();
        }
        log.warn("[MFA SM Service] [{}] 현재 상태 조회 실패: FactorContext를 찾을 수 없음. NONE 반환.", sessionId);
        return MfaState.NONE;
    }

    @Override
    public boolean updateStateOnly(String sessionId, MfaState newState) {
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            log.debug("[MFA SM Service] [{}] 상태만 업데이트 위한 락 획득 시도: -> {}", sessionId, newState);
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] 상태만 업데이트 위한 락 획득 실패.", sessionId);
                return false;
            }
            log.debug("[MFA SM Service] [{}] 상태만 업데이트 위한 락 획득.", sessionId);

            
            stateMachine = getAndPrepareStateMachine(sessionId, newState, null );
            FactorContext factorContext = StateContextHelper.getFactorContext(stateMachine);

            if (factorContext == null) {
                log.warn("[MFA SM Service] [{}] 상태만 업데이트 실패: FactorContext 없음. 새 FactorContext 생성 및 상태 설정.", sessionId);
                
                
                
                
                
                Authentication currentAuth = stateMachine.getExtendedState().get("authentication", Authentication.class); 
                factorContext = new FactorContext(sessionId, currentAuth, newState, null );
            }

            factorContext.changeState(newState); 
            

            updateAndStartStateMachine(stateMachine, sessionId, newState, factorContext); 

            persistStateMachine(stateMachine, sessionId); 
            log.info("[MFA SM Service] [{}] 상태만 업데이트 완료: {}. FactorContext 버전: {}", sessionId, newState, factorContext.getVersion());
            return true;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] 상태만 업데이트 중 인터럽트 발생.", sessionId, e);
            throw new MfaStateMachineException("State-only update interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] 상태만 업데이트 중 오류 발생.", sessionId, e);
            throw new MfaStateMachineException("Error during state-only update for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] 상태만 업데이트 락 해제.", sessionId);
            }
        }
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;

        try {
            log.debug("[MFA SM Service] [{}] SM 해제 위한 락 획득 시도.", sessionId);
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);

            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] SM 해제 위한 락 획득 실패. 타임아웃.", sessionId);
                return;
            }
            log.debug("[MFA SM Service] [{}] SM 해제 위한 락 획득 성공.", sessionId);

            
            String redisKey = "spring:statemachine:context:" + sessionId;
            long deletedCount = redissonClient.getKeys().delete(redisKey);

            if (deletedCount > 0) {
                log.info("[MFA SM Service] [{}] 상태 머신 컨텍스트 정리 완료. 삭제된 키 개수: {}", sessionId, deletedCount);
            } else {
                log.debug("[MFA SM Service] [{}] 정리할 상태 머신 컨텍스트가 존재하지 않음.", sessionId);
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] SM 해제 중 인터럽트 발생.", sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] SM 해제 중 오류 발생.", sessionId, e);
        } finally {
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] SM 해제 락 해제.", sessionId);
            }
        }
    }

    private Message<MfaEvent> createEventMessage(MfaEvent event, FactorContext context, HttpServletRequest request) {
        return createEventMessage(event, context, request, null);
    }

    
    private Message<MfaEvent> createEventMessage(MfaEvent event, FactorContext context,
                                                 HttpServletRequest request, Map<String, Object> additionalHeaders) {
        Map<String, Object> headers = new HashMap<>();
        if (context != null) {
            headers.put("sessionId", context.getMfaSessionId());
            if (context.getPrimaryAuthentication() != null && context.getPrimaryAuthentication().getName() != null) {
                headers.put("username", context.getPrimaryAuthentication().getName());
            }
            headers.put("version", context.getVersion()); 
            headers.put("stateHash", context.calculateStateHash());
            if (context.getPrimaryAuthentication() != null) {
                headers.put("authentication", context.getPrimaryAuthentication());
            }
        }

        if (request != null) {
            Object selectedFactor = request.getAttribute("selectedFactor");
            if (selectedFactor != null) {
                headers.put("selectedFactor", selectedFactor.toString());
            }
        }

        
        if (additionalHeaders != null && !additionalHeaders.isEmpty()) {
            headers.putAll(additionalHeaders);
        }

        return MessageBuilder.withPayload(event).copyHeaders(headers).build();
    }

    private boolean isTerminalState(MfaState state) {
        if (state == null) return false;
        return state.isTerminal();
    }

    
    private Object deepCopyIfNeeded(String key, Object value) {
        if (value == null) {
            return null;
        }

        
        if (isImmutableType(value)) {
            return value;
        }

        try {
            
            if (value instanceof java.util.Set) {
                java.util.Set<?> original = (java.util.Set<?>) value;
                java.util.Set<Object> deepCopy = new java.util.HashSet<>();
                for (Object item : original) {
                    deepCopy.add(deepCopyItem(item));
                }
                return deepCopy;
            }

            
            if (value instanceof java.util.List) {
                java.util.List<?> original = (java.util.List<?>) value;
                java.util.List<Object> deepCopy = new java.util.ArrayList<>();
                for (Object item : original) {
                    deepCopy.add(deepCopyItem(item));
                }
                return deepCopy;
            }

            
            if (value instanceof java.util.Map) {
                java.util.Map<?, ?> original = (java.util.Map<?, ?>) value;
                java.util.Map<Object, Object> deepCopy = new java.util.HashMap<>();
                for (java.util.Map.Entry<?, ?> entry : original.entrySet()) {
                    deepCopy.put(
                        deepCopyItem(entry.getKey()),
                        deepCopyItem(entry.getValue())
                    );
                }
                return deepCopy;
            }

            
            if (value instanceof java.io.Serializable) {
                return org.apache.commons.lang3.SerializationUtils.clone((java.io.Serializable) value);
            }

            
            log.warn("[MFA SM Service] deepCopyIfNeeded - 복사 불가능한 타입 ({}): {}. 원본 참조 반환.",
                     value.getClass().getName(), key);
            return value;

        } catch (Exception e) {
            log.error("[MFA SM Service] deepCopyIfNeeded - Deep copy 실패 (key: {}). 원본 참조 반환.", key, e);
            return value; 
        }
    }

    
    private Object deepCopyItem(Object item) {
        if (item == null || isImmutableType(item)) {
            return item;
        }

        if (item instanceof java.io.Serializable) {
            try {
                return org.apache.commons.lang3.SerializationUtils.clone((java.io.Serializable) item);
            } catch (Exception e) {
                log.warn("[MFA SM Service] deepCopyItem - 직렬화 실패. 원본 참조 반환: {}", item.getClass().getName(), e);
                return item;
            }
        }

        log.warn("[MFA SM Service] deepCopyItem - Serializable 아님. 원본 참조 반환: {}", item.getClass().getName());
        return item;
    }

    
    private boolean isImmutableType(Object value) {
        return value instanceof String
            || value instanceof Integer
            || value instanceof Long
            || value instanceof Double
            || value instanceof Float
            || value instanceof Boolean
            || value instanceof Character
            || value instanceof Byte
            || value instanceof Short
            || value instanceof java.math.BigDecimal
            || value instanceof java.math.BigInteger
            || value instanceof java.time.LocalDate
            || value instanceof java.time.LocalDateTime
            || value instanceof java.time.ZonedDateTime
            || value instanceof java.time.Instant
            || value instanceof java.util.UUID
            || value.getClass().isEnum();
    }

    
    private record Result(boolean eventAccepted, MfaState smCurrentStateAfterEvent, FactorContext contextFromSmAfterEvent) {}

    public static class MfaStateMachineException extends RuntimeException {
        public MfaStateMachineException(String message) { super(message); }
        public MfaStateMachineException(String message, Throwable cause) { super(message, cause); }
    }
}