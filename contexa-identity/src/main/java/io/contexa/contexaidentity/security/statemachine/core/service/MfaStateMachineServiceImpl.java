package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.aop.framework.Advised;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachineEventResult;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class MfaStateMachineServiceImpl implements MfaStateMachineService {

    private final ObjectProvider<StateMachine<MfaState, MfaEvent>> stateMachineProvider;
    private final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;
    private final RedissonClient redissonClient;

    private static final long LOCK_WAIT_TIME_SECONDS = 10;
    private static final long LOCK_LEASE_TIME_SECONDS = 30;
    private static final MfaState FALLBACK_INITIAL_MFA_STATE = MfaState.NONE; // 실제 초기 상태로 변경 필요
    private static final long EVENT_PROCESSING_TIMEOUT_SECONDS = 5;

    private String getLockKey(String sessionId) {
        return "mfa_lock:session:" + sessionId;
    }

    // 상태 머신 인스턴스 획득 및 상태 복원/초기화 로직을 담당하는 헬퍼 메서드
    private StateMachine<MfaState, MfaEvent> getAndPrepareStateMachine(String machineId, MfaState initialStateIfNotRestored, FactorContext initialFactorContextForReset) {
        StateMachine<MfaState, MfaEvent> stateMachine = stateMachineProvider.getObject();
        try {
            stateMachinePersister.restore(stateMachine, machineId);
            log.debug("[MFA SM Service] [{}] 풀에서 가져온 SM에 상태 복원 완료. 현재 상태: {}", machineId, stateMachine.getState() != null ? stateMachine.getState().getId() : "N/A");
            // 복원 후 SM이 시작되지 않았거나, 상태가 없는 매우 예외적인 경우 시작 시도
            if (stateMachine.getState() == null || stateMachine.getState().getId() == null) {
                log.warn("[MFA SM Service] [{}] 복원 후 SM 상태가 null. initialStateIfNotRestored({})로 리셋 및 시작 시도.", machineId, initialStateIfNotRestored);
                resetAndStartStateMachine(stateMachine, machineId, initialStateIfNotRestored, initialFactorContextForReset);
            } else {
                // 복원 성공 시, SM이 이미 로드된 상태에 있으므로 별도 start 불필요할 수 있음.
                // 만약 Persister가 SM을 중지된 상태로 복원한다면 여기서 시작 필요.
                // 여기서는 restore가 사용 가능한 상태로 만든다고 가정.
            }
        } catch (Exception e) {
            log.warn("[MFA SM Service] [{}] 상태 머신 복원 실패 또는 새 세션. 초기 상태({})로 설정. 오류: {}", machineId, initialStateIfNotRestored, e.getMessage());
            resetAndStartStateMachine(stateMachine, machineId, initialStateIfNotRestored, initialFactorContextForReset);
        }
        return stateMachine;
    }

    // 상태 머신을 특정 상태와 FactorContext로 리셋하고 시작하는 헬퍼 메서드
    private void resetAndStartStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String machineId, MfaState targetState, FactorContext factorContext) {
        if (stateMachine.getState() != null) { // 현재 상태가 있다면 중지
            stateMachine.stopReactively().block();
            log.debug("[MFA SM Service] [{}] SM 리셋 전 중지 완료.", machineId);
        }

        ExtendedState extendedState = stateMachine.getExtendedState();
        extendedState.getVariables().clear(); // 이전 ExtendedState 내용 삭제
        /*if (factorContext != null) {
            StateContextHelper.setFactorContext(extendedState, factorContext);
            log.debug("[MFA SM Service] [{}] 리셋 중 FactorContext (버전:{})를 ExtendedState에 설정.", machineId, factorContext.getVersion());
        }*/

        StateMachineContext<MfaState, MfaEvent> newContext = new DefaultStateMachineContext<>(
                targetState, null, null, extendedState, null, machineId
        );
        stateMachine.getStateMachineAccessor()
                .doWithAllRegions(access -> access.resetStateMachineReactively(newContext).block());
        log.debug("[MFA SM Service] [{}] SM 상태({})로 리셋 완료.", machineId, targetState);
        if (factorContext != null) {
            StateContextHelper.setFactorContext(extendedState, factorContext);
            log.debug("[MFA SM Service] [{}] 리셋 중 FactorContext (버전:{})를 ExtendedState에 설정.", machineId, factorContext.getVersion());
        }
        stateMachine.startReactively().block(); // 리셋 후 항상 시작
        log.debug("[MFA SM Service] [{}] 리셋된 SM 시작 완료.", machineId);
    }

    // --- 인터페이스 메서드 구현 ---

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

            stateMachine = stateMachineProvider.getObject();

            // 외부에서 전달된 FactorContext의 초기 상태 및 정보로 StateMachine을 리셋하고 시작
            resetAndStartStateMachine(stateMachine, sessionId, context.getCurrentState(), context);
            log.info("[MFA SM Service] [{}] SM 초기화. SM 상태: {}, FactorContext 버전: {}",
                    sessionId, stateMachine.getState().getId(), context.getVersion());

            // PRIMARY_AUTH_SUCCESS 이벤트 전송
            Message<MfaEvent> message = createEventMessage(MfaEvent.PRIMARY_AUTH_SUCCESS, context, request);
            log.debug("[MFA SM Service] [{}] 이벤트 전송 (initialize): {}", sessionId, message.getPayload());

            Result eventProcessingResult = sendEventInternal(stateMachine, message, context); // 내부 sendEvent 로직 사용

            if (!eventProcessingResult.eventAccepted()) {
                log.warn("[MFA SM Service] [{}] SM 초기화 중 PRIMARY_AUTH_SUCCESS 이벤트가 수락되지 않음. 현재 SM 상태: {}", sessionId, eventProcessingResult.smCurrentStateAfterEvent());
            } else {
                log.info("[MFA SM Service] [{}] 이벤트 {} 처리 후 상태: {}", sessionId, message.getPayload(), eventProcessingResult.smCurrentStateAfterEvent());
            }

            // 외부 context 객체에 SM 내부 context의 최종 변경 사항을 반영 (Result 객체 사용)
            synchronizeExternalContext(context, eventProcessingResult.contextFromSmAfterEvent(), eventProcessingResult.smCurrentStateAfterEvent());

            // 최종적으로 "외부 context"의 버전을 증가 (모든 작업 완료 후)
            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context); // SM에도 최종 반영

            persistStateMachine(stateMachine, sessionId); // 최종 상태 영속화
            log.debug("[MFA SM Service] [{}] SM 영속화 완료 (initialize). 최종 FactorContext 버전: {}", sessionId, context.getVersion());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] SM 초기화 중 인터럽트 발생.", sessionId, e);
            throw new MfaStateMachineException("State Machine initialization interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] SM 초기화 중 오류 발생.", sessionId, e);
            throw new MfaStateMachineException("Error during State Machine initialization for " + sessionId + ": " + e.getMessage(), e);
        } finally {
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

    /**
     * Phase 2: 추가 헤더와 함께 이벤트 전송
     */
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
                return false; // 인터페이스 시그니처에 따라 boolean 반환
            }
            log.debug("[MFA SM Service] [{}] 이벤트 ({}) 처리 위한 락 획득.", sessionId, event);

            // SM 인스턴스를 가져오고, sessionId로 상태 복원. 복원 실패 시 context의 현재 상태로 초기화.
            stateMachine = getAndPrepareStateMachine(sessionId, context.getCurrentState(), context);

            // 이벤트 전송 전, 외부 context의 (업데이트된) 버전을 SM 내부 FactorContext에 반영 준비
            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context); // Action에서 사용할 최신 버전의 context 설정
            log.debug("[MFA SM Service] [{}] 이벤트 ({}) 처리 전 외부 FactorContext (버전:{}) SM에 설정.", sessionId, event, context.getVersion());

            Message<MfaEvent> message = createEventMessage(event, context, request, additionalHeaders);
            log.debug("[MFA SM Service] [{}] 이벤트 전송: {}", sessionId, message.getPayload());

            eventProcessingResult = sendEventInternal(stateMachine, message, context);

            if (eventProcessingResult.eventAccepted()) {
                log.info("[MFA SM Service] [{}] 이벤트 {} 처리 후 SM 상태: {}", sessionId, message.getPayload(), eventProcessingResult.smCurrentStateAfterEvent());
            } else {
                log.warn("[MFA SM Service] [{}] 이벤트 ({})가 현재 SM 상태 ({})에서 수락되지 않음.", sessionId, event, eventProcessingResult.smCurrentStateAfterEvent());
            }

            // 외부 context 객체에 SM 내부 context의 최종 변경 사항을 반영
            synchronizeExternalContext(context, eventProcessingResult.contextFromSmAfterEvent(), eventProcessingResult.smCurrentStateAfterEvent());

            // 최종적으로 동기화된 외부 context를 SM의 ExtendedState에 다시 저장
            StateContextHelper.setFactorContext(stateMachine, context);

            persistStateMachine(stateMachine, sessionId); // 최종 상태 영속화
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
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] 이벤트 ({}) 처리 락 해제.", sessionId, event);
            }
        }
    }

    /**
     * 실제 상태 머신 이벤트 전송 및 결과 처리를 위한 내부 헬퍼 메서드
     */
    private Result sendEventInternal(StateMachine<MfaState, MfaEvent> stateMachine, Message<MfaEvent> message, FactorContext originalExternalContext) {
        Boolean accepted = stateMachine.sendEvent(Mono.just(message))
                .map(result -> result.getResultType() == StateMachineEventResult.ResultType.ACCEPTED)
                .blockFirst(Duration.ofSeconds(EVENT_PROCESSING_TIMEOUT_SECONDS));

        boolean eventAccepted = Boolean.TRUE.equals(accepted);
        MfaState smStateAfterEvent = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
        FactorContext contextFromSmAfterEvent = StateContextHelper.getFactorContext(stateMachine);

        return new Result(eventAccepted, smStateAfterEvent, contextFromSmAfterEvent);
    }

    /**
     * SM 내부의 FactorContext 변경사항을 외부 FactorContext 객체에 동기화하는 헬퍼 메서드
     */
    private void synchronizeExternalContext(FactorContext externalContext, FactorContext contextFromSm, MfaState smActualState) {
        if (externalContext == null) return;

        if (contextFromSm != null) {
            externalContext.changeState(smActualState); // SM의 실제 상태로 외부 context 상태 업데이트
            externalContext.setVersion(contextFromSm.getVersion()); // SM 내부 FactorContext의 버전 사용
            // Attributes 병합 또는 덮어쓰기 (여기서는 SM 내부 것을 우선)
            externalContext.getAttributes().clear();
            externalContext.getAttributes().putAll(contextFromSm.getAttributes());
            // 기타 필요한 FactorContext 필드들도 contextFromSm의 값으로 업데이트
            externalContext.setCurrentProcessingFactor(contextFromSm.getCurrentProcessingFactor());
            externalContext.setCurrentStepId(contextFromSm.getCurrentStepId());
            externalContext.setMfaRequiredAsPerPolicy(contextFromSm.isMfaRequiredAsPerPolicy());
            externalContext.setRetryCount(contextFromSm.getRetryCount());
            externalContext.setLastError(contextFromSm.getLastError());
            // ... (completedFactors 등 중요 필드도 필요시 동기화) ...
        } else {
            // SM에서 FactorContext를 찾을 수 없는 예외적인 경우
            log.warn("[MFA SM Service] [{}] SM 내부에서 FactorContext를 찾을 수 없음. 외부 context의 상태만 SM 실제 상태로 업데이트.", externalContext.getMfaSessionId());
            externalContext.changeState(smActualState);
        }
    }


    /**
     * 상태 머신을 영속화하는 헬퍼 메서드 (프록시 처리 포함)
     */
    private void persistStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String sessionId) throws Exception {
        StateMachine<MfaState, MfaEvent> machineToPersist = stateMachine;
        if (stateMachine instanceof Advised) {
            try {
                Object target = ((Advised) stateMachine).getTargetSource().getTarget();
                if (target instanceof StateMachine) {
                    // 프록시가 한 번 더 감싸져 있을 가능성 고려
                    if (target instanceof Advised) {
                        Object innerTarget = ((Advised) target).getTargetSource().getTarget();
                        if (innerTarget instanceof StateMachine) {
                            machineToPersist = (StateMachine<MfaState, MfaEvent>) innerTarget;
                        }
                    } else {
                        machineToPersist = (StateMachine<MfaState, MfaEvent>) target;
                    }
                    log.debug("[MFA SM Service] [{}] 원본 StateMachine 객체 추출 성공 (persist).", sessionId);
                } else {
                    log.warn("[MFA SM Service] [{}] 프록시 원본이 StateMachine 타입 아님 (persist). 프록시 사용.", sessionId);
                }
            } catch (Exception e) {
                log.error("[MFA SM Service] [{}] 원본 StateMachine 추출 실패 (persist). 프록시 사용.", sessionId, e);
            }
        }
        stateMachinePersister.persist(machineToPersist, sessionId);
    }

    // getFactorContext, saveFactorContext, getCurrentState, updateStateOnly, releaseStateMachine 등도
    // getAndPrepareStateMachine과 persistStateMachine 헬퍼 메서드를 적절히 활용하여 수정.

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

            // getAndPrepareStateMachine은 FALLBACK_INITIAL_MFA_STATE와 FactorContext null로 호출하여
            // 순수하게 복원 시도만 하거나, 복원 실패 시 기본 상태로 만듦.
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

            stateMachine = stateMachineProvider.getObject();

            context.incrementVersion(); // 저장 전 버전 증가
            resetAndStartStateMachine(stateMachine, sessionId, context.getCurrentState(), context);
            log.debug("[MFA SM Service] [{}] 외부 FactorContext (버전:{}) SM에 동기화 완료.", sessionId, context.getVersion());

            persistStateMachine(stateMachine, sessionId); // 헬퍼 메서드 사용
            log.info("[MFA SM Service] [{}] FactorContext 명시적 저장 및 SM 영속화 완료. 버전: {}", sessionId, context.getVersion());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] FactorContext 저장 중 인터럽트 발생.", sessionId, e);
            throw new MfaStateMachineException("Saving FactorContext interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] FactorContext 저장 중 오류 발생.", sessionId, e);
            throw new MfaStateMachineException("Error during saving FactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
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

            // getAndPrepareStateMachine으로 SM을 가져오고 기존 상태 복원
            stateMachine = getAndPrepareStateMachine(sessionId, newState, null /* FactorContext는 SM에서 가져올 것이므로 null 전달 */);
            FactorContext factorContext = StateContextHelper.getFactorContext(stateMachine);

            if (factorContext == null) {
                log.warn("[MFA SM Service] [{}] 상태만 업데이트 실패: FactorContext 없음. 새 FactorContext 생성 및 상태 설정.", sessionId);
                // 이 경우, FactorContext가 없으면 새로 만들어야 함.
                // 하지만 primaryAuthentication 등 필수 정보가 없으므로 제한적.
                // 여기서는 최소한의 FactorContext를 만들고 상태만 설정 후 저장.
                // 더 나은 방법은 FactorContext가 없는 경우 false를 반환하거나 예외를 던지는 것.
                // 지금은 새 FactorContext를 만드는 것으로 가정 (이전 로직과 유사하게).
                Authentication currentAuth = stateMachine.getExtendedState().get("authentication", Authentication.class); // 시도
                factorContext = new FactorContext(sessionId, currentAuth, newState, null /* flowTypeName */);
            }

            factorContext.changeState(newState); // FactorContext 상태 변경 (내부에서 버전업 가능)
            // factorContext.incrementVersion(); // changeState에서 버전업 안 한다면 여기서

            resetAndStartStateMachine(stateMachine, sessionId, newState, factorContext); // SM 상태와 ExtendedState를 factorContext와 동기화

            persistStateMachine(stateMachine, sessionId); // 헬퍼 메서드 사용
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
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] 상태만 업데이트 락 해제.", sessionId);
            }
        }
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        log.info("[MFA SM Service] [{}] 세션에 대한 상태 머신 컨텍스트 정리 요청.", sessionId);
        // Redis에서 "spring:statemachine:context:" + sessionId 키를 직접 삭제하는 로직 추가 가능
    }

    private Message<MfaEvent> createEventMessage(MfaEvent event, FactorContext context, HttpServletRequest request) {
        return createEventMessage(event, context, request, null);
    }

    /**
     * Phase 2: 추가 헤더를 지원하는 createEventMessage 오버로드
     */
    private Message<MfaEvent> createEventMessage(MfaEvent event, FactorContext context,
                                                 HttpServletRequest request, Map<String, Object> additionalHeaders) {
        Map<String, Object> headers = new HashMap<>();
        if (context != null) {
            headers.put("sessionId", context.getMfaSessionId());
            if (context.getPrimaryAuthentication() != null && context.getPrimaryAuthentication().getName() != null) {
                headers.put("username", context.getPrimaryAuthentication().getName());
            }
            headers.put("version", context.getVersion()); // 현재 FactorContext의 버전을 헤더에 포함
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

        // Phase 2: 추가 헤더 병합
        if (additionalHeaders != null && !additionalHeaders.isEmpty()) {
            headers.putAll(additionalHeaders);
        }

        return MessageBuilder.withPayload(event).copyHeaders(headers).build();
    }

    private boolean isTerminalState(MfaState state) {
        if (state == null) return false;
        return state.isTerminal();
    }

    // 이벤트 처리 결과를 담는 내부 레코드 (Java 14+ 사용 가능)
    private record Result(boolean eventAccepted, MfaState smCurrentStateAfterEvent, FactorContext contextFromSmAfterEvent) {}

    public static class MfaStateMachineException extends RuntimeException {
        public MfaStateMachineException(String message) { super(message); }
        public MfaStateMachineException(String message, Throwable cause) { super(message, cause); }
    }
}