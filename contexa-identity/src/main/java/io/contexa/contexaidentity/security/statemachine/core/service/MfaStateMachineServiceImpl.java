package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
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
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * MFA StateMachine 서비스 구현체
 *
 * P0 변경사항:
 * - ObjectProvider → StateMachineFactory로 변경 (Factory 패턴)
 * - acquireStateMachine(), releaseStateMachineInstance() 추가 (리소스 관리)
 * - 모든 메서드에 finally 블록 리소스 정리 추가
 * - Proxy 언래핑 로직 제거 (Factory 직접 생성으로 불필요)
 *
 * 보존사항:
 * - Redisson Lock 패턴 완전 보존
 * - Deep Copy 동기화 로직 완전 보존
 * - FactorContext 관리 로직 완전 보존
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MfaStateMachineServiceImpl implements MfaStateMachineService {

    private final StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;
    private final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;
    private final RedissonClient redissonClient;
    private final StateMachineProperties properties; // P2: Properties 주입

    private static final long LOCK_WAIT_TIME_SECONDS = 10;
    private static final long LOCK_LEASE_TIME_SECONDS = 30;
    private static final MfaState FALLBACK_INITIAL_MFA_STATE = MfaState.NONE; // 실제 초기 상태로 변경 필요

    // P2: Properties에서 timeout 가져오기 (EVENT_PROCESSING_TIMEOUT_SECONDS 제거)

    private String getLockKey(String sessionId) {
        return "mfa_lock:session:" + sessionId;
    }

    /**
     * P0: StateMachine 인스턴스 획득 (Factory 패턴)
     *
     * @param sessionId MFA 세션 ID (machineId로 사용)
     * @return 새로운 StateMachine 인스턴스
     */
    private StateMachine<MfaState, MfaEvent> acquireStateMachine(String sessionId) {
        StateMachine<MfaState, MfaEvent> sm = stateMachineFactory.getStateMachine(sessionId);
        log.debug("[MFA SM Service] [{}] StateMachine 인스턴스 생성 완료 (Factory)", sessionId);
        return sm;
    }

    /**
     * P0: StateMachine 인스턴스 리소스 정리 (공식 권장)
     *
     * @param sm        StateMachine 인스턴스
     * @param sessionId MFA 세션 ID
     */
    private void releaseStateMachineInstance(StateMachine<MfaState, MfaEvent> sm, String sessionId) {
        if (sm != null) {
            try {
                // 공식 권장: stopReactively() 호출로 리소스 정리
                sm.stopReactively().block(Duration.ofSeconds(5));
                log.debug("[MFA SM Service] [{}] StateMachine 인스턴스 정리 완료", sessionId);
            } catch (Exception e) {
                log.warn("[MFA SM Service] [{}] StateMachine 정리 중 오류 (무시됨): {}", sessionId, e.getMessage());
            }
            // GC가 자동으로 메모리 정리
        }
    }

    // 상태 머신 인스턴스 획득 및 상태 복원/초기화 로직을 담당하는 헬퍼 메서드
    private StateMachine<MfaState, MfaEvent> getAndPrepareStateMachine(String machineId, MfaState initialStateIfNotRestored, FactorContext initialFactorContextForReset) {
        StateMachine<MfaState, MfaEvent> stateMachine = acquireStateMachine(machineId);
        try {
            stateMachinePersister.restore(stateMachine, machineId);
            log.debug("[MFA SM Service] [{}] 풀에서 가져온 SM에 상태 복원 완료. 현재 상태: {}", machineId, stateMachine.getState() != null ? stateMachine.getState().getId() : "N/A");

            // ===== 검증 포인트 3: restore() 직후 ExtendedState 확인 =====
            ExtendedState restoredExtendedState = stateMachine.getExtendedState();
            FactorContext restoredContext = StateContextHelper.getFactorContext(stateMachine);
            log.warn("[VERIFY-3] restore() 직후 [{}] - ExtendedState 변수 개수: {}, FactorContext: {}",
                     machineId, restoredExtendedState.getVariables().size(),
                     restoredContext != null ? "존재 (version " + restoredContext.getVersion() + ")" : "NULL");

            // 복원 후 SM이 시작되지 않았거나, 상태가 없는 매우 예외적인 경우 시작 시도
            if (stateMachine.getState() == null || stateMachine.getState().getId() == null) {
                log.warn("[MFA SM Service] [{}] 복원 후 SM 상태가 null. initialStateIfNotRestored({})로 업데이트 및 시작 시도.", machineId, initialStateIfNotRestored);
                log.warn("[VERIFY-3] 복원 후 State는 null이지만 FactorContext는 [{}]: {}",
                         machineId, restoredContext != null ? "존재 (version " + restoredContext.getVersion() + ")" : "NULL");
                updateAndStartStateMachine(stateMachine, machineId, initialStateIfNotRestored, initialFactorContextForReset);
            } else {
                // 복원 성공 시, SM이 이미 로드된 상태에 있으므로 별도 start 불필요할 수 있음.
                // 만약 Persister가 SM을 중지된 상태로 복원한다면 여기서 시작 필요.
                // 여기서는 restore가 사용 가능한 상태로 만든다고 가정.
            }
        } catch (Exception e) {
            log.warn("[MFA SM Service] [{}] 상태 머신 복원 실패 또는 새 세션. 초기 상태({})로 설정. 오류: {}", machineId, initialStateIfNotRestored, e.getMessage());
            updateAndStartStateMachine(stateMachine, machineId, initialStateIfNotRestored, initialFactorContextForReset);
        }
        return stateMachine;
    }

    // 상태 머신을 특정 상태로 업데이트하되 ExtendedState는 보존하는 헬퍼 메서드 (부분 업데이트용)
    private void updateAndStartStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String machineId, MfaState targetState, FactorContext factorContext) {
        if (stateMachine.getState() != null) {
            stateMachine.stopReactively().block();
            log.debug("[MFA SM Service] [{}] SM 업데이트 전 중지 완료.", machineId);
        }

        // ExtendedState 보존 - clear() 호출 안함!
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

        // 검증 로그
        ExtendedState finalExtendedState = stateMachine.getExtendedState();
        FactorContext finalContext = StateContextHelper.getFactorContext(stateMachine);
        log.debug("[MFA SM Service] [{}] updateAndStartStateMachine 완료 - ExtendedState 변수 개수: {}, FactorContext: {}",
                 machineId, finalExtendedState.getVariables().size(),
                 finalContext != null ? "존재 (version " + finalContext.getVersion() + ")" : "NULL");
    }

    // 상태 머신을 특정 상태와 FactorContext로 리셋하고 시작하는 헬퍼 메서드 (완전 초기화용)
    private void resetAndStartStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String machineId, MfaState targetState, FactorContext factorContext) {
        if (stateMachine.getState() != null) { // 현재 상태가 있다면 중지
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
        stateMachine.startReactively().block(); // 리셋 후 항상 시작
        log.debug("[MFA SM Service] [{}] 리셋된 SM 시작 완료.", machineId);

        // ===== 검증 포인트 1: resetAndStartStateMachine 완료 후 ExtendedState 검증 =====
        ExtendedState finalExtendedState = stateMachine.getExtendedState();
        FactorContext finalContext = StateContextHelper.getFactorContext(stateMachine);
        log.warn("[VERIFY-1] resetAndStartStateMachine 완료 후 [{}] - ExtendedState 변수 개수: {}, FactorContext: {}",
                 machineId, finalExtendedState.getVariables().size(),
                 finalContext != null ? "존재 (version " + finalContext.getVersion() + ")" : "NULL");
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

            stateMachine = acquireStateMachine(sessionId);

            // 외부에서 전달된 FactorContext의 초기 상태 및 정보로 StateMachine을 리셋하고 시작
            resetAndStartStateMachine(stateMachine, sessionId, context.getCurrentState(), context);
            log.info("[MFA SM Service] [{}] SM 초기화 완료. SM 상태: {}, FactorContext 버전: {}",
                    sessionId, stateMachine.getState().getId(), context.getVersion());

            // ⚠️ PRIMARY_AUTH_SUCCESS 이벤트 전송은 PrimaryAuthenticationSuccessHandler에서 MfaDecision과 함께 수행
            // initializeStateMachine()은 State Machine과 FactorContext 동기화만 수행

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
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] 이벤트 ({}) 처리 락 해제.", sessionId, event);
            }
        }
    }

    /**
     * 실제 상태 머신 이벤트 전송 및 결과 처리를 위한 내부 헬퍼 메서드
     */
    /**
     * P2: Reactor 기반 이벤트 전송 최적화
     *
     * Reactor 체인 구성:
     * - sendEvent: 비동기 이벤트 전송
     * - doOnNext/doOnError/doOnComplete: 각 단계별 로깅
     * - map: 결과 타입 변환 (ACCEPTED → boolean)
     * - timeout: Properties 기반 타임아웃 설정
     * - blockFirst: 결과 대기 (타임아웃 + 1초)
     *
     * 타임아웃 처리:
     * - null 반환 시 폴백 처리
     * - 현재 상태 유지 및 이벤트 거부
     */
    private Result sendEventInternal(StateMachine<MfaState, MfaEvent> stateMachine, Message<MfaEvent> message, FactorContext originalExternalContext) {
        String sessionId = originalExternalContext.getMfaSessionId();
        MfaEvent event = message.getPayload();
        MfaState currentState = stateMachine.getState() != null ? stateMachine.getState().getId() : null;

        // P2: Properties에서 timeout 가져오기
        int timeoutSeconds = properties.getMfa().getTransitionTimeoutSeconds() != null ?
            properties.getMfa().getTransitionTimeoutSeconds() : 5;

        log.debug("[SM Internal] 이벤트 전송 시작 - Event: {}, CurrentState: {}, Session: {}, Timeout: {}초",
                 event, currentState, sessionId, timeoutSeconds);

        // P2: Reactor 체인 최적화
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

        // P2: 타임아웃 폴백 처리
        if (accepted == null) {
            log.error("[SM Internal] ⚠️ 이벤트 처리 타임아웃 발생 - Event: {}, State: {}, Session: {}, Timeout: {}초",
                     event, currentState, sessionId, timeoutSeconds);
            log.error("[SM Internal] State Machine이 응답하지 않음. 이벤트 거부로 처리.");

            // 폴백: 이벤트 거부로 처리, 현재 상태 유지
            MfaState fallbackState = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
            FactorContext fallbackContext = StateContextHelper.getFactorContext(stateMachine);

            return new Result(false, fallbackState, fallbackContext != null ? fallbackContext : originalExternalContext);
        }

        boolean eventAccepted = Boolean.TRUE.equals(accepted);
        MfaState smStateAfterEvent = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
        FactorContext contextFromSmAfterEvent = StateContextHelper.getFactorContext(stateMachine);

        // 검증: contextFromSm 획득 후 속성 검증 로그 추가
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

    /**
     * SM 내부의 FactorContext 변경사항을 외부 FactorContext 객체에 동기화하는 헬퍼 메서드
     */
    private void synchronizeExternalContext(FactorContext externalContext, FactorContext contextFromSm, MfaState smActualState) {
        if (externalContext == null) {
            log.warn("[MFA SM Service] External context is null, skipping synchronization");
            return;
        }

        if (contextFromSm != null) {
            externalContext.changeState(smActualState); // SM의 실제 상태로 외부 context 상태 업데이트
            externalContext.setVersion(contextFromSm.getVersion()); // SM 내부 FactorContext의 버전 사용

            // Phase 3.1: Attributes Deep Copy 구현
            // Attributes 병합: SM 내부 속성을 외부 context에 병합 (clear 제거하여 기존 속성 보존)
            if (contextFromSm.getAttributes() != null) {
                log.debug("[MFA SM Service] [{}] Merging {} attributes from SM to external context",
                         externalContext.getMfaSessionId(), contextFromSm.getAttributes().size());
                contextFromSm.getAttributes().forEach((key, value) -> {
                    // Deep copy for collection types
                    Object copiedValue = deepCopyIfNeeded(key, value);
                    externalContext.setAttribute(key, copiedValue);
                    if ("availableFactors".equals(key)) {
                        log.info("[MFA SM Service] [{}] Synced availableFactors: {}",
                                externalContext.getMfaSessionId(), copiedValue);
                    }
                });
            }

            // Phase 3.2: 누락된 필드 동기화 추가
            // 기본 필드들
            externalContext.setCurrentProcessingFactor(contextFromSm.getCurrentProcessingFactor());
            externalContext.setCurrentStepId(contextFromSm.getCurrentStepId());
            externalContext.setMfaRequiredAsPerPolicy(contextFromSm.isMfaRequiredAsPerPolicy());
            externalContext.setRetryCount(contextFromSm.getRetryCount());
            externalContext.setLastError(contextFromSm.getLastError());

            // Phase 3.2.1: completedFactors는 FactorContext 내부에서 관리되므로
            // 외부에서 강제 동기화하지 않음 (불변 컬렉션 오류 방지)
            // completedFactors는 각 Action에서 factorContext.addCompletedFactor()로 추가됨

            // 타임스탬프 필드들
            if (contextFromSm.getLastActivityTimestamp() != null) {
                externalContext.updateLastActivityTimestamp();
            }
        } else {
            // SM에서 FactorContext를 찾을 수 없는 예외적인 경우
            log.warn("[MFA SM Service] [{}] SM 내부에서 FactorContext를 찾을 수 없음. 외부 context의 상태만 SM 실제 상태로 업데이트.", externalContext.getMfaSessionId());
            externalContext.changeState(smActualState);
        }
    }


    /**
     * P0: 상태 머신을 영속화하는 헬퍼 메서드 (Proxy 언래핑 제거)
     *
     * Factory 패턴에서는 Proxy 없이 직접 인스턴스를 생성하므로
     * Proxy 언래핑 로직이 불필요합니다.
     */
    private void persistStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String sessionId) throws Exception {
        stateMachinePersister.persist(stateMachine, sessionId);
        log.debug("[MFA SM Service] [{}] StateMachine 영속화 완료", sessionId);
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

            // ✅ Redis 키 존재 여부 먼저 확인 (수정 2 - Use-After-Release 방지)
            String redisKey = "spring:statemachine:context:" + sessionId;
            long keyExists = redissonClient.getKeys().countExists(redisKey);

            if (keyExists == 0) {
                log.info("[MFA SM Service] [{}] State Machine context does not exist (likely released). Skipping save.", sessionId);
                return; // ✅ 조기 종료 - 블로킹 방지
            }
            log.debug("[MFA SM Service] [{}] State Machine context exists. Proceeding with save.", sessionId);

            stateMachine = acquireStateMachine(sessionId);

            // ===== 근본 해결: resetAndStartStateMachine() 제거 =====
            // 기존 StateMachine 복원 시도
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

            // 복원 실패 시에만 시작
            if (!restored) {
                stateMachine.startReactively().block();
                log.debug("[MFA SM Service] [{}] SM 새로 시작 완료.", sessionId);
            }

            // 버전 증가 후 FactorContext만 업데이트
            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context);
            log.debug("[MFA SM Service] [{}] 외부 FactorContext (버전:{}) SM에 동기화 완료.", sessionId, context.getVersion());

            // ===== 검증 포인트 2: persistStateMachine 호출 전후 비교 =====
            FactorContext beforePersist = StateContextHelper.getFactorContext(stateMachine);
            log.warn("[VERIFY-2] persistStateMachine 호출 전 [{}] - FactorContext: {}",
                     sessionId, beforePersist != null ? "존재 (version " + beforePersist.getVersion() + ")" : "NULL");

            persistStateMachine(stateMachine, sessionId);
            log.info("[MFA SM Service] [{}] FactorContext 명시적 저장 및 SM 영속화 완료. 버전: {}", sessionId, context.getVersion());

            // ===== 검증: 복원 테스트 =====
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

            updateAndStartStateMachine(stateMachine, sessionId, newState, factorContext); // SM 상태 업데이트 (ExtendedState 보존)

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

            // Redis에서 State Machine 컨텍스트 키 삭제
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

    /**
     * Phase 3.1: Attributes Deep Copy 헬퍼 메서드
     *
     * Collection 타입의 속성값에 대해 Deep copy를 수행하여
     * 외부에서 수정해도 State Machine 내부 데이터가 영향받지 않도록 합니다.
     *
     * @param key 속성 키
     * @param value 속성 값
     * @return Deep copy된 값 또는 원본 값
     */
    private Object deepCopyIfNeeded(String key, Object value) {
        if (value == null) {
            return null;
        }

        // 불변 객체는 그대로 반환 (복사 불필요)
        if (isImmutableType(value)) {
            return value;
        }

        try {
            // Set 타입 Deep copy - 내부 요소도 재귀적으로 복사
            if (value instanceof java.util.Set) {
                java.util.Set<?> original = (java.util.Set<?>) value;
                java.util.Set<Object> deepCopy = new java.util.HashSet<>();
                for (Object item : original) {
                    deepCopy.add(deepCopyItem(item));
                }
                return deepCopy;
            }

            // List 타입 Deep copy - 내부 요소도 재귀적으로 복사
            if (value instanceof java.util.List) {
                java.util.List<?> original = (java.util.List<?>) value;
                java.util.List<Object> deepCopy = new java.util.ArrayList<>();
                for (Object item : original) {
                    deepCopy.add(deepCopyItem(item));
                }
                return deepCopy;
            }

            // Map 타입 Deep copy - 키와 값 모두 재귀적으로 복사
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

            // Serializable 객체는 직렬화를 통한 진짜 Deep copy
            if (value instanceof java.io.Serializable) {
                return org.apache.commons.lang3.SerializationUtils.clone((java.io.Serializable) value);
            }

            // 복사 불가능한 객체는 원본 반환 (경고 로그)
            log.warn("[MFA SM Service] deepCopyIfNeeded - 복사 불가능한 타입 ({}): {}. 원본 참조 반환.",
                     value.getClass().getName(), key);
            return value;

        } catch (Exception e) {
            log.error("[MFA SM Service] deepCopyIfNeeded - Deep copy 실패 (key: {}). 원본 참조 반환.", key, e);
            return value; // 복사 실패 시 원본 반환 (기존 동작 유지)
        }
    }

    // 개별 아이템 Deep copy
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

    // 불변 타입 체크
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

    // 이벤트 처리 결과를 담는 내부 레코드 (Java 14+ 사용 가능)
    private record Result(boolean eventAccepted, MfaState smCurrentStateAfterEvent, FactorContext contextFromSmAfterEvent) {}

    public static class MfaStateMachineException extends RuntimeException {
        public MfaStateMachineException(String message) { super(message); }
        public MfaStateMachineException(String message, Throwable cause) { super(message, cause); }
    }
}