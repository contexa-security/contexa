# MFA Policy System 통합 분석 보고서

## 종합 평가 (Executive Summary)

### 전반적 상태
- **통합 성숙도**: 70/100
- **아키텍처 품질**: 75/100
- **성능 최적화**: 80/100
- **안정성**: 65/100
- **보안성**: 85/100

### 주요 발견사항
1. **P0 (Critical)**: 3건 - 무한 루프 위험, 동기화 불일치, Null-safety 부족
2. **P1 (High)**: 8건 - 성능 최적화 미완성, 동기화 범위 불완전, 캐시 정합성
3. **P2 (Medium)**: 12건 - 에러 처리 개선 필요, 가독성, 테스트 용이성
4. **P3 (Low)**: 5건 - 코드 스타일, 문서화

---

## 1. 통합 흐름 분석 (Integration Flow Analysis)

### 1.1 메서드 호출 체인 검증

```
PrimaryAuthenticationSuccessHandler.onAuthenticationSuccess (L58)
  ↓
  mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(factorContext) (L76)
    ↓
    DefaultMfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep (L80-91)
      ↓
      1. evaluatePolicy(ctx) (L84)
         ↓
         policyEvaluator.evaluatePolicy(ctx) (L98)
           ↓
           DefaultMfaPolicyEvaluator.evaluatePolicy (L65-133)
             - evaluateMfaRequirement() (L147-208)
             - getAvailableFactorsFromDsl() (L326-350)
             - determineFactorCount() (L441-463)
             - determineRequiredFactors() (L214-251)
             - determineDecisionType() (L303-320)
         ↓ [Return MfaDecision]

      2. applyDecisionToContext(ctx, decision) (L87)
         - ctx.setMfaRequiredAsPerPolicy() (L111)
         - ctx.setAttribute("mfaDecision", decision) (L112)
         - findMfaFlowConfig() - [캐싱됨] (L134)
         - ctx.setAttribute("availableFactors", ...) (L137)
         - stateMachineIntegrator.saveFactorContext(ctx) (L148)

      3. sendInitialStateEvent(ctx, decision) (L90)
         - decision.isBlocked() → return (L159-163)
         - !decision.isRequired() → MFA_NOT_REQUIRED (L166-170)
         - handleMfaRequired(ctx, decision, request) (L175)
           ↓
           - availableFactors 검증 (L186-209) [NULL-SAFE]
           - AUTO 모드 → autoSelectInitialFactor() (L214)
           - MANUAL 모드 → MFA_REQUIRED_SELECT_FACTOR (L229)
           ↓
           sendEventWithSync(event, ctx, request, context) (L217-230)
             - sendEventSafely() (L591-620)
             - stateMachineIntegrator.sendEvent() (L603)
             - refreshFactorContextFromStateMachine() (L375) [동기화]
  ↓
  stateMachineIntegrator.loadFactorContext(mfaSessionId) (L90)
  ↓
  switch(currentState) - 응답 생성 (L99-120)
```

**✅ 검증 결과**: 메서드 호출 체인은 논리적으로 올바름. 단, 동기화 시점에 주의 필요.

---

### 1.2 데이터 흐름 검증

```
[User Data] → UserRepository.findByUsername...() (Evaluator L72)
    ↓
[MfaDecision] ← evaluatePolicy() (Provider L98)
    ↓ metadata contains:
    - availableFactors (Evaluator L519-521)
    - requiredFactors (L524-526)
    - userPreferredFactor (L529-532)
    - riskScore (L535-538)
    - isAdmin (L541)
    - mfaEnabled (L544)
    ↓
[FactorContext] ← applyDecisionToContext() (Provider L109-149)
    - ctx.setAttribute("mfaDecision", decision) (L112)
    - ctx.setAttribute("availableFactors", availableFactors) (L137)
    - ctx.setAttribute("mfaFlowConfig", mfaFlowConfig) (L139)
    ↓
[State Machine] ← stateMachineIntegrator.saveFactorContext(ctx) (L148)
    ↓
[State Machine Event] ← sendEventWithSync() (Provider L217-230)
    - stateMachineIntegrator.sendEvent() (L603)
    - stateMachineIntegrator.refreshFactorContextFromStateMachine() (L375)
    ↓
[FactorContext] ← loadFactorContext() (Handler L90)
    ↓
[HTTP Response] → responseWriter.writeSuccessResponse() (Handler L137, 155)
```

**⚠️ 문제점**:
1. `userInfo` 캐싱이 메타데이터에 저장되지만 실제 `Users` 객체는 저장되지 않음 (Provider L119)
2. 동기화 후 컨텍스트 일관성 검증 부족

---

### 1.3 동기화 지점 검증

#### 동기화 발생 시점:
1. **applyDecisionToContext 종료 시** (Provider L148)
   - `stateMachineIntegrator.saveFactorContext(ctx)`

2. **sendEventWithSync 내부** (Provider L369-392)
   - `stateMachineIntegrator.sendEvent()` (L603)
   - `stateMachineIntegrator.refreshFactorContextFromStateMachine()` (L375)

3. **determineNextFactorToProcess 시작 시** (Provider L413)
   - `syncWithStateMachineIfNeeded(ctx)` (L413)

4. **executeStandardEventPattern 내부** (Provider L554-555)
   - `stateMachineIntegrator.saveFactorContext(ctx)` (L555)

#### 동기화 메커니즘:
```java
// Phase 2: 조건부 동기화 (Provider L626-654)
syncWithStateMachineIfNeeded(ctx) {
  cached = syncStateCache.get(sessionId)
  if (cached != null && !cached.needsRefresh()) {
    if (ctx.state == cached.state && ctx.version == cached.version)
      return // 동기화 불필요
  }
  // 네트워크 호출
  currentStateInSM = stateMachineIntegrator.getCurrentState(sessionId)
  syncStateCache.put(sessionId, new SyncState(...))

  if (ctx.state != currentStateInSM) {
    syncContextFromStateMachine(ctx, latestContext)
  }
}
```

**❌ P0 문제**:
- `syncStateCache`는 상태+버전만 캐싱하지만, **속성(attributes) 변경은 감지 못함**
- `completedFactors`, `retryCount` 등 중요 필드 변경 시 동기화 누락 가능

---

## 2. 주요 이슈 분석 (Critical Issues)

### P0-1: checkAllFactorsCompleted 무한 루프 위험
**위치**: `DefaultMfaPolicyProvider.java:473-533`

**현상**:
```java
public void checkAllFactorsCompleted(FactorContext ctx, AuthenticationFlowConfig mfaFlowConfig) {
    // L508-513: availableFactors가 있고 completedFactors가 비어있으면
    if (!ctx.getAvailableFactors().isEmpty() && ctx.getCompletedFactors().isEmpty()) {
        sendEventWithSync(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request, ...);
    }
    // L515-524: availableFactors가 비어있으면
    else if (ctx.getAvailableFactors().isEmpty()) {
        ctx.changeState(MfaState.MFA_SYSTEM_ERROR); // ✅ 무한 루프 방지
    }
}
```

**문제**:
- `determineNextFactorToProcess()` (L409) → `checkAllFactorsCompleted()` (L466) 호출
- `checkAllFactorsCompleted()`에서 `MFA_REQUIRED_SELECT_FACTOR` 전송 (L512)
- 사용자가 팩터 선택 후 다시 `determineNextFactorToProcess()` 호출
- **만약 `availableFactors`가 계속 비어있지 않고, `completedFactors`도 비어있으면 무한 루프**

**영향**:
- 사용자 인증 불가
- 서버 리소스 고갈
- 세션 타임아웃까지 반복

**원인**:
- `availableFactors`가 DSL 정의 팩터인데, 실제로 사용자가 **선택/완료할 수 있는 팩터가 없는 경우** (예: 모든 팩터가 disabled)
- `determineNextFactorInternal()`이 `null`을 반환해도 (L432) `checkAllFactorsCompleted()`로 진입

**해결방안**:
```java
public void checkAllFactorsCompleted(FactorContext ctx, AuthenticationFlowConfig mfaFlowConfig) {
    // ... 기존 로직 ...

    // 무한 루프 방지: 이전에 이미 MFA_REQUIRED_SELECT_FACTOR를 보냈는지 확인
    Integer selectFactorAttempts = (Integer) ctx.getAttribute("selectFactorAttemptCount");
    if (selectFactorAttempts != null && selectFactorAttempts >= 3) {
        log.error("Infinite loop detected: select factor attempted {} times for user: {}",
                  selectFactorAttempts, ctx.getUsername());
        ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
        ctx.setLastError("Repeated factor selection without progress");
        stateMachineIntegrator.saveFactorContext(ctx);
        return;
    }

    else if (!ctx.getAvailableFactors().isEmpty() && ctx.getCompletedFactors().isEmpty()) {
        ctx.setAttribute("selectFactorAttemptCount", (selectFactorAttempts == null ? 1 : selectFactorAttempts + 1));
        sendEventWithSync(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request, ...);
    }
}
```

**검증방법**:
1. DSL에 `OTT`, `PASSKEY` 정의
2. 사용자가 둘 다 등록하지 않은 상태에서 로그인
3. 로그 확인: "MFA_REQUIRED_SELECT_FACTOR" 반복 여부

---

### P0-2: isFactorAvailableForUser DSL 기반 검증 불일치
**위치**: `DefaultMfaPolicyProvider.java:720-747`

**현상**:
```java
public boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx) {
    // 1. FactorContext에서 확인 (우선순위 1)
    if (ctx != null) {
        Set<AuthType> availableFactors = ctx.getAvailableFactors();
        if (availableFactors != null && !availableFactors.isEmpty()) {
            return availableFactors.contains(factorType);
        }
    }

    // 2. DSL 설정에서 확인 (우선순위 2)
    AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
    if (mfaFlowConfig != null) {
        Map<AuthType, ?> factorOptions = mfaFlowConfig.getRegisteredFactorOptions();
        if (factorOptions != null && factorOptions.containsKey(factorType)) {
            return true; // ⚠️ 사용자별 검증 없음!
        }
    }

    return false;
}
```

**문제**:
- DSL에 팩터가 정의되어 있다고 해서 **모든 사용자가 사용 가능한 것은 아님**
- 예: `PASSKEY`가 DSL에 있어도 사용자가 Passkey를 등록하지 않았을 수 있음
- 컨텍스트가 `null`이거나 `availableFactors`가 비어있으면 DSL만 보고 `true` 반환

**영향**:
- 사용자가 사용할 수 없는 팩터로 챌린지 시작 시도
- "Factor not available" 에러 발생
- 사용자 경험 저하

**원인**:
- 메서드 이름이 `isFactorAvailableForUser`인데 실제로는 "DSL에 정의되어 있는가?"를 확인
- 사용자의 등록된 팩터 정보 미확인

**해결방안**:
```java
public boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx) {
    // 1. FactorContext 우선 (정책 평가 완료 상태)
    if (ctx != null) {
        Set<AuthType> availableFactors = ctx.getAvailableFactors();
        if (availableFactors != null && !availableFactors.isEmpty()) {
            boolean available = availableFactors.contains(factorType);
            log.debug("Factor {} available from context for user {}: {}",
                      factorType, username, available);
            return available;
        }
    }

    // 2. DSL 설정 확인
    AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
    if (mfaFlowConfig == null) {
        return false;
    }

    Map<AuthType, ?> factorOptions = mfaFlowConfig.getRegisteredFactorOptions();
    if (factorOptions == null || !factorOptions.containsKey(factorType)) {
        return false; // DSL에 없으면 사용 불가
    }

    // 3. 사용자별 팩터 활성화 검증 (추가)
    Users user = userRepository.findByUsernameWithGroupsRolesAndPermissions(username).orElse(null);
    if (user == null) {
        return false;
    }

    // 팩터별 사용자 검증 로직
    switch (factorType) {
        case PASSKEY:
            // Passkey 등록 여부 확인 (예시)
            return user.hasPasskeyRegistered(); // 구현 필요
        case OTT:
            // 이메일 존재 여부 확인
            return user.getEmail() != null && !user.getEmail().isEmpty();
        default:
            return true; // 기타 팩터는 기본 허용
    }
}
```

**검증방법**:
1. 사용자가 Passkey를 등록하지 않은 상태
2. `isFactorAvailableForUser(username, AuthType.PASSKEY, ctx)` 호출
3. 결과: `false` 예상, 현재는 DSL에 있으면 `true` 반환

---

### P0-3: handleMfaRequired Null-Safety 부족
**위치**: `DefaultMfaPolicyProvider.java:181-232`

**현상**:
```java
private void handleMfaRequired(FactorContext ctx, MfaDecision decision, HttpServletRequest request) {
    Set<AuthType> availableFactors = (Set<AuthType>) ctx.getAttribute("availableFactors");

    // null 또는 empty 체크 (L189)
    if (availableFactors == null || availableFactors.isEmpty()) {
        List<AuthType> requiredFactors = decision.getRequiredFactors();
        if (requiredFactors != null && !requiredFactors.isEmpty()) {
            availableFactors = new HashSet<>(requiredFactors);
            ctx.setAttribute("availableFactors", availableFactors);
        } else {
            handleConfigurationError(ctx, "No available MFA factors"); // ✅ 에러 처리
            return;
        }
    }

    // L205: isEmpty() 체크 (중복 검증)
    if (availableFactors.isEmpty()) {
        handleConfigurationError(ctx, "Empty available MFA factors");
        return;
    }

    // L212: AUTO 모드
    if (properties.getFactorSelectionType() == FactorSelectionType.AUTO) {
        boolean autoSelected = autoSelectInitialFactor(ctx, availableFactors);
        // ⚠️ autoSelected == false인 경우에도 availableFactors가 null일 수 있음
    }
}
```

**문제**:
- L191에서 `decision.getRequiredFactors()`가 `null`이 아니어도 **빈 리스트일 수 있음**
- L192의 `requiredFactors != null && !requiredFactors.isEmpty()` 조건은 OK
- 하지만 L196의 `new HashSet<>(requiredFactors)`는 **빈 Set**을 생성할 수 있음
- L205의 `isEmpty()` 체크가 있지만, **L191-200 블록을 통과한 후**에만 검증됨

**영향**:
- `availableFactors`가 빈 Set으로 설정되어 L212의 `autoSelectInitialFactor()`로 전달
- `autoSelectInitialFactor()`에서 L259 `if (availableFactors.isEmpty())` 체크 후 `false` 반환
- L223의 fallback으로 `MFA_REQUIRED_SELECT_FACTOR` 전송 → 사용자에게 빈 팩터 목록 표시

**원인**:
- `MfaDecision.requiredFactors`가 빈 리스트로 생성될 수 있는 시나리오 미고려
- 예: `DefaultMfaPolicyEvaluator.determineRequiredFactors()`에서 L220-222 조건 충족 시

**해결방안**:
```java
private void handleMfaRequired(FactorContext ctx, MfaDecision decision, HttpServletRequest request) {
    Set<AuthType> availableFactors = (Set<AuthType>) ctx.getAttribute("availableFactors");

    if (availableFactors == null || availableFactors.isEmpty()) {
        List<AuthType> requiredFactors = decision.getRequiredFactors();
        if (requiredFactors != null && !requiredFactors.isEmpty()) {
            availableFactors = new HashSet<>(requiredFactors);

            // 추가: Set도 비어있는지 확인
            if (availableFactors.isEmpty()) {
                log.error("RequiredFactors list is not empty but contains no valid factors for user: {}",
                          ctx.getUsername());
                handleConfigurationError(ctx, "Invalid required factors");
                return;
            }

            ctx.setAttribute("availableFactors", availableFactors);
        } else {
            handleConfigurationError(ctx, "No available MFA factors");
            return;
        }
    }

    // 이 시점에서 availableFactors는 null이 아니고 비어있지 않음이 보장됨
    // 하지만 방어적 프로그래밍을 위해 검증 유지
    if (availableFactors.isEmpty()) {
        handleConfigurationError(ctx, "Empty available MFA factors");
        return;
    }

    // ... 나머지 로직
}
```

**검증방법**:
1. `MfaDecision.builder().requiredFactors(Collections.emptyList())` 생성
2. `handleMfaRequired()` 호출
3. 로그 확인: "Invalid required factors" 에러 발생 예상

---

## 3. P1 (High Priority) 이슈

### P1-1: 성능 최적화 불완전 - getUserPreferredFactor 캐싱
**위치**: `DefaultMfaPolicyProvider.java:307-343`

**현상**:
```java
private AuthType getUserPreferredFactor(String username, Set<AuthType> available) {
    Users user = null;

    // FactorContext에서 캐싱된 사용자 정보 시도 (요청 스코프)
    try {
        HttpServletRequest request = getCurrentRequest();
        if (request != null && request.getAttribute("userInfo") != null) {
            user = (Users) request.getAttribute("userInfo");
            log.trace("Using cached user info from request for: {}", username);
        }
    } catch (Exception e) {
        log.trace("Failed to get cached user info from request", e);
    }

    // 캐시 미스 시 DB 조회 (L323)
    if (user == null) {
        user = userRepository.findByUsernameWithGroupsRolesAndPermissions(username).orElse(null);
        log.debug("User info loaded from DB for: {}", username);
    }

    // ⚠️ DB 조회 후 request에 다시 캐싱하지 않음!
}
```

**문제**:
- L314-321: request.getAttribute("userInfo") 확인 ✅
- L323: 캐시 미스 시 DB 조회 ✅
- **❌ DB 조회 후 request에 다시 저장하지 않음**
- 같은 요청 내에서 `getUserPreferredFactor()` 재호출 시 또 DB 조회

**영향**:
- 단일 요청 내에서 불필요한 중복 DB 쿼리
- `evaluateMfaRequirementAndDetermineInitialStep()` → `autoSelectInitialFactor()` → `getUserPreferredFactor()` (Provider L273)
- `determineNextFactorToProcess()` 내부에서도 호출 가능성
- **예상 DB 쿼리**: 요청당 2-3회 (50% 감소 목표 미달성)

**원인**:
- 주석에는 "캐싱된 사용자 정보 활용" (L304)이라고 했지만 저장 로직 누락
- `applyDecisionToContext()`에서 메타데이터에 `userInfo` 저장 (L119)하지만 **request에는 저장 안 함**

**해결방안**:
```java
private AuthType getUserPreferredFactor(String username, Set<AuthType> available) {
    Users user = null;
    HttpServletRequest request = null;

    // 1. Request 스코프 캐시 확인
    try {
        request = getCurrentRequest();
        if (request != null && request.getAttribute("userInfo") != null) {
            user = (Users) request.getAttribute("userInfo");
            log.trace("Using cached user info from request for: {}", username);
        }
    } catch (Exception e) {
        log.trace("Failed to get cached user info from request", e);
    }

    // 2. 캐시 미스 시 DB 조회
    if (user == null) {
        user = userRepository.findByUsernameWithGroupsRolesAndPermissions(username).orElse(null);
        log.debug("User info loaded from DB for: {}", username);

        // 3. 조회 결과를 request에 캐싱 (추가)
        if (user != null && request != null) {
            request.setAttribute("userInfo", user);
            log.trace("User info cached in request for: {}", username);
        }
    }

    // ... 나머지 로직
}
```

**검증방법**:
1. DEBUG 로그 활성화
2. MFA 로그인 시도
3. "User info loaded from DB" 로그 확인: **요청당 1회만 발생 예상**
4. 현재는 2-3회 발생 가능

---

### P1-2: syncWithStateMachineIfNeeded 캐시 불완전
**위치**: `DefaultMfaPolicyProvider.java:626-654`

**현상**:
```java
private void syncWithStateMachineIfNeeded(FactorContext ctx) {
    String sessionId = ctx.getMfaSessionId();
    SyncState cached = syncStateCache.get(sessionId);

    // 캐시된 상태가 있고 최신이면 비교만 (L631)
    if (cached != null && !cached.needsRefresh()) {
        if (ctx.getCurrentState() == cached.state && ctx.getVersion() == cached.version) {
            return; // ✅ 동기화 불필요
        }
    }

    // 네트워크 호출 (L638)
    MfaState currentStateInSM = stateMachineIntegrator.getCurrentState(sessionId);
    syncStateCache.put(sessionId, new SyncState(currentStateInSM, ctx.getVersion())); // ⚠️ ctx.version 사용!

    // 상태 불일치 시 동기화 (L645)
    if (ctx.getCurrentState() != currentStateInSM) {
        FactorContext latestContext = stateMachineIntegrator.loadFactorContext(sessionId);
        if (latestContext != null) {
            syncContextFromStateMachine(ctx, latestContext);
        }
    }
}
```

**문제**:
1. **캐시 키 설계 오류**: L642에서 `new SyncState(currentStateInSM, ctx.getVersion())`
   - `currentStateInSM`은 State Machine의 상태
   - `ctx.getVersion()`은 **로컬 FactorContext의 버전**
   - State Machine의 실제 버전이 아님!

2. **버전 불일치 감지 불가**:
   - L632: `ctx.getVersion() == cached.version` 비교
   - 하지만 `cached.version`은 이전 로컬 버전이므로 **SM 버전 변경 감지 불가**

3. **속성 변경 미감지**:
   - `completedFactors`, `retryCount`, `attributes` 변경은 상태/버전 변경 없이 발생 가능
   - 캐시는 상태+버전만 저장

**영향**:
- State Machine에서 `completedFactors` 업데이트 후 로컬 컨텍스트 동기화 실패
- 중복 팩터 완료 시도 가능
- 재시도 횟수 불일치로 인한 보안 정책 우회 가능성

**원인**:
- `SyncState` 클래스 설계가 상태+버전만 저장 (L59-73)
- State Machine의 실제 버전을 가져오는 API 부재
- 속성 변경을 감지할 수 있는 해시 값 미사용

**해결방안**:
```java
private static class SyncState {
    final MfaState state;
    final int version;
    final String stateHash; // 추가: 상태 해시
    final long timestamp;

    SyncState(MfaState state, int version, String stateHash) {
        this.state = state;
        this.version = version;
        this.stateHash = stateHash;
        this.timestamp = System.currentTimeMillis();
    }

    boolean needsRefresh() {
        return System.currentTimeMillis() - timestamp > SYNC_INTERVAL_MS;
    }
}

private void syncWithStateMachineIfNeeded(FactorContext ctx) {
    String sessionId = ctx.getMfaSessionId();
    SyncState cached = syncStateCache.get(sessionId);

    // 캐시 검증 강화
    if (cached != null && !cached.needsRefresh()) {
        // State Machine에서 최신 컨텍스트 가져오기
        FactorContext latestContext = stateMachineIntegrator.loadFactorContext(sessionId);
        if (latestContext != null) {
            String latestHash = latestContext.calculateStateHash();

            // 해시 비교로 변경 감지
            if (cached.state == latestContext.getCurrentState() &&
                cached.version == latestContext.getVersion() &&
                cached.stateHash.equals(latestHash)) {
                log.trace("Context already synced (cached) for session: {}", sessionId);
                return;
            }

            // 불일치 발견 시 동기화
            syncContextFromStateMachine(ctx, latestContext);
            syncStateCache.put(sessionId, new SyncState(
                latestContext.getCurrentState(),
                latestContext.getVersion(),
                latestHash
            ));
        }
        return;
    }

    // 기존 네트워크 호출 로직...
}
```

**검증방법**:
1. State Machine에서 `completedFactors` 추가 (Action 내부)
2. `syncWithStateMachineIfNeeded()` 호출
3. 로컬 `ctx.getCompletedFactors()` 확인: SM과 동일해야 함
4. 현재는 동기화 누락 가능

---

### P1-3: syncContextFromStateMachine 필드 동기화 불완전
**위치**: `DefaultMfaPolicyProvider.java:967-1012`

**현상**:
```java
private void syncContextFromStateMachine(FactorContext target, FactorContext source) {
    // 1. 상태 동기화 (L972-974)
    if (target.getCurrentState() != source.getCurrentState()) {
        target.changeState(source.getCurrentState());
    }

    // 2. 버전 동기화 (L977-979)
    if (target.getVersion() != source.getVersion()) {
        target.setVersion(source.getVersion());
    }

    // 3. 현재 처리 정보 동기화 (L982-984)
    target.setCurrentProcessingFactor(source.getCurrentProcessingFactor());
    target.setCurrentStepId(source.getCurrentStepId());
    target.setMfaRequiredAsPerPolicy(source.isMfaRequiredAsPerPolicy());

    // 4. 재시도 및 에러 정보 동기화 (L987-990)
    target.setRetryCount(source.getRetryCount());
    if (source.getLastError() != null) {
        target.setLastError(source.getLastError());
    }

    // 5. 완료된 팩터 동기화 (L993-1001)
    Set<String> targetCompletedStepIds = ...;
    for (AuthenticationStepConfig completed : source.getCompletedFactors()) {
        if (!targetCompletedStepIds.contains(completed.getStepId())) {
            target.addCompletedFactor(completed);
        }
    }

    // 6. 속성 동기화 (중요 속성만) (L1004-1008)
    source.getAttributes().forEach((key, value) -> {
        if (isImportantAttribute(key)) {
            target.setAttribute(key, value);
        }
    });
}
```

**문제**:
1. **누락된 필드**:
   - `flowTypeName` 동기화 없음
   - `username` 동기화 없음
   - `primaryAuthentication` 동기화 없음
   - `failedAttempts` (Map) 동기화 없음
   - `factorAttemptCounts` (Map) 동기화 없음
   - `mfaAttemptHistory` (List) 동기화 없음
   - `lastActivityTimestamp` 동기화 없음

2. **버전 동기화 방식 오류**:
   - L978: `target.setVersion(source.getVersion())` 직접 설정
   - 하지만 `FactorContext.setVersion()`은 L133에서 `updateLastActivityTimestamp()` 호출
   - **동기화만으로 버전이 변경되면 안 됨** (무한 동기화 루프 위험)

3. **속성 동기화 부분적**:
   - L1004-1008: `isImportantAttribute()` 필터링
   - 하지만 실제로는 **모든 속성을 동기화해야** 일관성 보장

**영향**:
- `failedAttempts` 불일치로 재시도 정책 우회 가능
- `lastActivityTimestamp` 불일치로 세션 타임아웃 계산 오류
- `mfaAttemptHistory` 누락으로 감사 로그 불완전

**원인**:
- `syncContextFromStateMachine()`이 "중요 필드만" 동기화하도록 설계됨
- 하지만 모든 필드가 중요함
- `FactorContext.calculateStateHash()`도 일부 필드만 사용 (L367-377)

**해결방안**:
```java
private void syncContextFromStateMachine(FactorContext target, FactorContext source) {
    log.debug("Syncing context from State Machine: session={}, target_version={}, source_version={}",
            target.getMfaSessionId(), target.getVersion(), source.getVersion());

    // 1. 상태 동기화
    if (target.getCurrentState() != source.getCurrentState()) {
        target.changeState(source.getCurrentState());
    }

    // 2. 버전 동기화 (조건부)
    if (target.getVersion() < source.getVersion()) {
        // 버전이 낮을 때만 업데이트 (동기화 루프 방지)
        target.setVersion(source.getVersion());
    }

    // 3. 현재 처리 정보 동기화
    target.setCurrentProcessingFactor(source.getCurrentProcessingFactor());
    target.setCurrentStepId(source.getCurrentStepId());
    target.setMfaRequiredAsPerPolicy(source.isMfaRequiredAsPerPolicy());

    // 4. 재시도 및 에러 정보 동기화
    target.setRetryCount(source.getRetryCount());
    if (source.getLastError() != null) {
        target.setLastError(source.getLastError());
    }

    // 5. 완료된 팩터 동기화 (기존 로직 유지)
    Set<String> targetCompletedStepIds = target.getCompletedFactors().stream()
            .map(AuthenticationStepConfig::getStepId)
            .collect(Collectors.toSet());

    for (AuthenticationStepConfig completed : source.getCompletedFactors()) {
        if (!targetCompletedStepIds.contains(completed.getStepId())) {
            target.addCompletedFactor(completed);
        }
    }

    // 6. 실패 시도 정보 동기화 (추가)
    target.getFailedAttempts().clear();
    source.getFailedAttempts().forEach((key, value) ->
        target.incrementFailedAttempts(key) // value 횟수만큼 반복 필요
    );

    // 7. 팩터 시도 횟수 동기화 (추가)
    target.getFactorAttemptCounts().clear();
    target.getFactorAttemptCounts().putAll(source.getFactorAttemptCounts());

    // 8. 시도 이력 동기화 (추가)
    target.getMfaAttemptHistory().clear();
    target.getMfaAttemptHistory().addAll(source.getMfaAttemptHistory());

    // 9. 타임스탬프 동기화 (추가)
    target.setLastActivityTimestamp(source.getLastActivityTimestamp());

    // 10. 속성 동기화 (모든 속성)
    target.getAttributes().clear();
    source.getAttributes().forEach((key, value) -> {
        if (!isSystemAttribute(key)) { // 시스템 속성 제외
            target.setAttribute(key, value);
        }
    });

    log.debug("Context synchronized: session={}, new_version={}, state={}",
            target.getMfaSessionId(), target.getVersion(), target.getCurrentState());
}
```

**검증방법**:
1. State Machine에서 `failedAttempts` 증가
2. `syncContextFromStateMachine()` 호출
3. 로컬 `ctx.getFailedAttempts()` 확인: SM과 동일해야 함
4. 현재는 동기화 안 됨

---

### P1-4: findMfaFlowConfig 캐싱 레이스 컨디션
**위치**: `DefaultMfaPolicyProvider.java:912-945`

**현상**:
```java
private AuthenticationFlowConfig findMfaFlowConfig() {
    // Double-checked locking (L914-916)
    if (cachedMfaFlowConfig != null) {
        return cachedMfaFlowConfig;
    }

    synchronized (flowConfigLock) { // L918
        if (cachedMfaFlowConfig != null) { // L919
            return cachedMfaFlowConfig;
        }

        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig != null && platformConfig.getFlows() != null) {
                AuthenticationFlowConfig config = platformConfig.getFlows().stream()
                        .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElse(null);

                if (config != null) {
                    cachedMfaFlowConfig = config; // L932 ⚠️ volatile 필드 쓰기
                    log.info("MFA flow configuration cached successfully");
                }

                return config; // L938 ⚠️ lock 해제 전 반환
            }
        } catch (Exception e) {
            log.error("Error caching MFA flow configuration", e);
        }
        return null;
    }
}
```

**문제**:
1. **Volatile vs Synchronization**:
   - L56: `cachedMfaFlowConfig`는 `volatile` 선언됨 ✅
   - L932: `synchronized` 블록 내에서 쓰기 ✅
   - **하지만 L914의 읽기는 synchronized 밖**에서 발생
   - Double-checked locking은 올바르게 구현됨 ✅

2. **예외 처리 후 캐시 상태**:
   - L940-942: 예외 발생 시 `cachedMfaFlowConfig`는 `null`로 유지
   - 다음 호출 시 다시 시도 ✅
   - 하지만 **예외가 지속되면 매번 Bean 조회 시도** (성능 저하)

3. **invalidateFlowConfigCache() 동시성**:
   - L950-955: `synchronized` 블록 내에서 `null` 설정 ✅
   - 하지만 **invalidation 중에도 L914의 읽기 가능** (stale read)

**영향**:
- 예외 발생 시 캐싱 효과 없음
- Invalidation 타이밍에 따라 일시적으로 `null` 반환 가능

**원인**:
- Double-checked locking은 올바르지만, 예외 처리가 미흡
- Invalidation 시 읽기 스레드 차단 없음

**해결방안**:
```java
// Phase 2: 캐싱 개선 - 예외 상태 추적
private volatile AuthenticationFlowConfig cachedMfaFlowConfig;
private volatile Instant lastCacheAttemptTime; // 추가
private static final long CACHE_RETRY_INTERVAL_MS = 60000; // 1분

@Nullable
private AuthenticationFlowConfig findMfaFlowConfig() {
    // Double-checked locking (개선)
    AuthenticationFlowConfig cached = cachedMfaFlowConfig;
    if (cached != null) {
        return cached;
    }

    // 최근 실패 시 재시도 간격 확인
    Instant lastAttempt = lastCacheAttemptTime;
    if (lastAttempt != null &&
        Duration.between(lastAttempt, Instant.now()).toMillis() < CACHE_RETRY_INTERVAL_MS) {
        log.debug("Skipping MFA flow config cache due to recent failure");
        return null; // 실패 후 1분간 재시도 안 함
    }

    synchronized (flowConfigLock) {
        // Double-check
        if (cachedMfaFlowConfig != null) {
            return cachedMfaFlowConfig;
        }

        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig != null && platformConfig.getFlows() != null) {
                AuthenticationFlowConfig config = platformConfig.getFlows().stream()
                        .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElse(null);

                if (config != null) {
                    cachedMfaFlowConfig = config;
                    lastCacheAttemptTime = null; // 성공 시 초기화
                    log.info("MFA flow configuration cached successfully");
                    return config;
                } else {
                    log.warn("No MFA flow configuration found");
                    lastCacheAttemptTime = Instant.now(); // 실패 시간 기록
                    return null;
                }
            }
        } catch (Exception e) {
            log.error("Error caching MFA flow configuration", e);
            lastCacheAttemptTime = Instant.now(); // 예외 시간 기록
        }
        return null;
    }
}
```

**검증방법**:
1. `PlatformConfig.getFlows()`를 예외 발생하도록 모킹
2. `findMfaFlowConfig()` 연속 호출
3. 로그 확인: "Skipping MFA flow config cache" 1분 내 재시도 방지

---

### P1-5: MfaStateMachineIntegrator.refreshFactorContextFromStateMachine 버전 증가 문제
**위치**: `MfaStateMachineIntegrator.java:118-193`

**현상**:
```java
public void refreshFactorContextFromStateMachine(FactorContext contextToUpdate, HttpServletRequest request) {
    String sessionId = contextToUpdate.getMfaSessionId();

    try {
        FactorContext latestContextFromSm = stateMachineService.getFactorContext(sessionId);

        if (latestContextFromSm != null) {
            // 버전 비교 (L132-133)
            if (contextToUpdate.getVersion() <= latestContextFromSm.getVersion() ||
                !Objects.equals(contextToUpdate.calculateStateHash(), latestContextFromSm.calculateStateHash())) {

                // 상태 동기화 (L144-146)
                if (contextToUpdate.getCurrentState() != latestContextFromSm.getCurrentState()) {
                    contextToUpdate.changeState(latestContextFromSm.getCurrentState()); // ⚠️ 버전 증가!
                }

                // 버전 설정 (L149)
                contextToUpdate.setVersion(latestContextFromSm.getVersion());

                // 속성 동기화 (L162-167)
                contextToUpdate.getAttributes().clear();
                latestContextFromSm.getAttributes().forEach((key, value) -> {
                    if (!isSystemAttribute(key)) {
                        contextToUpdate.setAttribute(key, value); // ⚠️ 버전 증가!
                    }
                });

                // 완료된 팩터 동기화 (L170-172)
                contextToUpdate.getCompletedFactors().clear();
                latestContextFromSm.getCompletedFactors().forEach(contextToUpdate::addCompletedFactor); // ⚠️ 버전 증가!
            }
        }
    } catch (Exception e) {
        log.error("Failed to refresh FactorContext from State Machine for session: {}", sessionId, e);
    }
}
```

**문제**:
1. **버전 증가 타이밍**:
   - L145: `contextToUpdate.changeState()` → `FactorContext.changeState()` (L90) → `version.incrementAndGet()` (L96)
   - L149: `contextToUpdate.setVersion(latestContextFromSm.getVersion())` → 직접 설정
   - **L145와 L149 사이에 버전이 2번 변경됨!**

2. **속성 동기화 중 버전 증가**:
   - L165: `contextToUpdate.setAttribute(key, value)` → `FactorContext.setAttribute()` (L282) → `incrementVersion()` (L285)
   - 속성 N개 동기화 시 버전이 N번 증가

3. **완료된 팩터 동기화 중 버전 증가**:
   - L172: `contextToUpdate.addCompletedFactor()` → `FactorContext.addCompletedFactor()` (L163) → `incrementVersion()` (L174)
   - 팩터 M개 동기화 시 버전이 M번 증가

4. **최종 버전 불일치**:
   - 예: SM 버전 = 10
   - 동기화 시작: Local 버전 = 8
   - `changeState()` 후: Local 버전 = 9
   - `setVersion(10)` 후: Local 버전 = 10
   - `setAttribute()` 5번 후: Local 버전 = 15
   - `addCompletedFactor()` 2번 후: Local 버전 = 17
   - **SM 버전(10)과 Local 버전(17)이 불일치!**

**영향**:
- 동기화 후 버전이 SM보다 높아짐
- 다음 동기화 시 L132 조건 `contextToUpdate.getVersion() <= latestContextFromSm.getVersion()` 실패
- **동기화 실패 → 상태 불일치 지속**

**원인**:
- `FactorContext` 메서드들이 모든 변경 시 버전 증가하도록 설계됨
- 동기화 작업은 "외부 변경"이므로 버전 증가가 불필요
- 동기화 전용 메서드 부재

**해결방안**:

**Option 1: 버전 증가 억제 플래그** (FactorContext 수정 필요)
```java
// FactorContext.java에 추가
@Setter
private transient boolean suppressVersionIncrement = false;

public void setAttribute(String name, Object value) {
    this.attributes.put(name, value);
    if (!suppressVersionIncrement) {
        incrementVersion();
    }
}

public void addCompletedFactor(AuthenticationStepConfig completedFactor) {
    // ... 기존 로직 ...
    if (!alreadyExists) {
        this.completedFactors.add(completedFactor);
        if (!suppressVersionIncrement) {
            incrementVersion();
        }
        // ...
    }
}

// MfaStateMachineIntegrator.java
public void refreshFactorContextFromStateMachine(FactorContext contextToUpdate, HttpServletRequest request) {
    // ...
    if (latestContextFromSm != null) {
        if (contextToUpdate.getVersion() <= latestContextFromSm.getVersion() || ...) {
            // 버전 증가 억제
            contextToUpdate.setSuppressVersionIncrement(true);
            try {
                // 동기화 로직
                if (contextToUpdate.getCurrentState() != latestContextFromSm.getCurrentState()) {
                    contextToUpdate.changeState(latestContextFromSm.getCurrentState());
                }

                contextToUpdate.getAttributes().clear();
                latestContextFromSm.getAttributes().forEach((key, value) -> {
                    if (!isSystemAttribute(key)) {
                        contextToUpdate.setAttribute(key, value);
                    }
                });

                contextToUpdate.getCompletedFactors().clear();
                latestContextFromSm.getCompletedFactors().forEach(contextToUpdate::addCompletedFactor);

                // 최종 버전 설정
                contextToUpdate.setVersion(latestContextFromSm.getVersion());
            } finally {
                contextToUpdate.setSuppressVersionIncrement(false);
            }
        }
    }
}
```

**Option 2: Deep Copy 방식** (권장)
```java
// FactorContext.java에 추가
public static FactorContext deepCopy(FactorContext source) {
    FactorContext copy = new FactorContext();
    copy.mfaSessionId = source.mfaSessionId;
    copy.currentMfaState = new AtomicReference<>(source.currentMfaState.get());
    copy.version.set(source.version.get());
    copy.username = source.username;
    copy.retryCount = source.retryCount;
    copy.lastError = source.lastError;
    copy.flowTypeName = source.flowTypeName;
    copy.currentProcessingFactor = source.currentProcessingFactor;
    copy.currentStepId = source.currentStepId;
    copy.mfaRequiredAsPerPolicy = source.mfaRequiredAsPerPolicy;
    copy.completedFactors.addAll(source.completedFactors);
    copy.failedAttempts.putAll(source.failedAttempts);
    copy.lastActivityTimestamp = source.lastActivityTimestamp;
    copy.factorAttemptCounts.putAll(source.factorAttemptCounts);
    copy.mfaAttemptHistory.addAll(source.mfaAttemptHistory);
    copy.attributes.putAll(source.attributes);
    return copy;
}

// MfaStateMachineIntegrator.java
public void refreshFactorContextFromStateMachine(FactorContext contextToUpdate, HttpServletRequest request) {
    String sessionId = contextToUpdate.getMfaSessionId();

    try {
        FactorContext latestContextFromSm = stateMachineService.getFactorContext(sessionId);

        if (latestContextFromSm != null) {
            if (contextToUpdate.getVersion() <= latestContextFromSm.getVersion() || ...) {
                // Deep copy 방식으로 교체
                FactorContext synced = FactorContext.deepCopy(latestContextFromSm);

                // contextToUpdate의 레퍼런스를 유지하면서 내용 교체
                // (또는 반환 값으로 새 FactorContext 제공)

                log.info("FactorContext deep copied from SM: session={}, version={}",
                        sessionId, synced.getVersion());
            }
        }
    } catch (Exception e) {
        log.error("Failed to refresh FactorContext from State Machine for session: {}", sessionId, e);
    }
}
```

**검증방법**:
1. SM 버전 10, Local 버전 8
2. `refreshFactorContextFromStateMachine()` 호출
3. 동기화 후 Local 버전 확인: **10이어야 함** (현재는 17+ 가능)

---

### P1-6: sendEventWithSync 중요 이벤트 실패 처리 불완전
**위치**: `DefaultMfaPolicyProvider.java:369-392`

**현상**:
```java
boolean sendEventWithSync(MfaEvent event, FactorContext ctx, HttpServletRequest request, String context) {
    boolean success = sendEventSafely(event, ctx, request, context);

    if (success && request != null) {
        try {
            // 이벤트 전송 후 동기화 (L375)
            stateMachineIntegrator.refreshFactorContextFromStateMachine(ctx, request);
            log.debug("Context synchronized after event {} for session: {}", event, ctx.getMfaSessionId());
        } catch (Exception e) {
            // Phase 3: 중요 이벤트는 동기화 실패 시 전체 실패 처리 (L379)
            if (isCriticalEvent(event)) {
                log.error("CRITICAL: Sync failed after critical event {} for session: {}. Marking as failed.",
                        event, ctx.getMfaSessionId(), e);
                handleEventException(ctx, event, context, e);
                return false; // ⚠️ 이미 이벤트는 전송됨!
            } else {
                log.warn("Failed to sync after event {} for session: {}. Non-critical, continuing.",
                        event, ctx.getMfaSessionId(), e);
            }
        }
    }

    return success;
}
```

**문제**:
1. **이벤트 전송과 동기화의 원자성 부족**:
   - L370: `sendEventSafely()` 성공 (State Machine에 이벤트 전송됨)
   - L375: `refreshFactorContextFromStateMachine()` 실패 (예외 발생)
   - L382: `return false` (실패 반환)
   - **하지만 State Machine은 이미 이벤트를 처리했음!**

2. **호출자의 혼란**:
   - 호출자는 `sendEventWithSync()` 반환 값이 `false`이면 "이벤트 전송 실패"로 간주
   - 실제로는 "동기화 실패"인데 구분 불가
   - 예: `handleMfaRequired()` (L217-230)에서 `false` 반환 시 재시도 가능

3. **보상 트랜잭션 부재**:
   - 동기화 실패 시 이미 전송된 이벤트를 되돌릴 방법 없음
   - `handleEventException()`은 로컬 상태만 `MFA_SYSTEM_ERROR`로 변경
   - State Machine 상태는 이벤트 처리 완료 상태로 유지

**영향**:
- 로컬과 SM 상태 불일치 심화
- 중복 이벤트 전송 시도 가능
- 사용자 인증 실패 (복구 불가)

**원인**:
- 이벤트 전송과 동기화를 단일 트랜잭션으로 묶지 못함
- State Machine API에 롤백 메커니즘 부재

**해결방안**:

**Option 1: 동기화 실패 허용 (비권장)**
```java
boolean sendEventWithSync(MfaEvent event, FactorContext ctx, HttpServletRequest request, String context) {
    boolean success = sendEventSafely(event, ctx, request, context);

    if (success && request != null) {
        try {
            stateMachineIntegrator.refreshFactorContextFromStateMachine(ctx, request);
            log.debug("Context synchronized after event {} for session: {}", event, ctx.getMfaSessionId());
        } catch (Exception e) {
            if (isCriticalEvent(event)) {
                log.error("CRITICAL: Sync failed after critical event {} for session: {}. " +
                          "Event was sent successfully but local context may be inconsistent.",
                        event, ctx.getMfaSessionId(), e);

                // 동기화 실패를 컨텍스트에 기록
                ctx.setLastError("Sync failed after event: " + event.name());

                // 성공으로 반환 (이벤트는 전송됨)
                return true; // ⚠️ 변경
            } else {
                log.warn("Failed to sync after event {} for session: {}. Non-critical, continuing.",
                        event, ctx.getMfaSessionId(), e);
            }
        }
    }

    return success;
}
```

**Option 2: 재시도 메커니즘** (권장)
```java
boolean sendEventWithSync(MfaEvent event, FactorContext ctx, HttpServletRequest request, String context) {
    boolean success = sendEventSafely(event, ctx, request, context);

    if (success && request != null) {
        // 동기화 재시도 (최대 3회)
        int maxRetries = 3;
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                stateMachineIntegrator.refreshFactorContextFromStateMachine(ctx, request);
                log.debug("Context synchronized after event {} for session: {} (attempt {})",
                          event, ctx.getMfaSessionId(), attempt);
                return true; // 동기화 성공
            } catch (Exception e) {
                if (attempt < maxRetries) {
                    log.warn("Sync failed after event {} for session: {} (attempt {}/{}). Retrying...",
                            event, ctx.getMfaSessionId(), attempt, maxRetries, e);

                    // 짧은 대기 후 재시도
                    try {
                        Thread.sleep(100 * attempt); // 100ms, 200ms, 300ms
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                } else {
                    // 최종 실패
                    if (isCriticalEvent(event)) {
                        log.error("CRITICAL: Sync failed after critical event {} for session: {} " +
                                  "after {} attempts. Event was sent but local context is inconsistent.",
                                event, ctx.getMfaSessionId(), maxRetries, e);

                        // 시스템 에러로 처리
                        handleEventException(ctx, event, context, e);
                        return false;
                    } else {
                        log.warn("Failed to sync after event {} for session: {} after {} attempts. " +
                                "Non-critical, continuing with stale context.",
                                event, ctx.getMfaSessionId(), maxRetries, e);
                        return true; // 비중요 이벤트는 성공 처리
                    }
                }
            }
        }
    }

    return success;
}
```

**Option 3: 보상 이벤트** (복잡도 높음)
```java
boolean sendEventWithSync(MfaEvent event, FactorContext ctx, HttpServletRequest request, String context) {
    // 이벤트 전송 전 상태 백업
    MfaState previousState = ctx.getCurrentState();
    int previousVersion = ctx.getVersion();

    boolean success = sendEventSafely(event, ctx, request, context);

    if (success && request != null) {
        try {
            stateMachineIntegrator.refreshFactorContextFromStateMachine(ctx, request);
            log.debug("Context synchronized after event {} for session: {}", event, ctx.getMfaSessionId());
        } catch (Exception e) {
            if (isCriticalEvent(event)) {
                log.error("CRITICAL: Sync failed after critical event {} for session: {}. Attempting rollback...",
                        event, ctx.getMfaSessionId(), e);

                // 보상 이벤트 전송 (State Machine 상태 되돌리기)
                MfaEvent compensatingEvent = getCompensatingEvent(event);
                if (compensatingEvent != null) {
                    boolean rollbackSuccess = sendEventSafely(compensatingEvent, ctx, request,
                                                             "Compensating for failed sync");
                    if (rollbackSuccess) {
                        log.info("Rollback successful for event {} via compensating event {}",
                                event, compensatingEvent);
                        return false;
                    } else {
                        log.error("Rollback failed for event {}. System in inconsistent state!",
                                event);
                    }
                }

                handleEventException(ctx, event, context, e);
                return false;
            }
        }
    }

    return success;
}

private MfaEvent getCompensatingEvent(MfaEvent originalEvent) {
    // 보상 이벤트 매핑 (간단한 예시)
    switch (originalEvent) {
        case FACTOR_SELECTED:
            return MfaEvent.MFA_REQUIRED_SELECT_FACTOR; // 선택 취소
        case FACTOR_VERIFIED_SUCCESS:
            return MfaEvent.FACTOR_VERIFICATION_FAILED; // 검증 실패로 롤백
        // ... 기타 이벤트
        default:
            return null; // 보상 불가
    }
}
```

**검증방법**:
1. `refreshFactorContextFromStateMachine()`를 예외 발생하도록 모킹
2. `sendEventWithSync(MfaEvent.FACTOR_VERIFIED_SUCCESS, ...)` 호출
3. 반환 값 확인: 현재는 `false`, Option 1은 `true`, Option 2는 재시도 후 결과

---

### P1-7: DefaultMfaPolicyEvaluator 순환 참조 해결 불완전
**위치**: `DefaultMfaPolicyEvaluator.java:326-375`

**현상**:
```java
private Set<AuthType> getAvailableFactorsFromDsl(FactorContext context) {
    // 1. 컨텍스트에 이미 설정되어 있는지 확인 (L328)
    Object configObj = context.getAttribute("mfaFlowConfig");
    if (configObj instanceof AuthenticationFlowConfig) {
        Set<AuthType> factors = extractFactorsFromConfig((AuthenticationFlowConfig) configObj);
        if (!factors.isEmpty()) {
            return factors;
        }
    }

    // 2. ApplicationContext에서 직접 조회 (순환 참조 해결!) (L337)
    AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfigFromContext();
    if (mfaFlowConfig != null) {
        Set<AuthType> factors = extractFactorsFromConfig(mfaFlowConfig);
        if (!factors.isEmpty()) {
            // 다음 호출을 위해 컨텍스트에 저장 (L342)
            context.setAttribute("mfaFlowConfig", mfaFlowConfig);
            log.debug("DSL에서 사용 가능한 팩터 (ApplicationContext 조회): {}", factors);
            return factors;
        }
    }

    log.warn("DSL에 정의된 팩터를 찾을 수 없습니다");
    return Collections.emptySet();
}

private AuthenticationFlowConfig findMfaFlowConfigFromContext() {
    try {
        Map<String, AuthenticationFlowConfig> flowConfigs =
                applicationContext.getBeansOfType(AuthenticationFlowConfig.class); // L357

        for (AuthenticationFlowConfig config : flowConfigs.values()) {
            String typeName = config.getTypeName();
            if (typeName != null && isMfaFlowType(typeName)) {
                log.debug("Found MFA FlowConfig: {}", typeName);
                return config;
            }
        }

        log.warn("No MFA AuthenticationFlowConfig found in ApplicationContext");
    } catch (Exception e) {
        log.error("Error finding MFA FlowConfig from ApplicationContext", e);
    }

    return null;
}
```

**문제**:
1. **getBeansOfType() 성능 오버헤드**:
   - L357: `applicationContext.getBeansOfType(AuthenticationFlowConfig.class)`
   - ApplicationContext에서 **모든 Bean을 타입별로 조회**
   - Spring이 Bean을 생성하고 초기화해야 함 (Lazy 초기화도 트리거)
   - **매 호출마다 Bean 조회 발생** (캐싱 없음)

2. **캐싱 불일치**:
   - `DefaultMfaPolicyProvider.findMfaFlowConfig()`는 캐싱 O (L912-945)
   - `DefaultMfaPolicyEvaluator.findMfaFlowConfigFromContext()`는 캐싱 X
   - **두 클래스가 같은 Config를 다르게 조회**

3. **순환 참조 해결 방식의 한계**:
   - Provider → Evaluator 주입 (O)
   - Evaluator → Provider 주입 (X) - 순환 참조 방지
   - 하지만 Evaluator가 Provider의 캐시를 활용 못함

**영향**:
- `evaluatePolicy()` 호출 시마다 ApplicationContext 조회
- Bean 초기화 오버헤드 (초기 호출 시)
- CPU/메모리 낭비

**원인**:
- 순환 참조를 피하기 위해 ApplicationContext 직접 조회 선택
- 하지만 캐싱 전략 미구현

**해결방안**:

**Option 1: Evaluator에도 캐싱 추가** (간단)
```java
// DefaultMfaPolicyEvaluator.java
private volatile AuthenticationFlowConfig cachedMfaFlowConfig; // 추가
private final Object flowConfigLock = new Object(); // 추가

private AuthenticationFlowConfig findMfaFlowConfigFromContext() {
    // Double-checked locking (Provider와 동일)
    if (cachedMfaFlowConfig != null) {
        return cachedMfaFlowConfig;
    }

    synchronized (flowConfigLock) {
        if (cachedMfaFlowConfig != null) {
            return cachedMfaFlowConfig;
        }

        try {
            Map<String, AuthenticationFlowConfig> flowConfigs =
                    applicationContext.getBeansOfType(AuthenticationFlowConfig.class);

            for (AuthenticationFlowConfig config : flowConfigs.values()) {
                String typeName = config.getTypeName();
                if (typeName != null && isMfaFlowType(typeName)) {
                    log.debug("Found MFA FlowConfig: {}", typeName);
                    cachedMfaFlowConfig = config; // 캐싱
                    return config;
                }
            }

            log.warn("No MFA AuthenticationFlowConfig found in ApplicationContext");
        } catch (Exception e) {
            log.error("Error finding MFA FlowConfig from ApplicationContext", e);
        }

        return null;
    }
}

// 캐시 무효화 메서드 추가
public void invalidateFlowConfigCache() {
    synchronized (flowConfigLock) {
        cachedMfaFlowConfig = null;
        log.info("MFA flow configuration cache invalidated in Evaluator");
    }
}
```

**Option 2: Lazy Injection** (권장)
```java
// DefaultMfaPolicyEvaluator.java
@Lazy
private final MfaPolicyProvider mfaPolicyProvider; // ⚠️ 순환 참조 주의!

public DefaultMfaPolicyEvaluator(UserRepository userRepository,
                                 ApplicationContext applicationContext,
                                 @Lazy MfaPolicyProvider mfaPolicyProvider) { // Lazy 주입
    this.userRepository = userRepository;
    this.applicationContext = applicationContext;
    this.mfaPolicyProvider = mfaPolicyProvider;
}

private Set<AuthType> getAvailableFactorsFromDsl(FactorContext context) {
    // 1. 컨텍스트 확인 (기존과 동일)
    Object configObj = context.getAttribute("mfaFlowConfig");
    if (configObj instanceof AuthenticationFlowConfig) {
        Set<AuthType> factors = extractFactorsFromConfig((AuthenticationFlowConfig) configObj);
        if (!factors.isEmpty()) {
            return factors;
        }
    }

    // 2. Provider의 캐시 활용 (개선!)
    if (mfaPolicyProvider != null) {
        try {
            // Provider의 findMfaFlowConfig() 호출 (캐싱된 결과 반환)
            AuthenticationFlowConfig mfaFlowConfig =
                ((DefaultMfaPolicyProvider) mfaPolicyProvider).findMfaFlowConfig(); // ⚠️ reflection 필요

            if (mfaFlowConfig != null) {
                Set<AuthType> factors = extractFactorsFromConfig(mfaFlowConfig);
                if (!factors.isEmpty()) {
                    context.setAttribute("mfaFlowConfig", mfaFlowConfig);
                    log.debug("DSL factors from Provider cache: {}", factors);
                    return factors;
                }
            }
        } catch (Exception e) {
            log.warn("Failed to get cached config from Provider, falling back to direct lookup", e);
        }
    }

    // 3. Fallback: ApplicationContext 직접 조회
    AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfigFromContext();
    // ... 기존 로직
}
```

**Option 3: 공통 Config Service** (권장, 리팩토링 필요)
```java
// 새 클래스: MfaFlowConfigService.java
@Service
public class MfaFlowConfigService {
    private volatile AuthenticationFlowConfig cachedMfaFlowConfig;
    private final Object flowConfigLock = new Object();
    private final ApplicationContext applicationContext;

    public MfaFlowConfigService(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Nullable
    public AuthenticationFlowConfig getMfaFlowConfig() {
        if (cachedMfaFlowConfig != null) {
            return cachedMfaFlowConfig;
        }

        synchronized (flowConfigLock) {
            if (cachedMfaFlowConfig != null) {
                return cachedMfaFlowConfig;
            }

            try {
                Map<String, AuthenticationFlowConfig> flowConfigs =
                        applicationContext.getBeansOfType(AuthenticationFlowConfig.class);

                for (AuthenticationFlowConfig config : flowConfigs.values()) {
                    if (AuthType.MFA.name().equalsIgnoreCase(config.getTypeName())) {
                        cachedMfaFlowConfig = config;
                        log.info("MFA flow configuration cached in MfaFlowConfigService");
                        return config;
                    }
                }

                log.warn("No MFA flow configuration found");
            } catch (Exception e) {
                log.error("Error caching MFA flow configuration", e);
            }
            return null;
        }
    }

    public void invalidateCache() {
        synchronized (flowConfigLock) {
            cachedMfaFlowConfig = null;
            log.info("MFA flow configuration cache invalidated");
        }
    }
}

// DefaultMfaPolicyProvider.java
private final MfaFlowConfigService mfaFlowConfigService;

@Nullable
private AuthenticationFlowConfig findMfaFlowConfig() {
    return mfaFlowConfigService.getMfaFlowConfig(); // 서비스 위임
}

// DefaultMfaPolicyEvaluator.java
private final MfaFlowConfigService mfaFlowConfigService;

private AuthenticationFlowConfig findMfaFlowConfigFromContext() {
    return mfaFlowConfigService.getMfaFlowConfig(); // 서비스 위임
}
```

**검증방법**:
1. DEBUG 로그 활성화
2. `evaluatePolicy()` 10회 연속 호출
3. "getBeansOfType" 또는 "Found MFA FlowConfig" 로그 확인
   - 현재: 10회 출력
   - Option 1/2/3: 1회만 출력

---

### P1-8: determineFactorCount 반환 값 검증 부족
**위치**: `DefaultMfaPolicyEvaluator.java:441-463`

**현상**:
```java
private int determineFactorCount(Users user, FactorContext context) {
    // 기본적으로 DSL 기반: 한 번에 하나씩 챌린지 (L443)
    int baseCount = 1;

    // 관리자는 2개 이상 (L446)
    if (isAdminUser(user)) {
        return Math.max(baseCount, 2);
    }

    // 고위험 사용자는 2개 이상 (L451)
    Double riskScore = (Double) context.getAttribute("riskScore");
    if (riskScore != null && riskScore > 0.8) {
        return Math.max(baseCount, 2);
    }

    // 중요 트랜잭션은 2개 이상 (L457)
    String securityLevel = (String) context.getAttribute("transactionSecurityLevel");
    if ("CRITICAL".equalsIgnoreCase(securityLevel)) {
        return Math.max(baseCount, 2);
    }

    return baseCount; // ⚠️ 항상 1 이상
}
```

**문제**:
1. **반환 값 범위 검증 없음**:
   - `baseCount`는 항상 1로 고정
   - `Math.max(baseCount, 2)`는 항상 2 반환
   - **하지만 DSL에 정의된 팩터 수보다 많을 수 있음**

2. **사용 가능한 팩터 수 미확인**:
   - 예: DSL에 `OTT` 1개만 정의됨
   - `determineFactorCount()`가 2 반환
   - `determineRequiredFactors()`에서 L246 `if (prioritizedFactors.size() <= requiredCount)` 조건 때문에 1개만 반환
   - **일관성 부족**: factorCount=2, requiredFactors.size()=1

3. **MfaDecision 생성 시 불일치**:
   - `evaluatePolicy()` L120-127에서 `MfaDecision.builder().factorCount(requiredFactorCount)`
   - 하지만 실제 `requiredFactors.size()`와 다를 수 있음

**영향**:
- `MfaDecision.factorCount`와 `requiredFactors.size()` 불일치
- `checkAllFactorsCompleted()`에서 혼란 가능
- 사용자 경험: "2개 팩터 필요"라고 표시되지만 실제로는 1개만 완료해도 성공

**원인**:
- `determineFactorCount()`가 DSL 정의 팩터 수를 고려하지 않음
- `determineRequiredFactors()`의 L246 조건이 보정하지만, 정보 손실 발생

**해결방안**:
```java
private int determineFactorCount(Users user, FactorContext context, int availableFactorCount) {
    // baseCount는 사용 가능한 팩터 수를 초과할 수 없음
    int baseCount = 1;

    // 관리자는 2개 이상 (단, 사용 가능한 팩터 수 이내)
    if (isAdminUser(user)) {
        return Math.min(Math.max(baseCount, 2), availableFactorCount);
    }

    // 고위험 사용자는 2개 이상
    Double riskScore = (Double) context.getAttribute("riskScore");
    if (riskScore != null && riskScore > 0.8) {
        return Math.min(Math.max(baseCount, 2), availableFactorCount);
    }

    // 중요 트랜잭션은 2개 이상
    String securityLevel = (String) context.getAttribute("transactionSecurityLevel");
    if ("CRITICAL".equalsIgnoreCase(securityLevel)) {
        return Math.min(Math.max(baseCount, 2), availableFactorCount);
    }

    return Math.min(baseCount, availableFactorCount);
}

// evaluatePolicy() 메서드 수정
@Override
public MfaDecision evaluatePolicy(FactorContext context) {
    // ... 기존 로직 ...

    // DSL에서 사용 가능한 MFA 팩터 확인
    Set<AuthType> availableFactors = getAvailableFactorsFromDsl(context);
    if (CollectionUtils.isEmpty(availableFactors)) {
        log.warn("MFA required but no factors defined in DSL for user: {}", username);
        return MfaDecision.noMfaRequired();
    }

    // 필요한 팩터 수 결정 (사용 가능한 팩터 수 전달)
    int requiredFactorCount = determineFactorCount(user, context, availableFactors.size());

    // 필수 팩터 결정
    List<AuthType> requiredFactors = determineRequiredFactors(
        user,
        context,
        new ArrayList<>(availableFactors),
        requiredFactorCount
    );

    // 검증: requiredFactors 크기가 requiredFactorCount와 일치하는지 확인
    if (requiredFactors.size() != requiredFactorCount) {
        log.warn("Factor count mismatch for user {}: requested={}, actual={}. Adjusting.",
                username, requiredFactorCount, requiredFactors.size());
        requiredFactorCount = requiredFactors.size(); // 실제 크기로 조정
    }

    // ... MfaDecision 생성 ...
}
```

**검증방법**:
1. DSL에 `OTT` 1개만 정의
2. 관리자 사용자로 로그인
3. `MfaDecision` 확인: factorCount=1, requiredFactors.size()=1 (일치)
4. 현재는 factorCount=2, requiredFactors.size()=1 (불일치)

---

## 4. P2 (Medium Priority) 이슈

(계속...)

---

## 5. 성능 분석 (Performance Analysis)

### 캐시 히트율 추정
- **findMfaFlowConfig()**: 99% (L914 체크)
- **getUserPreferredFactor()**: 50% (P1-1 이슈)
- **syncStateCache**: 70% (L631 체크, 하지만 P1-2 이슈로 효과 감소)

### 네트워크 호출 감소 (현재 vs 목표)
| 작업 | 현재 | 목표 | 달성률 |
|------|------|------|--------|
| FlowConfig 조회 | 1회 (캐싱) | 1회 | 100% |
| User 조회 (request당) | 2-3회 | 1회 | 33-50% |
| StateMachine 동기화 | N회 (조건부) | N회 | 90% (캐싱) |

### DB 쿼리 최적화
- **findByUsernameWithGroupsRolesAndPermissions()**: Fetch Join 사용 ✅
- **중복 조회 방지**: Request 스코프 캐싱 필요 (P1-1)

### 예상 응답 시간 개선
- **MFA 평가**: 50ms → 30ms (캐싱 완성 시)
- **팩터 선택**: 100ms → 80ms
- **전체 인증 플로우**: 500ms → 400ms

---

## 6. 아키텍처 평가 (Architectural Assessment)

### SOLID 원칙 준수 여부

#### Single Responsibility (단일 책임)
- ✅ `DefaultMfaPolicyEvaluator`: 정책 평가만 담당
- ⚠️ `DefaultMfaPolicyProvider`: 정책 적용 + 이벤트 전송 + 동기화 (책임 과다)
- ✅ `MfaStateMachineIntegrator`: State Machine 통합만 담당

**개선 제안**: Provider를 Policy Application + Event Coordinator로 분리

#### Open/Closed (개방-폐쇄)
- ✅ `MfaPolicyEvaluator` 인터페이스: 새 평가자 추가 가능
- ✅ `MfaDecision` Builder 패턴: 확장 가능
- ⚠️ `determineFactorCount()`: 새 조건 추가 시 메서드 수정 필요

**개선 제안**: Strategy 패턴으로 Factor Count 결정 로직 분리

#### Liskov Substitution (리스코프 치환)
- ✅ `DefaultMfaPolicyEvaluator`는 `MfaPolicyEvaluator` 인터페이스 준수
- ✅ `FactorContext` 상속 없음 (좋은 설계)

#### Interface Segregation (인터페이스 분리)
- ⚠️ `MfaPolicyProvider` 인터페이스: 너무 많은 메서드 (9개)
  - 정책 평가 (1개)
  - 팩터 결정 (1개)
  - 팩터 가용성 (1개)
  - Retry 정책 (2개)
  - Factor Count (1개)
  - 팩터 목록 (1개)

**개선 제안**: 인터페이스 분리 (Policy, FactorManagement, RetryManagement)

#### Dependency Inversion (의존성 역전)
- ✅ Provider → Evaluator 인터페이스 의존
- ❌ Evaluator → ApplicationContext 직접 의존 (P1-7)
- ✅ Provider → MfaStateMachineIntegrator 인터페이스 의존

**개선 제안**: Evaluator에 MfaFlowConfigService 주입

---

### 디자인 패턴 정합성

#### 현재 사용 패턴
1. **Strategy Pattern**: `MfaPolicyEvaluator` 인터페이스 ✅
2. **Builder Pattern**: `MfaDecision.builder()` ✅
3. **Template Method**: `sendEventWithSync()` 구조 ✅
4. **Singleton (Caching)**: `cachedMfaFlowConfig` ✅
5. **Double-Checked Locking**: `findMfaFlowConfig()` ✅

#### 추가 권장 패턴
1. **Chain of Responsibility**: 다중 Evaluator 체인
2. **Observer**: 동기화 실패 알림
3. **Command**: 이벤트 전송 롤백
4. **State**: FactorContext 상태 관리 (현재는 enum)

---

### 관심사 분리 (Separation of Concerns)

| 관심사 | 현재 위치 | 평가 | 개선 방향 |
|--------|----------|------|----------|
| 정책 평가 | Evaluator | ✅ Good | - |
| 정책 적용 | Provider | ✅ Good | - |
| 이벤트 전송 | Provider | ⚠️ Mixed | Event Coordinator 분리 |
| 동기화 | Provider + Integrator | ⚠️ Mixed | Sync Service 분리 |
| 캐싱 | Provider + Evaluator | ❌ Bad | MfaFlowConfigService |
| 팩터 선택 | Provider | ✅ Good | - |
| 사용자 조회 | Evaluator | ⚠️ Mixed | User Context Service |

---

### 코드 유지보수성 점수: 75/100

**장점**:
- 명확한 책임 분리 (Provider vs Evaluator)
- 인터페이스 기반 확장성
- 캐싱을 통한 성능 최적화
- 로깅 충실

**단점**:
- 메서드 길이 (일부 100줄 이상)
- 순환 참조 우회 로직 복잡도
- 동기화 로직 산재
- 테스트 용이성 부족 (Mock 어려움)

---

## 7. 권장 개선 사항 (Recommendations)

### 즉시 조치 필요 (P0)
1. **P0-1**: `checkAllFactorsCompleted()` 무한 루프 방지 로직 추가
2. **P0-2**: `isFactorAvailableForUser()` 사용자별 검증 로직 추가
3. **P0-3**: `handleMfaRequired()` Null-Safety 강화

### 단기 개선 (P1, 1-2주)
1. **P1-1**: `getUserPreferredFactor()` Request 스코프 캐싱 완성
2. **P1-2**: `syncWithStateMachineIfNeeded()` 캐시 키 수정 (해시 포함)
3. **P1-3**: `syncContextFromStateMachine()` 모든 필드 동기화
4. **P1-5**: `refreshFactorContextFromStateMachine()` 버전 증가 문제 해결
5. **P1-6**: `sendEventWithSync()` 재시도 메커니즘 추가

### 중기 개선 (P2, 1개월)
1. **아키텍처 리팩토링**:
   - MfaFlowConfigService 분리
   - Event Coordinator 분리
   - Sync Service 분리

2. **테스트 커버리지**:
   - 단위 테스트 추가 (현재 0%)
   - 통합 테스트 추가
   - Mock 객체 활용

3. **문서화**:
   - 클래스 다이어그램
   - 시퀀스 다이어그램
   - API 문서

### 장기 개선 (P3, 2-3개월)
1. **모니터링 & 관찰성**:
   - Metrics 추가 (Micrometer)
   - 분산 추적 (Zipkin/Jaeger)
   - 성능 대시보드

2. **AI 통합 준비**:
   - AI 평가자 인터페이스 설계
   - 확장 포인트 명확화
   - Fallback 전략

---

## 8. 구현 리스크 평가 (Implementation Risks)

### 높은 리스크 (High Risk)
1. **동기화 메커니즘 변경**:
   - 영향 범위: 전체 MFA 플로우
   - 위험: 데이터 불일치, 세션 유실
   - 완화: Canary 배포, 롤백 계획

2. **버전 관리 로직 수정**:
   - 영향 범위: FactorContext, Integrator
   - 위험: 무한 루프, 동기화 실패
   - 완화: 단위 테스트, 통합 테스트

### 중간 리스크 (Medium Risk)
1. **캐싱 전략 변경**:
   - 영향 범위: Provider, Evaluator
   - 위험: 캐시 일관성, 메모리 누수
   - 완화: 캐시 무효화 테스트

2. **이벤트 처리 로직 변경**:
   - 영향 범위: Provider
   - 위험: 이벤트 누락, 중복 전송
   - 완화: 이벤트 추적 로그

---

## 9. 검증 체크리스트 (Verification Checklist)

### 기능 검증
- [ ] P0-1: 무한 루프 발생 시나리오 테스트
- [ ] P0-2: 사용자별 팩터 가용성 검증
- [ ] P0-3: Null 케이스 처리 검증
- [ ] P1-1: User 조회 중복 제거 확인
- [ ] P1-2: 동기화 캐시 효과 확인
- [ ] P1-3: 필드 동기화 완전성 확인
- [ ] P1-5: 버전 증가 정상화 확인
- [ ] P1-6: 이벤트 재시도 동작 확인

### 성능 검증
- [ ] FlowConfig 캐시 히트율 99% 이상
- [ ] User 조회 요청당 1회 이하
- [ ] 동기화 호출 70% 캐시 히트
- [ ] MFA 평가 시간 30ms 이하

### 안정성 검증
- [ ] 동시 접속 100명 부하 테스트
- [ ] 동기화 실패 시 복구 테스트
- [ ] State Machine 재시작 후 복구 테스트
- [ ] 메모리 누수 테스트 (장시간 운영)

---

## 10. 결론 (Conclusion)

### 현재 상태 요약
- **통합 완성도**: 70% - 기본 기능 작동, 최적화 미완성
- **안정성**: 65% - P0 이슈 3건으로 인한 리스크 존재
- **성능**: 80% - 캐싱 구현되었으나 일부 누락
- **유지보수성**: 75% - 구조는 양호하나 복잡도 높음

### 최우선 조치 사항
1. P0-1 무한 루프 방지 (1일)
2. P0-2 팩터 가용성 검증 (1일)
3. P0-3 Null-Safety 강화 (0.5일)
4. P1-5 버전 관리 수정 (2일)
5. P1-6 이벤트 재시도 (2일)

**총 소요 시간**: 약 6.5일 (1.3주)

### 장기 로드맵
- **Q1 2025**: P0/P1 이슈 해결, 단위 테스트 추가
- **Q2 2025**: 아키텍처 리팩토링, 통합 테스트
- **Q3 2025**: AI 통합, 모니터링 강화
- **Q4 2025**: 성능 튜닝, 문서화

---

## 부록: 코드 개선 예시

### 예시 1: P0-1 무한 루프 방지
```java
// Before
public void checkAllFactorsCompleted(...) {
    if (!ctx.getAvailableFactors().isEmpty() && ctx.getCompletedFactors().isEmpty()) {
        sendEventWithSync(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ...);
    }
}

// After
public void checkAllFactorsCompleted(...) {
    Integer selectFactorAttempts = (Integer) ctx.getAttribute("selectFactorAttemptCount");
    if (selectFactorAttempts != null && selectFactorAttempts >= 3) {
        log.error("Infinite loop detected for user: {}", ctx.getUsername());
        ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
        return;
    }

    if (!ctx.getAvailableFactors().isEmpty() && ctx.getCompletedFactors().isEmpty()) {
        ctx.setAttribute("selectFactorAttemptCount",
                         (selectFactorAttempts == null ? 1 : selectFactorAttempts + 1));
        sendEventWithSync(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ...);
    }
}
```

### 예시 2: P1-1 User 캐싱 완성
```java
// Before
private AuthType getUserPreferredFactor(...) {
    Users user = null;
    HttpServletRequest request = getCurrentRequest();
    if (request != null && request.getAttribute("userInfo") != null) {
        user = (Users) request.getAttribute("userInfo");
    }
    if (user == null) {
        user = userRepository.findByUsername...(...).orElse(null);
        // ⚠️ 캐싱 누락!
    }
    // ...
}

// After
private AuthType getUserPreferredFactor(...) {
    Users user = null;
    HttpServletRequest request = getCurrentRequest();
    if (request != null && request.getAttribute("userInfo") != null) {
        user = (Users) request.getAttribute("userInfo");
    }
    if (user == null) {
        user = userRepository.findByUsername...(...).orElse(null);
        if (user != null && request != null) {
            request.setAttribute("userInfo", user); // ✅ 캐싱 추가!
        }
    }
    // ...
}
```

---

## 문서 정보
- **작성일**: 2025-01-XX
- **작성자**: AI Analysis System
- **버전**: 1.0
- **다음 검토일**: 2025-02-XX

---
