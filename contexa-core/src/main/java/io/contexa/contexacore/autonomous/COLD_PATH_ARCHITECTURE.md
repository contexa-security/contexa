# Cold Path Architecture - contexa

## Overview
contexa의 자율 보안 시스템은 벡터 유사도 기반으로 Hot Path와 Cold Path를 자동으로 라우팅합니다.

## 핵심 원칙
- **높은 유사도 (>0.85)**: Hot Path - 빠른 처리 (<50ms)
- **낮은 유사도 (≤0.85)**: Cold Path - 3-tier AI 분석

## Processing Mode 매핑

### 유사도 기반 라우팅 (RoutingDecisionHandler)
```
유사도 > 0.85    → PASS_THROUGH         → PassThroughStrategy (Hot Path)
유사도 0.6-0.85  → ASYNC_WITH_MONITORING → AsyncMonitoringStrategy (Cold Path)
유사도 0.3-0.6   → INVESTIGATE           → InvestigateStrategy (Cold Path)
유사도 < 0.3     → REALTIME_ESCALATE     → RealtimeEscalateStrategy (Cold Path)
```

### 전략 클래스별 역할

#### 1. PassThroughStrategy (Hot Path)
- **유사도**: > 0.85
- **처리**: HotPathEventProcessor 사용
- **목적**: 정상 패턴 빠른 통과
- **응답 시간**: <50ms

#### 2. AsyncMonitoringStrategy (Cold Path)
- **유사도**: 0.6-0.85
- **처리**: ColdPathEventProcessor 사용
- **목적**: 중간 위험, 비동기 모니터링
- **특징**: 즉시 허용 + 백그라운드 분석

#### 3. InvestigateStrategy (Cold Path)
- **유사도**: 0.3-0.6
- **처리**: ColdPathEventProcessor 사용
- **목적**: 낮은 유사도, 상세 조사
- **특징**: 3-tier AI 분석 수행

#### 4. RealtimeEscalateStrategy (Cold Path)
- **유사도**: < 0.3
- **처리**: ColdPathEventProcessor 사용
- **목적**: 매우 낮은 유사도, 즉시 에스컬레이션
- **특징**: Layer 1 → Layer 2 → Layer 3 실시간 에스컬레이션

## Handler 실행 순서
1. ValidationHandler (10)
2. VectorSimilarityHandler (15) - 유사도 계산
3. RoutingDecisionHandler (40) - ProcessingMode 결정
4. ProcessingExecutionHandler (50) - Strategy 실행
5. TrustScoreHandler (55) - AI 분석 후 Trust Score 업데이트
6. MetricsHandler (60)

## 3-Tier AI Processing (Cold Path)

### Layer 1: Rule-based (10-50ms)
- 기본 규칙 기반 검증
- 알려진 패턴 매칭

### Layer 2: Statistical + Lightweight AI (100-500ms)
- 통계적 이상 탐지
- TinyLlama 1.1B 모델

### Layer 3: Expert AI (500ms-5s)
- 전문가 수준 AI 분석
- Phi-3-mini 또는 더 큰 모델
- SOAR 통합

## 최근 변경사항 (2025-09-25)

### 삭제된 전략
- ~~AsyncEscalateStrategy~~ - 사용되지 않음, AsyncMonitoringStrategy와 중복
- ~~RealtimeBlockStrategy~~ - ProcessingMode는 있지만 전략 구현 불필요
- ~~RealtimeMitigateStrategy~~ - ProcessingMode는 있지만 전략 구현 불필요

### 수정사항
1. RealtimeEscalateStrategy: HotPathEventProcessor → ColdPathEventProcessor 변경
2. TrustScoreHandler: 실행 순서 25 → 55 (AI 분석 후 실행)
3. RoutingDecisionHandler: 사용하지 않는 ProcessingMode 참조 제거

## Zero Trust 원칙
- 유사도가 없으면 INVESTIGATE (Cold Path)로 기본 라우팅
- 불확실한 경우 항상 위험으로 간주
- AI 분석 완료 후에만 Trust Score 업데이트