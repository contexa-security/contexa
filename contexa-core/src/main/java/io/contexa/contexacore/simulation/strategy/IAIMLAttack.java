package io.contexa.contexacore.simulation.strategy;

import io.contexa.contexacore.domain.entity.AttackResult;

import java.util.Map;

/**
 * AI/ML 공격 전략 인터페이스
 *
 * AI 및 머신러닝 모델을 대상으로 한 공격 시뮬레이션
 */
public interface IAIMLAttack extends IAttackStrategy {

    /**
     * 모델 포이즈닝 공격
     * 학습 데이터를 오염시켜 모델 성능 저하
     */
    AttackResult poisonModel(String targetModel, Map<String, Object> poisonData);

    /**
     * 적대적 회피 공격
     * 탐지를 회피하는 적대적 예제 생성
     */
    AttackResult evadeDetection(String model, Map<String, Object> adversarialInput);

    /**
     * 프롬프트 인젝션 공격
     * LLM에 악의적인 프롬프트 주입
     */
    AttackResult injectPrompt(String prompt, String targetBehavior);

    /**
     * 모델 추출 공격
     * API 쿼리를 통한 모델 복제
     */
    AttackResult extractModel(String targetModel, int queryBudget);

    /**
     * 학습 데이터 조작
     * 모델 학습 과정 조작
     */
    AttackResult manipulateTraining(String dataset, Map<String, Object> manipulation);

    /**
     * 편향 악용
     * 모델의 편향을 악용한 공격
     */
    AttackResult exploitBias(String model, String biasType);

    /**
     * 백도어 공격
     * 모델에 백도어 설치
     */
    AttackResult backdoorModel(String triggerPattern, String targetOutcome);

    /**
     * 개인정보 추론
     * 모델에서 개인정보 추출
     */
    AttackResult inferPrivateData(String model, String[] queries);
}