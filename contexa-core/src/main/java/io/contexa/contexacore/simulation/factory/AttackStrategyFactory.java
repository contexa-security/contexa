package io.contexa.contexacore.simulation.factory;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.strategy.IAttackStrategy;
import io.contexa.contexacore.simulation.strategy.impl.*;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * 공격 전략 팩토리
 *
 * Factory Pattern을 사용하여 공격 전략 인스턴스를 생성하고 관리합니다.
 * 전략의 생명주기와 재사용을 효율적으로 관리합니다.
 */
@Component
public class AttackStrategyFactory {
    private static final Logger logger = LoggerFactory.getLogger(AttackStrategyFactory.class);

    // 전략 생성자 레지스트리
    private final Map<String, Supplier<IAttackStrategy>> strategySuppliers = new HashMap<>();

    // 싱글톤 전략 캐시
    private final Map<String, IAttackStrategy> singletonStrategies = new ConcurrentHashMap<>();

    // 전략 메타데이터
    private final Map<String, StrategyMetadata> strategyMetadata = new HashMap<>();

    // Event publisher for all strategies
    private SimulationEventPublisher eventPublisher;

    @Autowired
    public AttackStrategyFactory(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
        registerStrategies();
    }
    
    /**
     * 전략 등록
     */
    private void registerStrategies() {
        // 인증 공격 전략
        registerStrategy("BRUTE_FORCE", 
            BruteForceStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.BRUTE_FORCE,
                IAttackStrategy.AttackCategory.AUTHENTICATION,
                "Brute force password attack",
                true // 싱글톤
            )
        );
        
        registerStrategy("CREDENTIAL_STUFFING",
            CredentialStuffingStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.CREDENTIAL_STUFFING,
                IAttackStrategy.AttackCategory.AUTHENTICATION,
                "Credential stuffing using leaked databases",
                true
            )
        );
        
        registerStrategy("SESSION_HIJACKING",
            SessionHijackingStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.SESSION_HIJACKING,
                IAttackStrategy.AttackCategory.SESSION,
                "Session hijacking and token manipulation",
                true
            )
        );
        
        // 인가 공격 전략
        registerStrategy("PRIVILEGE_ESCALATION",
            PrivilegeEscalationStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.PRIVILEGE_ESCALATION,
                IAttackStrategy.AttackCategory.AUTHORIZATION,
                "Privilege escalation attack",
                true
            )
        );
        
        registerStrategy("IDOR",
            IDORStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.IDOR,
                IAttackStrategy.AttackCategory.AUTHORIZATION,
                "Insecure Direct Object Reference attack",
                true
            )
        );
        
        registerStrategy("API_BYPASS",
            APIBypassStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.API_BYPASS,
                IAttackStrategy.AttackCategory.AUTHORIZATION,
                "API authorization bypass attack",
                true
            )
        );
        
        // 행동 기반 공격 전략
        registerStrategy("IMPOSSIBLE_TRAVEL",
            ImpossibleTravelStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.IMPOSSIBLE_TRAVEL,
                IAttackStrategy.AttackCategory.BEHAVIORAL,
                "Impossible travel detection evasion",
                true
            )
        );

        // 고급 인증 공격 전략
        registerStrategy("TOKEN_REPLAY",
            TokenReplayStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.TOKEN_REPLAY,
                IAttackStrategy.AttackCategory.AUTHENTICATION,
                "Token replay attack using expired tokens",
                true
            )
        );

        registerStrategy("PASSWORD_SPRAY",
            PasswordSprayStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.PASSWORD_SPRAY,
                IAttackStrategy.AttackCategory.AUTHENTICATION,
                "Password spray attack across multiple accounts",
                true
            )
        );

        registerStrategy("MFA_BYPASS",
            MFABypassStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.MFA_BYPASS,
                IAttackStrategy.AttackCategory.AUTHENTICATION,
                "Multi-factor authentication bypass",
                true
            )
        );

        // 추가 행동 기반 공격 전략
        registerStrategy("BEHAVIORAL_ANOMALY",
            BehavioralAnomalyStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.BEHAVIORAL_ANOMALY,
                IAttackStrategy.AttackCategory.BEHAVIORAL,
                "Behavioral anomaly attack simulation",
                true
            )
        );

        registerStrategy("VELOCITY_ATTACK",
            VelocityAttackStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.VELOCITY_ATTACK,
                IAttackStrategy.AttackCategory.BEHAVIORAL,
                "High velocity attack patterns",
                true
            )
        );

        registerStrategy("SEQUENCE_BREAKING",
            SequenceBreakingStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.SEQUENCE_BREAKING,
                IAttackStrategy.AttackCategory.BEHAVIORAL,
                "Workflow sequence breaking attack",
                true
            )
        );

        // API 공격 전략
        registerStrategy("API_ABUSE",
            APIAbuseStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.API_ABUSE,
                IAttackStrategy.AttackCategory.API,
                "API abuse and business logic exploitation",
                true
            )
        );

        registerStrategy("GRAPHQL_INJECTION",
            GraphQLInjectionStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.GRAPHQL_INJECTION,
                IAttackStrategy.AttackCategory.API,
                "GraphQL injection and query manipulation",
                true
            )
        );

        registerStrategy("RATE_LIMIT_BYPASS",
            RateLimitBypassStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.RATE_LIMIT_BYPASS,
                IAttackStrategy.AttackCategory.API,
                "Rate limiting bypass techniques",
                true
            )
        );

        registerStrategy("API_KEY_EXPOSURE",
            APIKeyExposureStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.API_KEY_EXPOSURE,
                IAttackStrategy.AttackCategory.API,
                "API key exposure and exploitation",
                true
            )
        );

        // AI/ML 공격 전략
        registerStrategy("MODEL_POISONING",
            ModelPoisoningStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.MODEL_POISONING,
                IAttackStrategy.AttackCategory.AI_ML,
                "AI/ML model poisoning attack",
                true
            )
        );

        registerStrategy("ADVERSARIAL_EVASION",
            AdversarialEvasionStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.ADVERSARIAL_EVASION,
                IAttackStrategy.AttackCategory.AI_ML,
                "Adversarial example generation for evasion",
                true
            )
        );

        registerStrategy("PROMPT_INJECTION",
            PromptInjectionStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.PROMPT_INJECTION,
                IAttackStrategy.AttackCategory.AI_ML,
                "LLM prompt injection attack",
                true
            )
        );

        registerStrategy("MODEL_EXTRACTION",
            ModelExtractionStrategy::new,
            new StrategyMetadata(
                AttackResult.AttackType.MODEL_EXTRACTION,
                IAttackStrategy.AttackCategory.AI_ML,
                "Model extraction through API queries",
                true
            )
        );

        logger.info("Registered {} attack strategies", strategySuppliers.size());
    }
    
    /**
     * 전략 등록
     */
    private void registerStrategy(String name, Supplier<IAttackStrategy> supplier, StrategyMetadata metadata) {
        strategySuppliers.put(name, supplier);
        strategyMetadata.put(name, metadata);
    }
    
    /**
     * 전략 생성
     */
    public IAttackStrategy createStrategy(String strategyName) {
        StrategyMetadata metadata = strategyMetadata.get(strategyName);

        if (metadata == null) {
            throw new IllegalArgumentException("Unknown strategy: " + strategyName);
        }

        IAttackStrategy strategy;

        // 싱글톤 전략인 경우 캐시에서 반환
        if (metadata.isSingleton()) {
            strategy = singletonStrategies.computeIfAbsent(strategyName, k -> {
                logger.debug("Creating singleton instance of strategy: {}", strategyName);
                IAttackStrategy newStrategy = strategySuppliers.get(strategyName).get();
                // Set event publisher for the strategy
                if (eventPublisher != null) {
                    newStrategy.setEventPublisher(eventPublisher);
                }
                return newStrategy;
            });
        } else {
            // 매번 새 인스턴스 생성
            logger.debug("Creating new instance of strategy: {}", strategyName);
            strategy = strategySuppliers.get(strategyName).get();
            // Set event publisher for the strategy
            if (eventPublisher != null) {
                strategy.setEventPublisher(eventPublisher);
            }
        }

        return strategy;
    }

    /**
     * 전략 생성 (with explicit event publisher)
     */
    public IAttackStrategy createStrategy(String strategyName, SimulationEventPublisher publisher) {
        IAttackStrategy strategy = createStrategy(strategyName);
        if (publisher != null) {
            strategy.setEventPublisher(publisher);
        }
        return strategy;
    }

    /**
     * 전략 조회 (createStrategy의 별칭)
     */
    public IAttackStrategy getStrategy(String strategyName) {
        return createStrategy(strategyName);
    }
    
    /**
     * 타입별 전략 생성
     */
    public IAttackStrategy createStrategyByType(AttackResult.AttackType type) {
        for (Map.Entry<String, StrategyMetadata> entry : strategyMetadata.entrySet()) {
            if (entry.getValue().getType() == type) {
                return createStrategy(entry.getKey());
            }
        }
        throw new IllegalArgumentException("No strategy found for type: " + type);
    }
    
    /**
     * 카테고리별 전략 목록 조회
     */
    public List<IAttackStrategy> getStrategiesByCategory(IAttackStrategy.AttackCategory category) {
        List<IAttackStrategy> strategies = new ArrayList<>();
        
        for (Map.Entry<String, StrategyMetadata> entry : strategyMetadata.entrySet()) {
            if (entry.getValue().getCategory() == category) {
                strategies.add(createStrategy(entry.getKey()));
            }
        }
        
        return strategies;
    }
    
    /**
     * 모든 전략 이름 조회
     */
    public Set<String> getAllStrategyNames() {
        return new HashSet<>(strategySuppliers.keySet());
    }
    
    /**
     * 전략 메타데이터 조회
     */
    public StrategyMetadata getStrategyMetadata(String strategyName) {
        return strategyMetadata.get(strategyName);
    }
    
    /**
     * 전략 검증
     */
    public boolean validateStrategy(String strategyName) {
        if (!strategySuppliers.containsKey(strategyName)) {
            return false;
        }
        
        try {
            IAttackStrategy strategy = createStrategy(strategyName);
            return strategy != null;
        } catch (Exception e) {
            logger.error("Failed to validate strategy {}: {}", strategyName, e.getMessage());
            return false;
        }
    }
    
    /**
     * 무작위 전략 선택
     */
    public IAttackStrategy getRandomStrategy() {
        List<String> names = new ArrayList<>(strategySuppliers.keySet());
        if (names.isEmpty()) {
            throw new IllegalStateException("No strategies registered");
        }
        
        String randomName = names.get(new Random().nextInt(names.size()));
        return createStrategy(randomName);
    }
    
    /**
     * 카테고리에서 무작위 전략 선택
     */
    public IAttackStrategy getRandomStrategyFromCategory(IAttackStrategy.AttackCategory category) {
        List<String> matchingStrategies = new ArrayList<>();
        
        for (Map.Entry<String, StrategyMetadata> entry : strategyMetadata.entrySet()) {
            if (entry.getValue().getCategory() == category) {
                matchingStrategies.add(entry.getKey());
            }
        }
        
        if (matchingStrategies.isEmpty()) {
            throw new IllegalArgumentException("No strategies found for category: " + category);
        }
        
        String randomName = matchingStrategies.get(new Random().nextInt(matchingStrategies.size()));
        return createStrategy(randomName);
    }
    
    /**
     * 전략 통계
     */
    public StrategyStatistics getStatistics() {
        StrategyStatistics stats = new StrategyStatistics();
        stats.setTotalStrategies(strategySuppliers.size());
        stats.setSingletonStrategies((int) strategyMetadata.values().stream()
            .filter(StrategyMetadata::isSingleton).count());
        
        Map<IAttackStrategy.AttackCategory, Integer> categoryCount = new HashMap<>();
        for (StrategyMetadata metadata : strategyMetadata.values()) {
            categoryCount.merge(metadata.getCategory(), 1, Integer::sum);
        }
        stats.setStrategiesByCategory(categoryCount);
        
        return stats;
    }
    
    /**
     * 전략 메타데이터
     */
    public static class StrategyMetadata {
        private final AttackResult.AttackType type;
        private final IAttackStrategy.AttackCategory category;
        private final String description;
        private final boolean singleton;
        
        public StrategyMetadata(AttackResult.AttackType type,
                               IAttackStrategy.AttackCategory category,
                               String description,
                               boolean singleton) {
            this.type = type;
            this.category = category;
            this.description = description;
            this.singleton = singleton;
        }
        
        // Getters
        public AttackResult.AttackType getType() { return type; }
        public IAttackStrategy.AttackCategory getCategory() { return category; }
        public String getDescription() { return description; }
        public boolean isSingleton() { return singleton; }
    }
    
    /**
     * 전략 통계
     */
    public static class StrategyStatistics {
        private int totalStrategies;
        private int singletonStrategies;
        private Map<IAttackStrategy.AttackCategory, Integer> strategiesByCategory;
        
        // Getters and Setters
        public int getTotalStrategies() { return totalStrategies; }
        public void setTotalStrategies(int totalStrategies) { 
            this.totalStrategies = totalStrategies; 
        }
        
        public int getSingletonStrategies() { return singletonStrategies; }
        public void setSingletonStrategies(int singletonStrategies) { 
            this.singletonStrategies = singletonStrategies; 
        }
        
        public Map<IAttackStrategy.AttackCategory, Integer> getStrategiesByCategory() { 
            return strategiesByCategory; 
        }
        public void setStrategiesByCategory(Map<IAttackStrategy.AttackCategory, Integer> strategiesByCategory) { 
            this.strategiesByCategory = strategiesByCategory; 
        }
        
        @Override
        public String toString() {
            return String.format(
                "StrategyStatistics{total=%d, singleton=%d, byCategory=%s}",
                totalStrategies, singletonStrategies, strategiesByCategory
            );
        }
    }
}