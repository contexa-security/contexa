package io.contexa.contexacore.autonomous.helper;

import io.contexa.contexacore.autonomous.state.DistributedStateManager;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * MemorySystemHelper - 메모리 시스템 헬퍼
 * 
 * 자율 진화형 정책 패브릭의 메모리 시스템을 관리하는 헬퍼 클래스입니다.
 * SecurityPlaneAgent와 협력하여 단기/장기/작업 메모리를 관리합니다.
 * 
 * 주요 기능:
 * - 단기 메모리 (STM) 관리
 * - 장기 메모리 (LTM) 관리
 * - 작업 메모리 (WM) 관리
 * - 메모리 통합 및 전이
 * 
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MemorySystemHelper {

    // 기존 서비스 재사용
    private final UnifiedVectorService unifiedVectorService;
    private final StandardVectorStoreService standardVectorStoreService;
    private final DistributedStateManager stateManager;
    private final RedisTemplate<String, Object> redisTemplate;
    
    // 설정값
    @Value("${memory.system.enabled:true}")
    private boolean memoryEnabled;
    
    @Value("${memory.stm.capacity:1000}")
    private int stmCapacity;
    
    @Value("${memory.stm.ttl-minutes:30}")
    private int stmTtlMinutes;
    
    @Value("${memory.ltm.consolidation-threshold:0.7}")
    private double ltmConsolidationThreshold;
    
    @Value("${memory.ltm.retention-days:365}")
    private int ltmRetentionDays;
    
    @Value("${memory.wm.capacity:100}")
    private int wmCapacity;
    
    @Value("${memory.wm.ttl-seconds:300}")
    private int wmTtlSeconds;
    
    @Value("${memory.consolidation.interval-minutes:15}")
    private int consolidationIntervalMinutes;
    
    // 단기 메모리 (Short-Term Memory)
    private final Map<String, MemoryItem> shortTermMemory = new ConcurrentHashMap<>();
    
    // 작업 메모리 (Working Memory)
    private final Map<String, WorkingMemoryItem> workingMemory = new ConcurrentHashMap<>();
    
    // 메모리 인덱스
    private final Map<String, Set<String>> memoryIndex = new ConcurrentHashMap<>();
    
    // 메모리 접근 패턴
    private final Map<String, AccessPattern> accessPatterns = new ConcurrentHashMap<>();
    
    // 통계
    private final AtomicLong totalMemoryWrites = new AtomicLong(0);
    private final AtomicLong totalMemoryReads = new AtomicLong(0);
    private final AtomicLong consolidationCycles = new AtomicLong(0);
    private final AtomicLong evictionCount = new AtomicLong(0);
    
    @PostConstruct
    public void initialize() {
        if (!memoryEnabled) {
            log.info("메모리 시스템 비활성화됨");
            return;
        }
        
        log.info("MemorySystemHelper 초기화 시작");
        
        // 기존 메모리 상태 복원
        restoreMemoryState();
        
        // 메모리 관리 워커 시작
        startMemoryManagement();
        
        log.info("MemorySystemHelper 초기화 완료 - STM: {} items, WM: {} items", 
                shortTermMemory.size(), workingMemory.size());
    }
    
    /**
     * 메모리에 저장 (간편 메서드)
     * 
     * 타입을 지정하지 않으면 자동으로 단기 메모리에 저장됩니다.
     * 
     * @param key 메모리 키
     * @param value 저장할 값
     */
    public void storeMemory(String key, Object value) {
        storeInSTM(key, value, new HashMap<>()).subscribe();
    }

    /**
     * 메모리에 저장 (호환성 메서드)
     */
    public void store(String key, Object value) {
        storeMemory(key, value);
    }
    
    /**
     * 단기 메모리에 저장
     * 
     * @param key 메모리 키
     * @param value 저장할 값
     * @param metadata 메타데이터
     * @return 저장 결과
     */
    public Mono<MemoryResult> storeInSTM(String key, Object value, Map<String, Object> metadata) {
        if (!memoryEnabled) {
            return Mono.just(MemoryResult.disabled());
        }
        
        return Mono.defer(() -> {
            // 용량 체크 및 필요시 제거
            if (shortTermMemory.size() >= stmCapacity) {
                evictOldestFromSTM();
            }
            
            // 메모리 아이템 생성
            MemoryItem item = new MemoryItem(
                key, value, metadata, LocalDateTime.now(), MemoryType.SHORT_TERM
            );
            
            // 저장
            shortTermMemory.put(key, item);
            
            // 인덱스 업데이트
            updateMemoryIndex(key, metadata);
            
            // 접근 패턴 기록
            recordAccess(key, AccessType.WRITE);
            
            totalMemoryWrites.incrementAndGet();
            
            return Mono.just(MemoryResult.stored(key, MemoryType.SHORT_TERM));
        });
    }
    
    /**
     * 작업 메모리에 저장
     * 
     * @param key 메모리 키
     * @param value 저장할 값
     * @param context 작업 컨텍스트
     * @return 저장 결과
     */
    public Mono<MemoryResult> storeInWM(String key, Object value, String context) {
        if (!memoryEnabled) {
            return Mono.just(MemoryResult.disabled());
        }
        
        return Mono.defer(() -> {
            // 용량 체크
            if (workingMemory.size() >= wmCapacity) {
                evictOldestFromWM();
            }
            
            // 작업 메모리 아이템 생성
            WorkingMemoryItem item = new WorkingMemoryItem(
                key, value, context, LocalDateTime.now()
            );
            
            // 저장
            workingMemory.put(key, item);
            
            // Redis에도 저장 (TTL 설정)
            String redisKey = "wm:" + key;
            redisTemplate.opsForValue().set(redisKey, value, wmTtlSeconds, TimeUnit.SECONDS);
            
            totalMemoryWrites.incrementAndGet();
            
            return Mono.just(MemoryResult.stored(key, MemoryType.WORKING));
        });
    }
    
    /**
     * ✅ Phase 2: 장기 메모리에 저장 (벡터 스토어 활용)
     *
     * 중요한 단기 메모리를 장기 메모리(LTM)로 consolidation하여 저장
     *
     * @param key 메모리 키
     * @param content 저장할 내용
     * @param metadata 메타데이터
     * @return 저장 결과
     */
    public Mono<MemoryResult> storeInLTM(String key, String content, Map<String, Object> metadata) {
        if (!memoryEnabled) {
            return Mono.just(MemoryResult.disabled());
        }

        return Mono.defer(() -> {
            try {
                // 메타데이터 준비
                Map<String, Object> ltmMetadata = new HashMap<>(metadata);

                // ✅ documentType 표준화 (Enum 사용)
                ltmMetadata.put("documentType", VectorDocumentType.MEMORY_LTM.getValue());
                ltmMetadata.put("memoryType", "LONG_TERM");
                ltmMetadata.put("key", key);
                ltmMetadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));

                // 접근 패턴 정보 추가
                AccessPattern pattern = accessPatterns.get(key);
                if (pattern != null) {
                    ltmMetadata.put("accessCount", pattern.getAccessCount());
                    ltmMetadata.put("importanceScore", pattern.calculateImportanceScore());
                }

                // 원본 메타데이터에서 중요 정보 추출
                if (metadata.containsKey("userId")) {
                    ltmMetadata.put("userId", metadata.get("userId"));
                }
                if (metadata.containsKey("eventType")) {
                    ltmMetadata.put("eventType", metadata.get("eventType"));
                }
                if (metadata.containsKey("category")) {
                    ltmMetadata.put("category", metadata.get("category"));
                }

                // Document 생성
                Document doc = new Document(content, ltmMetadata);

                // 벡터 스토어에 저장
                unifiedVectorService.storeDocument(doc);

                totalMemoryWrites.incrementAndGet();

                log.debug("[MemorySystem] LTM 저장 완료: key={}, importanceScore={}",
                    key, pattern != null ? pattern.calculateImportanceScore() : "N/A");

                return Mono.just(MemoryResult.stored(key, MemoryType.LONG_TERM));

            } catch (Exception e) {
                log.warn("[MemorySystem] LTM 저장 실패: key={}", key, e);
                return Mono.just(MemoryResult.disabled());
            }
        });
    }
    
    /**
     * 메모리에서 검색
     * 
     * @param key 메모리 키
     * @return 검색 결과
     */
    public Mono<MemoryItem> retrieve(String key) {
        if (!memoryEnabled) {
            return Mono.empty();
        }
        
        return Mono.defer(() -> {
            // 작업 메모리 확인
            WorkingMemoryItem wmItem = workingMemory.get(key);
            if (wmItem != null) {
                recordAccess(key, AccessType.READ);
                totalMemoryReads.incrementAndGet();
                return Mono.just(wmItem.toMemoryItem());
            }
            
            // 단기 메모리 확인
            MemoryItem stmItem = shortTermMemory.get(key);
            if (stmItem != null) {
                recordAccess(key, AccessType.READ);
                totalMemoryReads.incrementAndGet();
                
                // 자주 접근되는 항목은 작업 메모리로 승격
                promoteToWorkingMemory(stmItem);
                
                return Mono.just(stmItem);
            }
            
            // 장기 메모리 검색
            return searchInLTM(key);
        });
    }
    
    /**
     * 유사 메모리 검색
     * 
     * @param query 검색 쿼리
     * @param topK 반환할 결과 수
     * @return 유사 메모리 목록
     */
    public Flux<MemoryItem> searchSimilar(String query, int topK) {
        if (!memoryEnabled) {
            return Flux.empty();
        }
        
        return Flux.defer(() -> {
            // 단기 메모리에서 검색
            List<MemoryItem> stmResults = searchInSTM(query, topK);

            // 장기 메모리에서 검색
            org.springframework.ai.vectorstore.SearchRequest searchRequest = org.springframework.ai.vectorstore.SearchRequest.builder()
                .query(query)
                .topK(topK)
                .similarityThreshold(0.7)
                .build();
            List<Document> ltmResults = unifiedVectorService.searchSimilar(searchRequest);
            
            // 결과 병합 및 정렬
            return Flux.concat(
                Flux.fromIterable(stmResults),
                Flux.fromIterable(ltmResults)
                    .map(this::documentToMemoryItem)
            )
            .take(topK);
        });
    }
    
    /**
     * 메모리 통합 (STM → LTM)
     * 
     * 중요한 단기 메모리를 장기 메모리로 전환
     */
//    @Scheduled(fixedDelayString = "${memory.consolidation.interval-minutes:15}000")
    public void consolidateMemory() {
        if (!memoryEnabled) {
            return;
        }
        
        log.debug("메모리 통합 시작");
        
        List<MemoryItem> itemsToConsolidate = shortTermMemory.values().stream()
            .filter(this::shouldConsolidate)
            .collect(Collectors.toList());
        
        for (MemoryItem item : itemsToConsolidate) {
            // 장기 메모리로 전환
            storeInLTM(
                item.getKey(),
                item.getValue().toString(),
                item.getMetadata()
            ).subscribe(
                result -> {
                    // 단기 메모리에서 제거
                    shortTermMemory.remove(item.getKey());
                    log.debug("메모리 통합 완료: {}", item.getKey());
                },
                error -> log.error("메모리 통합 실패: {}", item.getKey(), error)
            );
        }
        
        consolidationCycles.incrementAndGet();
        log.debug("메모리 통합 완료 - {} 항목 처리됨", itemsToConsolidate.size());
    }
    
    /**
     * 메모리 정리
     * 
     * 만료된 메모리 항목 제거
     */
//    @Scheduled(fixedDelay = 60000) // 1분마다
    public void cleanupMemory() {
        if (!memoryEnabled) {
            return;
        }
        
        // 만료된 STM 항목 제거
        LocalDateTime stmExpiry = LocalDateTime.now().minusMinutes(stmTtlMinutes);
        shortTermMemory.entrySet().removeIf(entry -> {
            boolean expired = entry.getValue().getTimestamp().isBefore(stmExpiry);
            if (expired) evictionCount.incrementAndGet();
            return expired;
        });
        
        // 만료된 WM 항목 제거
        LocalDateTime wmExpiry = LocalDateTime.now().minusSeconds(wmTtlSeconds);
        workingMemory.entrySet().removeIf(entry -> {
            boolean expired = entry.getValue().getTimestamp().isBefore(wmExpiry);
            if (expired) evictionCount.incrementAndGet();
            return expired;
        });
    }
    
    /**
     * 메모리 상태 저장
     */
//    @Scheduled(fixedDelay = 300000) // 5분마다
    public void saveMemoryState() {
        if (!memoryEnabled) {
            return;
        }
        
        try {
            Map<String, Object> state = new HashMap<>();
            state.put("stm", shortTermMemory);
            state.put("wm", workingMemory);
            state.put("index", memoryIndex);
            state.put("patterns", accessPatterns);
            state.put("statistics", Map.of(
                "writes", totalMemoryWrites.get(),
                "reads", totalMemoryReads.get(),
                "consolidations", consolidationCycles.get(),
                "evictions", evictionCount.get()
            ));
            
            // SecurityState 객체로 변환하여 저장
            DistributedStateManager.SecurityState securityState = DistributedStateManager.SecurityState.builder()
                .id("memory_system")
                .type("memory")
                .data(state)
                .lastModified(LocalDateTime.now())
                .modifiedBy("memory-helper")
                .version(1)
                .build();
            stateManager.saveState("memory_system", securityState).subscribe();
            log.debug("메모리 상태 저장 완료");
        } catch (Exception e) {
            log.error("메모리 상태 저장 실패", e);
        }
    }
    
    /**
     * 메모리 통계
     * 
     * @return 메모리 시스템 통계
     */
    public MemoryStatistics getStatistics() {
        return new MemoryStatistics(
            shortTermMemory.size(),
            workingMemory.size(),
            totalMemoryWrites.get(),
            totalMemoryReads.get(),
            consolidationCycles.get(),
            evictionCount.get(),
            calculateMemoryEfficiency()
        );
    }
    
    // Private 메서드들
    
    private void evictOldestFromSTM() {
        shortTermMemory.entrySet().stream()
            .min(Comparator.comparing(e -> e.getValue().getTimestamp()))
            .ifPresent(entry -> {
                shortTermMemory.remove(entry.getKey());
                evictionCount.incrementAndGet();
            });
    }
    
    private void evictOldestFromWM() {
        workingMemory.entrySet().stream()
            .min(Comparator.comparing(e -> e.getValue().getTimestamp()))
            .ifPresent(entry -> {
                workingMemory.remove(entry.getKey());
                evictionCount.incrementAndGet();
            });
    }
    
    private void updateMemoryIndex(String key, Map<String, Object> metadata) {
        for (Map.Entry<String, Object> entry : metadata.entrySet()) {
            String indexKey = entry.getKey() + ":" + entry.getValue();
            memoryIndex.computeIfAbsent(indexKey, k -> new HashSet<>()).add(key);
        }
    }
    
    private void recordAccess(String key, AccessType type) {
        AccessPattern pattern = accessPatterns.computeIfAbsent(key, k -> new AccessPattern());
        pattern.recordAccess(type);
    }
    
    private void promoteToWorkingMemory(MemoryItem item) {
        AccessPattern pattern = accessPatterns.get(item.getKey());
        if (pattern != null && pattern.getAccessCount() > 3) {
            storeInWM(item.getKey(), item.getValue(), "promoted").subscribe();
        }
    }
    
    private boolean shouldConsolidate(MemoryItem item) {
        AccessPattern pattern = accessPatterns.get(item.getKey());
        if (pattern == null) {
            return false;
        }
        
        // 접근 빈도와 중요도 기반 결정
        double score = pattern.calculateImportanceScore();
        return score >= ltmConsolidationThreshold;
    }
    
    private Mono<MemoryItem> searchInLTM(String key) {
        return Mono.fromCallable(() -> {
            Map<String, Object> filter = Map.of("key", key);
            List<Document> results = standardVectorStoreService.searchWithFilter(key, filter);
            
            if (!results.isEmpty()) {
                totalMemoryReads.incrementAndGet();
                return documentToMemoryItem(results.get(0));
            }
            return null;
        });
    }
    
    private List<MemoryItem> searchInSTM(String query, int limit) {
        return shortTermMemory.values().stream()
            .filter(item -> matchesQuery(item, query))
            .limit(limit)
            .collect(Collectors.toList());
    }
    
    private boolean matchesQuery(MemoryItem item, String query) {
        // 간단한 매칭 로직
        return item.getValue().toString().toLowerCase().contains(query.toLowerCase());
    }
    
    private MemoryItem documentToMemoryItem(Document doc) {
        return new MemoryItem(
            doc.getMetadata().get("key").toString(),
            doc.getText(),
            doc.getMetadata(),
            LocalDateTime.parse(doc.getMetadata().get("timestamp").toString()),
            MemoryType.LONG_TERM
        );
    }
    
    private void restoreMemoryState() {
        try {
            // DistributedStateManager의 getState는 Mono<SecurityState>를 반환
            stateManager.getState("memory_system").subscribe(
                savedState -> {
                    if (savedState != null) {
                        // 상태 복원 로직
                        log.info("메모리 상태 복원 완료");
                    }
                },
                error -> log.warn("메모리 상태 복원 실패, 새로 시작", error)
            );
        } catch (Exception e) {
            log.warn("메모리 상태 복원 중 예외 발생", e);
        }
    }
    
    private void startMemoryManagement() {
        // 메모리 관리 태스크 시작
        log.debug("메모리 관리 워커 시작됨");
    }
    
    private double calculateMemoryEfficiency() {
        long reads = totalMemoryReads.get();
        long writes = totalMemoryWrites.get();
        long evictions = evictionCount.get();
        
        if (writes == 0) return 0.0;
        
        // 읽기/쓰기 비율과 제거율을 고려한 효율성 계산
        double readWriteRatio = (double) reads / writes;
        double evictionRate = (double) evictions / writes;
        
        return Math.max(0.0, Math.min(1.0, readWriteRatio * (1.0 - evictionRate)));
    }
    
    // 내부 클래스들
    
    /**
     * 메모리 아이템
     */
    public static class MemoryItem {
        private final String key;
        private final Object value;
        private final Map<String, Object> metadata;
        private final LocalDateTime timestamp;
        private final MemoryType type;
        
        public MemoryItem(String key, Object value, Map<String, Object> metadata,
                         LocalDateTime timestamp, MemoryType type) {
            this.key = key;
            this.value = value;
            this.metadata = metadata;
            this.timestamp = timestamp;
            this.type = type;
        }
        
        // Getters
        public String getKey() { return key; }
        public Object getValue() { return value; }
        public Map<String, Object> getMetadata() { return metadata; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public MemoryType getType() { return type; }
    }
    
    /**
     * 작업 메모리 아이템
     */
    private static class WorkingMemoryItem {
        private final String key;
        private final Object value;
        private final String context;
        private final LocalDateTime timestamp;
        
        public WorkingMemoryItem(String key, Object value, String context, LocalDateTime timestamp) {
            this.key = key;
            this.value = value;
            this.context = context;
            this.timestamp = timestamp;
        }
        
        public MemoryItem toMemoryItem() {
            return new MemoryItem(
                key, value, 
                Map.of("context", context),
                timestamp,
                MemoryType.WORKING
            );
        }
        
        // Getters
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    /**
     * 접근 패턴
     */
    private static class AccessPattern {
        private long readCount = 0;
        private long writeCount = 0;
        private LocalDateTime lastAccess = LocalDateTime.now();
        
        public void recordAccess(AccessType type) {
            if (type == AccessType.READ) {
                readCount++;
            } else {
                writeCount++;
            }
            lastAccess = LocalDateTime.now();
        }
        
        public long getAccessCount() {
            return readCount + writeCount;
        }
        
        public double calculateImportanceScore() {
            long totalAccess = getAccessCount();
            long hoursSinceAccess = Duration.between(lastAccess, LocalDateTime.now()).toHours();
            
            // 접근 빈도와 최근성을 고려한 점수
            return totalAccess / (1.0 + hoursSinceAccess);
        }
    }
    
    /**
     * 메모리 타입
     */
    public enum MemoryType {
        SHORT_TERM,
        LONG_TERM,
        WORKING
    }
    
    /**
     * 접근 타입
     */
    private enum AccessType {
        READ,
        WRITE
    }
    
    /**
     * 메모리 결과
     */
    public static class MemoryResult {
        private final String status;
        private final String key;
        private final MemoryType type;
        
        private MemoryResult(String status, String key, MemoryType type) {
            this.status = status;
            this.key = key;
            this.type = type;
        }
        
        public static MemoryResult disabled() {
            return new MemoryResult("disabled", null, null);
        }
        
        public static MemoryResult stored(String key, MemoryType type) {
            return new MemoryResult("stored", key, type);
        }
        
        // Getters
        public String getStatus() { return status; }
        public String getKey() { return key; }
        public MemoryType getType() { return type; }
    }
    
    /**
     * 메모리 통계
     */
    public static class MemoryStatistics {
        private final int stmSize;
        private final int wmSize;
        private final long totalWrites;
        private final long totalReads;
        private final long consolidations;
        private final long evictions;
        private final double efficiency;
        
        public MemoryStatistics(int stmSize, int wmSize, long totalWrites, long totalReads,
                               long consolidations, long evictions, double efficiency) {
            this.stmSize = stmSize;
            this.wmSize = wmSize;
            this.totalWrites = totalWrites;
            this.totalReads = totalReads;
            this.consolidations = consolidations;
            this.evictions = evictions;
            this.efficiency = efficiency;
        }
        
        // Getters
        public int getStmSize() { return stmSize; }
        public int getWmSize() { return wmSize; }
        public long getTotalWrites() { return totalWrites; }
        public long getTotalReads() { return totalReads; }
        public long getConsolidations() { return consolidations; }
        public long getEvictions() { return evictions; }
        public double getEfficiency() { return efficiency; }
    }
}