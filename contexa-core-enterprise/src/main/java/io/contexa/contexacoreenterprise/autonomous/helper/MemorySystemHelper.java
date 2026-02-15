package io.contexa.contexacoreenterprise.autonomous.helper;

import io.contexa.contexacore.autonomous.MemorySystem;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacoreenterprise.properties.MemoryProperties;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.data.redis.core.RedisTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class MemorySystemHelper implements MemorySystem {

    private final UnifiedVectorService unifiedVectorService;
    private final DistributedStateManager stateManager;
    private final RedisTemplate<String, Object> redisTemplate;
    private final MemoryProperties memoryProperties;

    private final Map<String, MemoryItem> shortTermMemory = new ConcurrentHashMap<>();

    private final Map<String, WorkingMemoryItem> workingMemory = new ConcurrentHashMap<>();

    private final Map<String, Set<String>> memoryIndex = new ConcurrentHashMap<>();

    private final Map<String, AccessPattern> accessPatterns = new ConcurrentHashMap<>();

    private final AtomicLong totalMemoryWrites = new AtomicLong(0);
    private final AtomicLong totalMemoryReads = new AtomicLong(0);
    private final AtomicLong consolidationCycles = new AtomicLong(0);
    private final AtomicLong evictionCount = new AtomicLong(0);
    
    @PostConstruct
    public void initialize() {
        if (!memoryProperties.getSystem().isEnabled()) {
                        return;
        }

        restoreMemoryState();

        startMemoryManagement();
        
            }

    public void storeMemory(String key, Object value) {
        storeInSTM(key, value, new HashMap<>()).subscribe();
    }

    public void store(String key, Object value) {
        storeMemory(key, value);
    }

    @Override
    public Mono<Void> storeInSTM(String key, Object value, Map<String, Object> metadata) {
        if (!memoryProperties.getSystem().isEnabled()) {
            return Mono.empty();
        }

        return Mono.defer(() -> {
            
            if (shortTermMemory.size() >= memoryProperties.getStm().getCapacity()) {
                evictOldestFromSTM();
            }

            MemoryItem item = new MemoryItem(
                key, value, metadata, LocalDateTime.now(), MemoryType.SHORT_TERM
            );

            shortTermMemory.put(key, item);

            updateMemoryIndex(key, metadata);

            recordAccess(key, AccessType.WRITE);

            totalMemoryWrites.incrementAndGet();

            return Mono.empty();
        });
    }

    @Override
    public Mono<Void> storeInWM(String key, Object value, String namespace) {
        if (!memoryProperties.getSystem().isEnabled()) {
            return Mono.empty();
        }

        return Mono.defer(() -> {
            
            if (workingMemory.size() >= memoryProperties.getWm().getCapacity()) {
                evictOldestFromWM();
            }

            WorkingMemoryItem item = new WorkingMemoryItem(
                key, value, namespace, LocalDateTime.now()
            );

            workingMemory.put(key, item);

            String redisKey = "wm:" + key;
            redisTemplate.opsForValue().set(redisKey, value, memoryProperties.getWm().getTtlSeconds(), TimeUnit.SECONDS);

            totalMemoryWrites.incrementAndGet();

            return Mono.empty();
        });
    }

    public Mono<MemoryResult> storeInLTM(String key, String content, Map<String, Object> metadata) {
        if (!memoryProperties.getSystem().isEnabled()) {
            return Mono.just(MemoryResult.disabled());
        }

        return Mono.defer(() -> {
            try {
                
                Map<String, Object> ltmMetadata = new HashMap<>(metadata);

                ltmMetadata.put("documentType", VectorDocumentType.MEMORY_LTM.getValue());
                ltmMetadata.put("memoryType", "LONG_TERM");
                ltmMetadata.put("key", key);
                ltmMetadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));

                AccessPattern pattern = accessPatterns.get(key);
                if (pattern != null) {
                    ltmMetadata.put("accessCount", pattern.getAccessCount());
                    ltmMetadata.put("importanceScore", pattern.calculateImportanceScore());
                }

                if (metadata.containsKey("userId")) {
                    ltmMetadata.put("userId", metadata.get("userId"));
                }
                if (metadata.containsKey("eventType")) {
                    ltmMetadata.put("eventType", metadata.get("eventType"));
                }
                if (metadata.containsKey("category")) {
                    ltmMetadata.put("category", metadata.get("category"));
                }

                Document doc = new Document(content, ltmMetadata);

                unifiedVectorService.storeDocument(doc);

                totalMemoryWrites.incrementAndGet();

                return Mono.just(MemoryResult.stored(key, MemoryType.LONG_TERM));

            } catch (Exception e) {
                log.error("[MemorySystem] LTM save failed: key={}", key, e);
                return Mono.just(MemoryResult.disabled());
            }
        });
    }

    public Mono<MemoryItem> retrieve(String key) {
        if (!memoryProperties.getSystem().isEnabled()) {
            return Mono.empty();
        }
        
        return Mono.defer(() -> {
            
            WorkingMemoryItem wmItem = workingMemory.get(key);
            if (wmItem != null) {
                recordAccess(key, AccessType.READ);
                totalMemoryReads.incrementAndGet();
                return Mono.just(wmItem.toMemoryItem());
            }

            MemoryItem stmItem = shortTermMemory.get(key);
            if (stmItem != null) {
                recordAccess(key, AccessType.READ);
                totalMemoryReads.incrementAndGet();

                promoteToWorkingMemory(stmItem);
                
                return Mono.just(stmItem);
            }

            return searchInLTM(key);
        });
    }

    public Flux<MemoryItem> searchSimilar(String query, int topK) {
        if (!memoryProperties.getSystem().isEnabled()) {
            return Flux.empty();
        }
        
        return Flux.defer(() -> {
            
            List<MemoryItem> stmResults = searchInSTM(query, topK);

            org.springframework.ai.vectorstore.SearchRequest searchRequest = org.springframework.ai.vectorstore.SearchRequest.builder()
                .query(query)
                .topK(topK)
                .similarityThreshold(0.7)
                .build();
            List<Document> ltmResults = unifiedVectorService.searchSimilar(searchRequest);

            return Flux.concat(
                Flux.fromIterable(stmResults),
                Flux.fromIterable(ltmResults)
                    .map(this::documentToMemoryItem)
            )
            .take(topK);
        });
    }

    public void consolidateMemory() {
        if (!memoryProperties.getSystem().isEnabled()) {
            return;
        }

        List<MemoryItem> itemsToConsolidate = shortTermMemory.values().stream()
            .filter(this::shouldConsolidate)
            .collect(Collectors.toList());
        
        for (MemoryItem item : itemsToConsolidate) {
            
            storeInLTM(
                item.getKey(),
                item.getValue().toString(),
                item.getMetadata()
            ).subscribe(
                result -> {
                    
                    shortTermMemory.remove(item.getKey());
                                    },
                error -> log.error("Memory consolidation failed: {}", item.getKey(), error)
            );
        }
        
        consolidationCycles.incrementAndGet();
            }

    public void cleanupMemory() {
        if (!memoryProperties.getSystem().isEnabled()) {
            return;
        }

        LocalDateTime stmExpiry = LocalDateTime.now().minusMinutes(memoryProperties.getStm().getTtlMinutes());
        shortTermMemory.entrySet().removeIf(entry -> {
            boolean expired = entry.getValue().getTimestamp().isBefore(stmExpiry);
            if (expired) evictionCount.incrementAndGet();
            return expired;
        });

        LocalDateTime wmExpiry = LocalDateTime.now().minusSeconds(memoryProperties.getWm().getTtlSeconds());
        workingMemory.entrySet().removeIf(entry -> {
            boolean expired = entry.getValue().getTimestamp().isBefore(wmExpiry);
            if (expired) evictionCount.incrementAndGet();
            return expired;
        });
    }

    public void saveMemoryState() {
        if (!memoryProperties.getSystem().isEnabled()) {
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

            DistributedStateManager.SecurityState securityState = DistributedStateManager.SecurityState.builder()
                .id("memory_system")
                .type("memory")
                .data(state)
                .lastModified(LocalDateTime.now())
                .modifiedBy("memory-helper")
                .version(1)
                .build();
            stateManager.saveState("memory_system", securityState).subscribe();
                    } catch (Exception e) {
            log.error("Memory state save failed", e);
        }
    }

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

        double score = pattern.calculateImportanceScore();
        return score >= memoryProperties.getLtm().getConsolidationThreshold();
    }
    
    private Mono<MemoryItem> searchInLTM(String key) {
        return Mono.fromCallable(() -> {
            FilterExpressionBuilder builder = new FilterExpressionBuilder();
            Filter.Expression filter = builder.eq("key", key).build();

            SearchRequest searchRequest = SearchRequest.builder()
                .query(key)
                .topK(1)
                .similarityThreshold(0.7)
                .filterExpression(filter)
                .build();

            List<Document> results = unifiedVectorService.searchSimilar(searchRequest);

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
            
            stateManager.getState("memory_system").subscribe(
                savedState -> {
                    if (savedState != null) {
                        
                                            }
                },
                error -> log.error("Memory state restoration failed, starting fresh", error)
            );
        } catch (Exception e) {
            log.error("Exception during memory state restoration", e);
        }
    }
    
    private void startMemoryManagement() {
        
            }
    
    private double calculateMemoryEfficiency() {
        long reads = totalMemoryReads.get();
        long writes = totalMemoryWrites.get();
        long evictions = evictionCount.get();
        
        if (writes == 0) return 0.0;

        double readWriteRatio = (double) reads / writes;
        double evictionRate = (double) evictions / writes;
        
        return Math.max(0.0, Math.min(1.0, readWriteRatio * (1.0 - evictionRate)));
    }

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

        public String getKey() { return key; }
        public Object getValue() { return value; }
        public Map<String, Object> getMetadata() { return metadata; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public MemoryType getType() { return type; }
    }

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

        public LocalDateTime getTimestamp() { return timestamp; }
    }

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

            return totalAccess / (1.0 + hoursSinceAccess);
        }
    }

    public enum MemoryType {
        SHORT_TERM,
        LONG_TERM,
        WORKING
    }

    private enum AccessType {
        READ,
        WRITE
    }

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

        public String getStatus() { return status; }
        public String getKey() { return key; }
        public MemoryType getType() { return type; }
    }

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

        public int getStmSize() { return stmSize; }
        public int getWmSize() { return wmSize; }
        public long getTotalWrites() { return totalWrites; }
        public long getTotalReads() { return totalReads; }
        public long getConsolidations() { return consolidations; }
        public long getEvictions() { return evictions; }
        public double getEfficiency() { return efficiency; }
    }
}