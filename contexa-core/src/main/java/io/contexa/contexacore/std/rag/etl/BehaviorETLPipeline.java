package io.contexa.contexacore.std.rag.etl;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.ai.document.Document;
import org.springframework.ai.document.DocumentTransformer;
import org.springframework.ai.reader.JsonReader;
import org.springframework.ai.reader.TextReader;
import org.springframework.ai.transformer.splitter.TokenTextSplitter;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.core.io.Resource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 행동 분석 ETL 파이프라인
 * 
 * Spring AI 표준 ETL 아키텍처를 구현한 행동 데이터 처리 파이프라인입니다.
 * DocumentReader -> DocumentTransformer -> DocumentWriter 패턴을 따릅니다.
 * 
 * @since 1.0.0
 */
@RequiredArgsConstructor
public class BehaviorETLPipeline {
    
    @Value("${spring.ai.etl.batch-size:100}")
    private int batchSize;
    
    @Value("${spring.ai.etl.parallel-readers:4}")
    private int parallelReaders;
    
    @Value("${spring.ai.etl.chunk-size:1000}")
    private int chunkSize;
    
    @Value("${spring.ai.etl.chunk-overlap:200}")
    private int chunkOverlap;
    
    @Value("${spring.ai.etl.behavior.retention-days:90}")
    private int retentionDays;

    private final VectorStore vectorStore;
    private final JdbcTemplate jdbcTemplate;
    private final BehaviorMetadataEnricher metadataEnricher;
    private ExecutorService executorService;

    private TokenTextSplitter textSplitter;
    private BehaviorDataValidator dataValidator;
    private BehaviorAnonymizer anonymizer;

    // 메트릭 추적
    private final Map<String, Long> metrics = new ConcurrentHashMap<>();
    private final Map<String, ETLJobStatus> jobStatuses = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void initialize() {
        executorService = Executors.newFixedThreadPool(parallelReaders);
        // 텍스트 분할기 초기화
        this.textSplitter = new TokenTextSplitter(chunkSize, chunkOverlap, 5, 10000, true);
        
        // 데이터 검증기 초기화
        this.dataValidator = new BehaviorDataValidator();
        
        // 익명화 처리기 초기화
        this.anonymizer = new BehaviorAnonymizer();
    }
    
    /**
     * ETL 파이프라인 실행
     * 
     * @param dataSource 데이터 소스 (파일 경로, DB 쿼리, API 엔드포인트 등)
     * @param sourceType 소스 타입 (FILE, DATABASE, API, STREAM)
     * @return ETL 작업 ID
     */
    @Async
    public CompletableFuture<String> executePipeline(String dataSource, SourceType sourceType) {
        String jobId = UUID.randomUUID().toString();
        ETLJobStatus jobStatus = new ETLJobStatus(jobId, LocalDateTime.now());
        jobStatuses.put(jobId, jobStatus);
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                jobStatus.setStatus(JobStatus.RUNNING);
                
                // 1. Extract - 데이터 읽기
                List<Document> rawDocuments = extractData(dataSource, sourceType, jobStatus);
                jobStatus.setExtractedCount(rawDocuments.size());
                
                // 2. Transform - 데이터 변환
                List<Document> transformedDocuments = transformData(rawDocuments, jobStatus);
                jobStatus.setTransformedCount(transformedDocuments.size());
                
                // 3. Load - 데이터 적재
                loadData(transformedDocuments, jobStatus);
                jobStatus.setLoadedCount(transformedDocuments.size());
                
                jobStatus.setStatus(JobStatus.COMPLETED);
                jobStatus.setEndTime(LocalDateTime.now());
                
                // 메트릭 업데이트
                updateMetrics(jobStatus);
                
                return jobId;
                
            } catch (Exception e) {
                jobStatus.setStatus(JobStatus.FAILED);
                jobStatus.setErrorMessage(e.getMessage());
                jobStatus.setEndTime(LocalDateTime.now());
                throw new ETLPipelineException("ETL pipeline failed", e);
            }
        }, executorService);
    }
    
    /**
     * Extract 단계 - 데이터 추출
     */
    private List<Document> extractData(String dataSource, SourceType sourceType, ETLJobStatus jobStatus) {
        List<Document> documents = new ArrayList<>();
        
        switch (sourceType) {
            case FILE:
                documents = extractFromFile(dataSource);
                break;
            case DATABASE:
                documents = extractFromDatabase(dataSource);
                break;
            case API:
                documents = extractFromAPI(dataSource);
                break;
            case STREAM:
                documents = extractFromStream(dataSource);
                break;
        }
        
        return documents;
    }
    
    /**
     * 파일에서 데이터 추출
     */
    private List<Document> extractFromFile(String filePath) {
        List<Document> documents = new ArrayList<>();
        Path path = Paths.get(filePath);
        
        try {
            if (Files.isDirectory(path)) {
                // 디렉토리의 모든 파일 처리
                List<CompletableFuture<List<Document>>> futures = new ArrayList<>();
                
                try (Stream<Path> paths = Files.walk(path)) {
                    paths.filter(Files::isRegularFile)
                        .forEach(file -> {
                            CompletableFuture<List<Document>> future = CompletableFuture.supplyAsync(
                                () -> readSingleFile(file), executorService);
                            futures.add(future);
                        });
                }
                
                // 모든 파일 읽기 완료 대기
                for (CompletableFuture<List<Document>> future : futures) {
                    documents.addAll(future.join());
                }
                
            } else {
                // 단일 파일 처리
                documents = readSingleFile(path);
            }
            
        } catch (IOException e) {
            throw new ETLPipelineException("Failed to extract from file: " + filePath, e);
        }
        
        return documents;
    }
    
    /**
     * 단일 파일 읽기
     */
    private List<Document> readSingleFile(Path file) {
        String fileName = file.getFileName().toString().toLowerCase();
        
        try {
            if (fileName.endsWith(".json")) {
                // JSON 파일 읽기
                // Spring AI 1.0.0-SNAPSHOT에서는 Resource를 사용
                Resource resource = new FileSystemResource(file.toFile());
                JsonReader reader = new JsonReader(resource, "userId", "timestamp", "activity");
                return reader.get();
                
            } else if (fileName.endsWith(".txt") || fileName.endsWith(".log")) {
                // 텍스트/로그 파일 읽기
                TextReader reader = new TextReader(file.toUri().toString());
                List<Document> docs = reader.get();
                
                // 로그 파싱 및 구조화
                return parseLogDocuments(docs);
                
            } else if (fileName.endsWith(".csv")) {
                // CSV 파일 읽기
                return readCsvFile(file);
            }
            
        } catch (Exception e) {
            // 파일 읽기 실패 시 빈 리스트 반환
        }
        
        return Collections.emptyList();
    }
    
    /**
     * CSV 파일 읽기
     */
    private List<Document> readCsvFile(Path file) throws IOException {
        List<Document> documents = new ArrayList<>();
        List<String> lines = Files.readAllLines(file);
        
        if (lines.isEmpty()) return documents;
        
        String[] headers = lines.get(0).split(",");
        
        for (int i = 1; i < lines.size(); i++) {
            String[] values = lines.get(i).split(",");
            
            Map<String, Object> metadata = new HashMap<>();
            StringBuilder content = new StringBuilder();
            
            for (int j = 0; j < Math.min(headers.length, values.length); j++) {
                String header = headers[j].trim();
                String value = values[j].trim();
                
                metadata.put(header, value);
                content.append(header).append(": ").append(value).append("\n");
            }
            
            Document doc = new Document(content.toString(), metadata);
            documents.add(doc);
        }
        
        return documents;
    }
    
    /**
     * 로그 문서 파싱
     */
    private List<Document> parseLogDocuments(List<Document> rawDocs) {
        List<Document> parsedDocs = new ArrayList<>();
        
        for (Document rawDoc : rawDocs) {
            String content = rawDoc.getText();
            String[] lines = content.split("\n");
            
            for (String line : lines) {
                if (line.trim().isEmpty()) continue;
                
                Map<String, Object> metadata = parseLogLine(line);
                if (!metadata.isEmpty()) {
                    Document doc = new Document(line, metadata);
                    parsedDocs.add(doc);
                }
            }
        }
        
        return parsedDocs;
    }
    
    /**
     * 로그 라인 파싱
     */
    private Map<String, Object> parseLogLine(String line) {
        Map<String, Object> metadata = new HashMap<>();
        
        // 타임스탬프 추출
        String timestampPattern = "\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(timestampPattern);
        java.util.regex.Matcher matcher = pattern.matcher(line);
        
        if (matcher.find()) {
            metadata.put("timestamp", matcher.group());
        }
        
        // 로그 레벨 추출
        if (line.contains("ERROR")) metadata.put("level", "ERROR");
        else if (line.contains("WARN")) metadata.put("level", "WARN");
        else if (line.contains("INFO")) metadata.put("level", "INFO");
        else if (line.contains("DEBUG")) metadata.put("level", "DEBUG");
        
        // 사용자 ID 추출
        pattern = java.util.regex.Pattern.compile("user[Id]*[:=]([\\w-]+)", java.util.regex.Pattern.CASE_INSENSITIVE);
        matcher = pattern.matcher(line);
        if (matcher.find()) {
            metadata.put("userId", matcher.group(1));
        }
        
        // IP 주소 추출
        pattern = java.util.regex.Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
        matcher = pattern.matcher(line);
        if (matcher.find()) {
            metadata.put("ipAddress", matcher.group());
        }
        
        return metadata;
    }
    
    /**
     * 데이터베이스에서 데이터 추출
     */
    private List<Document> extractFromDatabase(String query) {
        List<Document> documents = new ArrayList<>();
        
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(query);
        
        for (Map<String, Object> row : rows) {
            // 내용 생성
            StringBuilder content = new StringBuilder();
            Map<String, Object> metadata = new HashMap<>();
            
            for (Map.Entry<String, Object> entry : row.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                
                if (value != null) {
                    metadata.put(key, value.toString());
                    content.append(key).append(": ").append(value).append("\n");
                }
            }
            
            Document doc = new Document(content.toString(), metadata);
            documents.add(doc);
        }
        
        return documents;
    }
    
    /**
     * API에서 데이터 추출
     */
    private List<Document> extractFromAPI(String endpoint) {
        // API 호출 구현 (Spring RestTemplate 사용)
        // 실제 구현은 API 스펙에 따라 달라짐
        return new ArrayList<>();
    }
    
    /**
     * 스트림에서 데이터 추출
     */
    private List<Document> extractFromStream(String streamConfig) {
        // Kafka, RabbitMQ 등 스트림 처리
        // 실제 구현은 스트림 시스템에 따라 달라짐
        return new ArrayList<>();
    }
    
    /**
     * Transform 단계 - 데이터 변환
     */
    private List<Document> transformData(List<Document> documents, ETLJobStatus jobStatus) {
        if (documents == null || documents.isEmpty()) {
            return documents;
        }
        
        // 1. 데이터 검증
        documents = dataValidator.apply(documents);
        
        // 2. 익명화 처리
        documents = anonymizer.apply(documents);
        
        // 3. 메타데이터 강화
        documents = metadataEnricher.apply(documents);
        
        // 4. 문서 분할
        List<Document> chunkedDocuments = new ArrayList<>();
        for (Document doc : documents) {
            List<Document> chunks = textSplitter.apply(List.of(doc));
            
            // 청크에 원본 문서 정보 추가
            for (int i = 0; i < chunks.size(); i++) {
                Document chunk = chunks.get(i);
                chunk.getMetadata().putAll(doc.getMetadata());
                chunk.getMetadata().put("chunkIndex", i);
                chunk.getMetadata().put("totalChunks", chunks.size());
                chunk.getMetadata().put("etlJobId", jobStatus.getJobId());
            }
            
            chunkedDocuments.addAll(chunks);
        }
        
        // 5. 중복 제거
        chunkedDocuments = removeDuplicates(chunkedDocuments);
        
        return chunkedDocuments;
    }
    
    /**
     * 중복 문서 제거
     */
    private List<Document> removeDuplicates(List<Document> documents) {
        Set<String> contentHashes = new HashSet<>();
        List<Document> uniqueDocs = new ArrayList<>();
        
        for (Document doc : documents) {
            String contentHash = generateContentHash(doc);
            
            if (!contentHashes.contains(contentHash)) {
                contentHashes.add(contentHash);
                uniqueDocs.add(doc);
            }
        }
        
        return uniqueDocs;
    }
    
    /**
     * 문서 해시 생성
     */
    private String generateContentHash(Document document) {
        String content = document.getText();
        String userId = (String) document.getMetadata().get("userId");
        String timestamp = (String) document.getMetadata().get("timestamp");
        
        String combined = (content != null ? content : "") + 
                         (userId != null ? userId : "") + 
                         (timestamp != null ? timestamp : "");
        
        return Integer.toHexString(combined.hashCode());
    }
    
    /**
     * Load 단계 - 데이터 적재
     */
    @Transactional
    public void loadData(List<Document> documents, ETLJobStatus jobStatus) {
        if (documents == null || documents.isEmpty()) {
            return;
        }
        
        // 배치 처리
        for (int i = 0; i < documents.size(); i += batchSize) {
            int end = Math.min(i + batchSize, documents.size());
            List<Document> batch = documents.subList(i, end);
            
            // 벡터 저장소에 적재
            vectorStore.add(batch);
            
            // 진행률 업데이트
            jobStatus.setLoadedCount(i + batch.size());
        }
        
        // 오래된 데이터 정리
        cleanupOldData();
    }
    
    /**
     * 오래된 데이터 정리
     */
    private void cleanupOldData() {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(retentionDays);
        String cutoffDateStr = cutoffDate.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        
        // 오래된 문서 ID 조회
        List<String> oldDocumentIds = jdbcTemplate.queryForList(
            "SELECT id FROM vector_store WHERE metadata->>'timestamp' < ?",
            String.class,
            cutoffDateStr
        );
        
        if (!oldDocumentIds.isEmpty()) {
            vectorStore.delete(oldDocumentIds);
            metrics.put("deletedOldDocuments", (long) oldDocumentIds.size());
        }
    }
    
    /**
     * 메트릭 업데이트
     */
    private void updateMetrics(ETLJobStatus jobStatus) {
        metrics.put("lastJobDuration", 
            java.time.Duration.between(jobStatus.getStartTime(), jobStatus.getEndTime()).toMillis());
        metrics.put("totalJobsCompleted", 
            metrics.getOrDefault("totalJobsCompleted", 0L) + 1);
        metrics.put("totalDocumentsProcessed", 
            metrics.getOrDefault("totalDocumentsProcessed", 0L) + jobStatus.getLoadedCount());
    }
    
    /**
     * ETL 작업 상태 조회
     */
    public ETLJobStatus getJobStatus(String jobId) {
        return jobStatuses.get(jobId);
    }
    
    /**
     * 모든 작업 상태 조회
     */
    public List<ETLJobStatus> getAllJobStatuses() {
        return new ArrayList<>(jobStatuses.values());
    }
    
    /**
     * 메트릭 조회
     */
    public Map<String, Long> getMetrics() {
        return new HashMap<>(metrics);
    }
    
    /**
     * 리소스 정리
     */
    public void shutdown() {
        executorService.shutdown();
    }
    
    /**
     * 소스 타입 열거형
     */
    public enum SourceType {
        FILE, DATABASE, API, STREAM
    }
    
    /**
     * 작업 상태 열거형
     */
    public enum JobStatus {
        PENDING, RUNNING, COMPLETED, FAILED
    }
    
    /**
     * ETL 작업 상태 클래스
     */
    public static class ETLJobStatus {
        private final String jobId;
        private final LocalDateTime startTime;
        private LocalDateTime endTime;
        private JobStatus status = JobStatus.PENDING;
        private int extractedCount;
        private int transformedCount;
        private int loadedCount;
        private String errorMessage;
        
        public ETLJobStatus(String jobId, LocalDateTime startTime) {
            this.jobId = jobId;
            this.startTime = startTime;
        }
        
        // Getters and Setters
        public String getJobId() { return jobId; }
        public LocalDateTime getStartTime() { return startTime; }
        public LocalDateTime getEndTime() { return endTime; }
        public void setEndTime(LocalDateTime endTime) { this.endTime = endTime; }
        public JobStatus getStatus() { return status; }
        public void setStatus(JobStatus status) { this.status = status; }
        public int getExtractedCount() { return extractedCount; }
        public void setExtractedCount(int count) { this.extractedCount = count; }
        public int getTransformedCount() { return transformedCount; }
        public void setTransformedCount(int count) { this.transformedCount = count; }
        public int getLoadedCount() { return loadedCount; }
        public void setLoadedCount(int count) { this.loadedCount = count; }
        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String message) { this.errorMessage = message; }
    }
    
    /**
     * ETL 파이프라인 예외
     */
    public static class ETLPipelineException extends RuntimeException {
        public ETLPipelineException(String message) {
            super(message);
        }
        
        public ETLPipelineException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    /**
     * 데이터 검증기
     */
    private static class BehaviorDataValidator implements DocumentTransformer {
        @Override
        public List<Document> apply(List<Document> documents) {
            return documents.stream()
                .filter(doc -> {
                    Map<String, Object> metadata = doc.getMetadata();
                    // 필수 필드 검증
                    return metadata.containsKey("userId") || 
                           metadata.containsKey("sessionId") ||
                           metadata.containsKey("ipAddress");
                })
                .collect(Collectors.toList());
        }
    }
    
    /**
     * 익명화 처리기
     */
    private static class BehaviorAnonymizer implements DocumentTransformer {
        @Override
        public List<Document> apply(List<Document> documents) {
            for (Document doc : documents) {
                Map<String, Object> metadata = doc.getMetadata();
                
                // PII 익명화
                if (metadata.containsKey("email")) {
                    String email = (String) metadata.get("email");
                    metadata.put("email", anonymizeEmail(email));
                }
                
                if (metadata.containsKey("phone")) {
                    metadata.put("phone", "***-***-****");
                }
                
                if (metadata.containsKey("ssn")) {
                    metadata.remove("ssn");
                }
                
                // IP 주소 부분 마스킹
                if (metadata.containsKey("ipAddress")) {
                    String ip = (String) metadata.get("ipAddress");
                    metadata.put("ipAddress", maskIpAddress(ip));
                }
            }
            
            return documents;
        }
        
        private String anonymizeEmail(String email) {
            if (email == null || !email.contains("@")) return "***@***.***";
            String[] parts = email.split("@");
            return parts[0].substring(0, Math.min(3, parts[0].length())) + "***@" + parts[1];
        }
        
        private String maskIpAddress(String ip) {
            if (ip == null || !ip.contains(".")) return ip;
            String[] parts = ip.split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + "." + parts[2] + ".***";
            }
            return ip;
        }
    }
}