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

    private final Map<String, Long> metrics = new ConcurrentHashMap<>();
    private final Map<String, ETLJobStatus> jobStatuses = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void initialize() {
        executorService = Executors.newFixedThreadPool(parallelReaders);
        
        this.textSplitter = new TokenTextSplitter(chunkSize, chunkOverlap, 5, 10000, true);

        this.dataValidator = new BehaviorDataValidator();

        this.anonymizer = new BehaviorAnonymizer();
    }

    @Async
    public CompletableFuture<String> executePipeline(String dataSource, SourceType sourceType) {
        String jobId = UUID.randomUUID().toString();
        ETLJobStatus jobStatus = new ETLJobStatus(jobId, LocalDateTime.now());
        jobStatuses.put(jobId, jobStatus);
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                jobStatus.setStatus(JobStatus.RUNNING);

                List<Document> rawDocuments = extractData(dataSource, sourceType, jobStatus);
                jobStatus.setExtractedCount(rawDocuments.size());

                List<Document> transformedDocuments = transformData(rawDocuments, jobStatus);
                jobStatus.setTransformedCount(transformedDocuments.size());

                loadData(transformedDocuments, jobStatus);
                jobStatus.setLoadedCount(transformedDocuments.size());
                
                jobStatus.setStatus(JobStatus.COMPLETED);
                jobStatus.setEndTime(LocalDateTime.now());

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

    private List<Document> extractFromFile(String filePath) {
        List<Document> documents = new ArrayList<>();
        Path path = Paths.get(filePath);
        
        try {
            if (Files.isDirectory(path)) {
                
                List<CompletableFuture<List<Document>>> futures = new ArrayList<>();
                
                try (Stream<Path> paths = Files.walk(path)) {
                    paths.filter(Files::isRegularFile)
                        .forEach(file -> {
                            CompletableFuture<List<Document>> future = CompletableFuture.supplyAsync(
                                () -> readSingleFile(file), executorService);
                            futures.add(future);
                        });
                }

                for (CompletableFuture<List<Document>> future : futures) {
                    documents.addAll(future.join());
                }
                
            } else {
                
                documents = readSingleFile(path);
            }
            
        } catch (IOException e) {
            throw new ETLPipelineException("Failed to extract from file: " + filePath, e);
        }
        
        return documents;
    }

    private List<Document> readSingleFile(Path file) {
        String fileName = file.getFileName().toString().toLowerCase();
        
        try {
            if (fileName.endsWith(".json")) {

                Resource resource = new FileSystemResource(file.toFile());
                JsonReader reader = new JsonReader(resource, "userId", "timestamp", "activity");
                return reader.get();
                
            } else if (fileName.endsWith(".txt") || fileName.endsWith(".log")) {
                
                TextReader reader = new TextReader(file.toUri().toString());
                List<Document> docs = reader.get();

                return parseLogDocuments(docs);
                
            } else if (fileName.endsWith(".csv")) {
                
                return readCsvFile(file);
            }
            
        } catch (Exception e) {
            
        }
        
        return Collections.emptyList();
    }

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

    private Map<String, Object> parseLogLine(String line) {
        Map<String, Object> metadata = new HashMap<>();

        String timestampPattern = "\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(timestampPattern);
        java.util.regex.Matcher matcher = pattern.matcher(line);
        
        if (matcher.find()) {
            metadata.put("timestamp", matcher.group());
        }

        if (line.contains("ERROR")) metadata.put("level", "ERROR");
        else if (line.contains("WARN")) metadata.put("level", "WARN");
        else if (line.contains("INFO")) metadata.put("level", "INFO");
        else if (line.contains("DEBUG")) metadata.put("level", "DEBUG");

        pattern = java.util.regex.Pattern.compile("user[Id]*[:=]([\\w-]+)", java.util.regex.Pattern.CASE_INSENSITIVE);
        matcher = pattern.matcher(line);
        if (matcher.find()) {
            metadata.put("userId", matcher.group(1));
        }

        pattern = java.util.regex.Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
        matcher = pattern.matcher(line);
        if (matcher.find()) {
            metadata.put("ipAddress", matcher.group());
        }
        
        return metadata;
    }

    private List<Document> extractFromDatabase(String query) {
        List<Document> documents = new ArrayList<>();
        
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(query);
        
        for (Map<String, Object> row : rows) {
            
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

    private List<Document> extractFromAPI(String endpoint) {

        return new ArrayList<>();
    }

    private List<Document> extractFromStream(String streamConfig) {

        return new ArrayList<>();
    }

    private List<Document> transformData(List<Document> documents, ETLJobStatus jobStatus) {
        if (documents == null || documents.isEmpty()) {
            return documents;
        }

        documents = dataValidator.apply(documents);

        documents = anonymizer.apply(documents);

        documents = metadataEnricher.apply(documents);

        List<Document> chunkedDocuments = new ArrayList<>();
        for (Document doc : documents) {
            List<Document> chunks = textSplitter.apply(List.of(doc));

            for (int i = 0; i < chunks.size(); i++) {
                Document chunk = chunks.get(i);
                chunk.getMetadata().putAll(doc.getMetadata());
                chunk.getMetadata().put("chunkIndex", i);
                chunk.getMetadata().put("totalChunks", chunks.size());
                chunk.getMetadata().put("etlJobId", jobStatus.getJobId());
            }
            
            chunkedDocuments.addAll(chunks);
        }

        chunkedDocuments = removeDuplicates(chunkedDocuments);
        
        return chunkedDocuments;
    }

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

    private String generateContentHash(Document document) {
        String content = document.getText();
        String userId = (String) document.getMetadata().get("userId");
        String timestamp = (String) document.getMetadata().get("timestamp");
        
        String combined = (content != null ? content : "") + 
                         (userId != null ? userId : "") + 
                         (timestamp != null ? timestamp : "");
        
        return Integer.toHexString(combined.hashCode());
    }

    @Transactional
    public void loadData(List<Document> documents, ETLJobStatus jobStatus) {
        if (documents == null || documents.isEmpty()) {
            return;
        }

        for (int i = 0; i < documents.size(); i += batchSize) {
            int end = Math.min(i + batchSize, documents.size());
            List<Document> batch = documents.subList(i, end);

            vectorStore.add(batch);

            jobStatus.setLoadedCount(i + batch.size());
        }

        cleanupOldData();
    }

    private void cleanupOldData() {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(retentionDays);
        String cutoffDateStr = cutoffDate.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

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

    private void updateMetrics(ETLJobStatus jobStatus) {
        metrics.put("lastJobDuration", 
            java.time.Duration.between(jobStatus.getStartTime(), jobStatus.getEndTime()).toMillis());
        metrics.put("totalJobsCompleted", 
            metrics.getOrDefault("totalJobsCompleted", 0L) + 1);
        metrics.put("totalDocumentsProcessed", 
            metrics.getOrDefault("totalDocumentsProcessed", 0L) + jobStatus.getLoadedCount());
    }

    public ETLJobStatus getJobStatus(String jobId) {
        return jobStatuses.get(jobId);
    }

    public List<ETLJobStatus> getAllJobStatuses() {
        return new ArrayList<>(jobStatuses.values());
    }

    public Map<String, Long> getMetrics() {
        return new HashMap<>(metrics);
    }

    public void shutdown() {
        executorService.shutdown();
    }

    public enum SourceType {
        FILE, DATABASE, API, STREAM
    }

    public enum JobStatus {
        PENDING, RUNNING, COMPLETED, FAILED
    }

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

    public static class ETLPipelineException extends RuntimeException {
        public ETLPipelineException(String message) {
            super(message);
        }
        
        public ETLPipelineException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static class BehaviorDataValidator implements DocumentTransformer {
        @Override
        public List<Document> apply(List<Document> documents) {
            return documents.stream()
                .filter(doc -> {
                    Map<String, Object> metadata = doc.getMetadata();
                    
                    return metadata.containsKey("userId") || 
                           metadata.containsKey("sessionId") ||
                           metadata.containsKey("ipAddress");
                })
                .collect(Collectors.toList());
        }
    }

    private static class BehaviorAnonymizer implements DocumentTransformer {
        @Override
        public List<Document> apply(List<Document> documents) {
            for (Document doc : documents) {
                Map<String, Object> metadata = doc.getMetadata();

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