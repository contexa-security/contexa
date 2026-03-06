package io.contexa.contexacore.std.rag.etl;

import io.contexa.contexacore.properties.ContexaRagProperties;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.reader.JsonReader;
import org.springframework.ai.reader.TextReader;
import org.springframework.ai.transformer.splitter.TokenTextSplitter;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Slf4j
public class BehaviorETLPipeline {

    private final VectorStore vectorStore;
    private final JdbcTemplate jdbcTemplate;
    private final ContexaRagProperties ragProperties;
    private TokenTextSplitter textSplitter;

    public BehaviorETLPipeline(VectorStore vectorStore, JdbcTemplate jdbcTemplate,
                               ContexaRagProperties ragProperties) {
        this.vectorStore = vectorStore;
        this.jdbcTemplate = jdbcTemplate;
        this.ragProperties = ragProperties;
    }

    @PostConstruct
    public void initialize() {
        this.textSplitter = new TokenTextSplitter(
                ragProperties.getEtl().getChunkSize(),
                ragProperties.getEtl().getChunkOverlap(),
                5, 10000, true);
    }

    @Async
    public CompletableFuture<String> executePipeline(String dataSource, SourceType sourceType) {
        String jobId = UUID.randomUUID().toString();

        try {
            List<Document> documents = extractData(dataSource, sourceType);
            if (documents.isEmpty()) {
                return CompletableFuture.completedFuture(jobId);
            }

            documents = transformData(documents);
            loadData(documents);

            return CompletableFuture.completedFuture(jobId);

        } catch (Exception e) {
            log.error("ETL pipeline failed: jobId={}", jobId, e);
            throw new ETLPipelineException("ETL pipeline failed", e);
        }
    }

    private List<Document> extractData(String dataSource, SourceType sourceType) {
        return switch (sourceType) {
            case FILE -> extractFromFile(dataSource);
            case DATABASE -> extractFromDatabase(dataSource);
        };
    }

    private List<Document> extractFromFile(String filePath) {
        List<Document> documents = new ArrayList<>();
        Path path = Paths.get(filePath);

        try {
            if (Files.isDirectory(path)) {
                try (Stream<Path> paths = Files.walk(path)) {
                    paths.filter(Files::isRegularFile)
                        .forEach(file -> documents.addAll(readSingleFile(file)));
                }
            } else {
                documents.addAll(readSingleFile(path));
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
                return parseLogDocuments(reader.get());

            } else if (fileName.endsWith(".csv")) {
                return readCsvFile(file);
            }

        } catch (Exception e) {
            log.error("Failed to read file: {}", file, e);
        }

        return Collections.emptyList();
    }

    private List<Document> readCsvFile(Path file) throws IOException {
        List<Document> documents = new ArrayList<>();
        List<String> lines = Files.readAllLines(file);

        if (lines.isEmpty()) {
            return documents;
        }

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

            documents.add(new Document(content.toString(), metadata));
        }

        return documents;
    }

    private List<Document> parseLogDocuments(List<Document> rawDocs) {
        List<Document> parsedDocs = new ArrayList<>();

        for (Document rawDoc : rawDocs) {
            String[] lines = rawDoc.getText().split("\n");

            for (String line : lines) {
                if (line.trim().isEmpty()) {
                    continue;
                }

                Map<String, Object> metadata = parseLogLine(line);
                if (!metadata.isEmpty()) {
                    parsedDocs.add(new Document(line, metadata));
                }
            }
        }

        return parsedDocs;
    }

    private Map<String, Object> parseLogLine(String line) {
        Map<String, Object> metadata = new HashMap<>();

        Pattern timestampPattern = Pattern.compile("\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}");
        Matcher matcher = timestampPattern.matcher(line);
        if (matcher.find()) {
            metadata.put("timestamp", matcher.group());
        }

        if (line.contains("ERROR")) {
            metadata.put("level", "ERROR");
        } else if (line.contains("WARN")) {
            metadata.put("level", "WARN");
        }

        Pattern userPattern = Pattern.compile("user[Id]*[:=]([\\w-]+)", Pattern.CASE_INSENSITIVE);
        matcher = userPattern.matcher(line);
        if (matcher.find()) {
            metadata.put("userId", matcher.group(1));
        }

        Pattern ipPattern = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
        matcher = ipPattern.matcher(line);
        if (matcher.find()) {
            metadata.put("ipAddress", matcher.group());
        }

        return metadata;
    }

    private void validateQuery(String query) {
        if (query == null || query.isBlank()) {
            throw new ETLPipelineException("Query cannot be null or empty", null);
        }
        String normalized = query.trim().toUpperCase();
        if (!normalized.startsWith("SELECT")) {
            throw new ETLPipelineException("Only SELECT queries are allowed for ETL extraction", null);
        }
        if (query.contains(";")) {
            throw new ETLPipelineException("Multiple statements are not allowed in ETL query", null);
        }
    }

    private List<Document> extractFromDatabase(String query) {
        validateQuery(query);
        List<Document> documents = new ArrayList<>();

        List<Map<String, Object>> rows = jdbcTemplate.queryForList(query);

        for (Map<String, Object> row : rows) {
            StringBuilder content = new StringBuilder();
            Map<String, Object> metadata = new HashMap<>();

            for (Map.Entry<String, Object> entry : row.entrySet()) {
                if (entry.getValue() != null) {
                    metadata.put(entry.getKey(), entry.getValue().toString());
                    content.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                }
            }

            documents.add(new Document(content.toString(), metadata));
        }

        return documents;
    }

    private List<Document> transformData(List<Document> documents) {
        List<Document> chunkedDocuments = new ArrayList<>();

        for (Document doc : documents) {
            List<Document> chunks = textSplitter.apply(List.of(doc));
            for (Document chunk : chunks) {
                chunk.getMetadata().putAll(doc.getMetadata());
            }
            chunkedDocuments.addAll(chunks);
        }

        return removeDuplicates(chunkedDocuments);
    }

    private List<Document> removeDuplicates(List<Document> documents) {
        Set<String> contentHashes = new HashSet<>();
        List<Document> uniqueDocs = new ArrayList<>();

        for (Document doc : documents) {
            String hash = generateContentHash(doc);
            if (contentHashes.add(hash)) {
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
    public void loadData(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return;
        }

        for (int i = 0; i < documents.size(); i += ragProperties.getEtl().getBatchSize()) {
            int end = Math.min(i + ragProperties.getEtl().getBatchSize(), documents.size());
            List<Document> batch = documents.subList(i, end);
            vectorStore.add(batch);
        }

        cleanupOldData();
    }

    private void cleanupOldData() {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(ragProperties.getEtl().getBehavior().getRetentionDays());
        String cutoffDateStr = cutoffDate.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        try {
            List<String> oldDocumentIds = jdbcTemplate.queryForList(
                "SELECT id FROM " + ragProperties.getEtl().getVectorTableName() + " WHERE metadata->>'timestamp' < ?",
                String.class,
                cutoffDateStr
            );

            if (!oldDocumentIds.isEmpty()) {
                vectorStore.delete(oldDocumentIds);
            }
        } catch (Exception e) {
            log.error("Failed to cleanup old data", e);
        }
    }

    public enum SourceType {
        FILE, DATABASE
    }

    public static class ETLPipelineException extends RuntimeException {
        public ETLPipelineException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
