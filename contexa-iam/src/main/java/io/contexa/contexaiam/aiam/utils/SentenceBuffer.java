package io.contexa.contexaiam.aiam.utils;

import reactor.core.publisher.Flux;
import java.util.ArrayList;
import java.util.List;

public class SentenceBuffer {
    private final StringBuilder buffer = new StringBuilder();
    private final List<String> completeSentences = new ArrayList<>();
    private boolean inJsonBlock = false;
    private int jsonDepth = 0;

    private static final String[] KOREAN_ENDINGS = {
            "확인했습니다.", "완료했습니다.", "시작했습니다.", "분석했습니다.",
            "검토했습니다.", "처리했습니다.", "조회했습니다.", "찾았습니다.",
            "진행했습니다.", "실행했습니다.", "수행했습니다.", "생성했습니다.",
            "했습니다.", "있습니다.", "됩니다.", "습니다.", "입니다.",
            "니다.", "했다.", "했어요.", "했요.", "다.", "요.", "!",
            
            "===", "###", "시작 ===", "완료 ===", "진행 ===", "분석 ===",
            "평가 ===", "생성 ===", "권한분석]", "위험평가]", "정책생성]"
    };

    public Flux<String> processChunk(String chunk) {
        if (chunk == null || chunk.trim().isEmpty()) {
            return Flux.empty();
        }

        if (chunk.contains("```json") || chunk.contains("===JSON시작===") ||
                chunk.contains("===JSON") || chunk.trim().startsWith("{\"")) {
            inJsonBlock = true;
            jsonDepth += countChar(chunk, '{') - countChar(chunk, '}');
            return Flux.empty(); 
        }

        if (inJsonBlock) {
            jsonDepth += countChar(chunk, '{') - countChar(chunk, '}');

            if (jsonDepth <= 0 || chunk.contains("```") || chunk.contains("===JSON끝===")) {
                inJsonBlock = false;
                jsonDepth = 0;
            }
            return Flux.empty(); 
        }

        String cleanChunk = cleanAndFilterChunk(chunk);
        if (cleanChunk.trim().isEmpty()) {
            return Flux.empty();
        }

        buffer.append(cleanChunk);

        extractCompleteSentences();

        List<String> result = new ArrayList<>(completeSentences);
        completeSentences.clear();

        return Flux.fromIterable(result);
    }

    private String cleanAndFilterChunk(String chunk) {
        if (chunk == null) return "";

        String cleaned = chunk;

        cleaned = cleaned.replaceAll("===JSON[^=]*===", "");
        cleaned = cleaned.replaceAll("```json[\\s\\S]*?```", "");

        cleaned = cleaned.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");

        return cleaned;
    }

    private void extractCompleteSentences() {
        String text = buffer.toString();

        String[] lines = text.split("\\n");
        StringBuilder remainingBuffer = new StringBuilder();

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();

            if (isCompleteLine(line)) {
                if (isValidSentence(line)) {
                    completeSentences.add(line);
                }
            } else {
                
                if (i == lines.length - 1) {
                    
                    remainingBuffer.append(line);
                } else {
                    
                    if (isValidSentence(line)) {
                        completeSentences.add(line);
                    }
                }
            }
        }

        buffer.setLength(0);
        if (remainingBuffer.length() > 0) {
            buffer.append(remainingBuffer.toString());
        }
    }

    private boolean isCompleteLine(String line) {
        if (line == null || line.trim().isEmpty()) {
            return false;
        }

        if (line.contains("===") || line.contains("###")) {
            return true;
        }

        for (String ending : KOREAN_ENDINGS) {
            if (line.endsWith(ending)) {
                return true;
            }
        }

        if (line.endsWith(".") || line.endsWith("!") || line.endsWith("?")) {
            return true;
        }

        return false;
    }

    private boolean isValidSentence(String sentence) {
        if (sentence == null || sentence.trim().isEmpty()) return false;

        String trimmed = sentence.trim();

        if (trimmed.length() < 3 && !containsSpecialPattern(trimmed)) return false;

        if (trimmed.matches("^[.,!?;:]+$")) return false;

        if (containsSpecialPattern(trimmed)) {
            return true;
        }

        return trimmed.matches(".*[가-힣a-zA-Z0-9]+.*");
    }

    private boolean containsSpecialPattern(String text) {
        if (text == null || text.trim().isEmpty()) return false;

        if (text.contains("===")) {
            return true;
        }

        if (text.contains("###")) {
            return true;
        }

        String[] labKeywords = {
                "권한분석", "위험평가", "정책생성", "분석 시작", "분석 완료",
                "진행 중", "처리 중", "StudioQuery", "RiskAssessment", "PolicyGeneration"
        };

        for (String keyword : labKeywords) {
            if (text.contains(keyword)) {
                return true;
            }
        }

        return false;
    }

    private int countChar(String str, char ch) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == ch) count++;
        }
        return count;
    }

    public Flux<String> flush() {
        if (buffer.length() > 0) {
            String remaining = buffer.toString().trim();
            buffer.setLength(0);

            if (isValidSentence(remaining)) {
                return Flux.just(remaining);
            }
        }
        return Flux.empty();
    }
}

