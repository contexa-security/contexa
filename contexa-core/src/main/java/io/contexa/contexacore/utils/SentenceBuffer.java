package io.contexa.contexacore.utils;

import io.contexa.contexacore.std.pipeline.streaming.StreamingProtocol;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class SentenceBuffer {
    private final StringBuilder buffer = new StringBuilder();
    private final List<String> completeSentences = new ArrayList<>();
    private boolean inJsonBlock = false;
    private int jsonDepth = 0;

    private static final Pattern JSON_MARKER_PATTERN = Pattern.compile("===JSON[^=]*===");
    private static final Pattern JSON_CODE_BLOCK_PATTERN = Pattern.compile("```json[\\s\\S]*?```");
    private static final Pattern CONTROL_CHAR_PATTERN = Pattern.compile("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]");
    private static final Pattern MARKDOWN_HEADER_PATTERN = Pattern.compile("#{1,6}\\s*");
    private static final Pattern PUNCTUATION_ONLY_PATTERN = Pattern.compile("^[.,!?;:]+$");
    private static final Pattern VALID_CONTENT_PATTERN = Pattern.compile(".*[가-힣a-zA-Z0-9]+.*");
    private static final Pattern NEWLINE_SPLIT_PATTERN = Pattern.compile("\\n");

    private static final int MAX_BUFFER_SIZE = 200;

    private static final String[] KOREAN_ENDINGS = {
            "확인했습니다.", "완료했습니다.", "시작했습니다.", "분석했습니다.",
            "검토했습니다.", "처리했습니다.", "조회했습니다.", "찾았습니다.",
            "진행했습니다.", "실행했습니다.", "수행했습니다.", "생성했습니다.",
            "했습니다.", "있습니다.", "됩니다.", "습니다.", "입니다.",
            "니다.", "했다.", "했어요.", "했요.", "다.", "요.", "!",

            "권한분석]", "위험평가]", "정책생성]"
    };

    public Flux<String> processChunk(String chunk) {
        if (chunk == null || chunk.trim().isEmpty()) {
            return Flux.empty();
        }

        if (chunk.contains("```json") || chunk.contains(StreamingProtocol.JSON_START_MARKER) ||
                chunk.contains("===JSON") || chunk.trim().startsWith("{\"")) {
            inJsonBlock = true;
            jsonDepth += countChar(chunk, '{') - countChar(chunk, '}');
            return Flux.empty();
        }

        if (inJsonBlock) {
            jsonDepth += countChar(chunk, '{') - countChar(chunk, '}');

            if (jsonDepth <= 0 || chunk.contains("```") || chunk.contains(StreamingProtocol.JSON_END_MARKER)) {
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

        cleaned = JSON_MARKER_PATTERN.matcher(cleaned).replaceAll("");
        cleaned = JSON_CODE_BLOCK_PATTERN.matcher(cleaned).replaceAll("");
        cleaned = CONTROL_CHAR_PATTERN.matcher(cleaned).replaceAll("");

        // Strip markdown header symbols (###, ##, #) and decorative markers (===)
        cleaned = MARKDOWN_HEADER_PATTERN.matcher(cleaned).replaceAll("");
        cleaned = cleaned.replace("===", "");

        return cleaned;
    }

    private void extractCompleteSentences() {
        String text = buffer.toString();

        String[] lines = NEWLINE_SPLIT_PATTERN.split(text);
        StringBuilder remainingBuffer = new StringBuilder();
        StringBuilder pendingLine = new StringBuilder();

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) continue;

            // Merge with pending incomplete line
            if (pendingLine.length() > 0) {
                pendingLine.append(" ").append(line);
                line = pendingLine.toString();
            }

            if (isCompleteLine(line)) {
                if (isValidSentence(line)) {
                    completeSentences.add(line);
                }
                pendingLine.setLength(0);
            } else if (i == lines.length - 1) {
                // Last line: keep in buffer for next chunk
                remainingBuffer.append(pendingLine.length() > 0 ? pendingLine : line);
                pendingLine.setLength(0);
            } else {
                // Middle incomplete line: accumulate with next line
                if (pendingLine.length() == 0) {
                    pendingLine.append(line);
                }
            }
        }

        // Flush pending line to buffer if not consumed
        if (pendingLine.length() > 0) {
            if (remainingBuffer.length() > 0) {
                remainingBuffer.append(" ");
            }
            remainingBuffer.append(pendingLine);
        }

        buffer.setLength(0);
        if (!remainingBuffer.isEmpty()) {
            buffer.append(remainingBuffer);
        }

        // Force flush if buffer exceeds max size to maintain UI responsiveness
        if (buffer.length() > MAX_BUFFER_SIZE && completeSentences.isEmpty()) {
            String forced = buffer.toString().trim();
            if (isValidSentence(forced)) {
                completeSentences.add(forced);
            }
            buffer.setLength(0);
        }
    }

    private boolean isCompleteLine(String line) {
        if (line == null || line.trim().isEmpty()) {
            return false;
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

        if (PUNCTUATION_ONLY_PATTERN.matcher(trimmed).matches()) return false;

        if (containsSpecialPattern(trimmed)) {
            return true;
        }

        return VALID_CONTENT_PATTERN.matcher(trimmed).matches();
    }

    private boolean containsSpecialPattern(String text) {
        if (text == null || text.trim().isEmpty()) return false;

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
