package io.contexa.contexacore.utils;

import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.List;

/**
 * 문장 단위 버퍼링 클래스 - 한국어 지원 개선
 *
 * 한국어 문장 종결어미 지원
 * JSON 블록 필터링
 * 완성된 문장만 전송
 * PROGRESS 문자열 반복 문제 해결
 */
public class SentenceBuffer {
    private final StringBuilder buffer = new StringBuilder();
    private final List<String> completeSentences = new ArrayList<>();
    private boolean inJsonBlock = false;
    private int jsonDepth = 0;

    // 한국어 문장 종결어미 패턴 (긴 패턴부터 우선 처리)
    private static final String[] KOREAN_ENDINGS = {
            "확인했습니다.", "완료했습니다.", "시작했습니다.", "분석했습니다.",
            "검토했습니다.", "처리했습니다.", "조회했습니다.", "찾았습니다.",
            "진행했습니다.", "실행했습니다.", "수행했습니다.", "생성했습니다.",
            "했습니다.", "있습니다.", "됩니다.", "습니다.", "입니다.",
            "니다.", "했다.", "했어요.", "했요.", "다.", "요.", "!",
            // 특별 패턴 추가
            "===", "###", "시작 ===", "완료 ===", "진행 ===", "분석 ===",
            "평가 ===", "생성 ===", "권한분석]", "위험평가]", "정책생성]"
    };

    /**
     * 청크를 처리하여 완성된 문장들을 반환
     */
    public Flux<String> processChunk(String chunk) {
        if (chunk == null || chunk.trim().isEmpty()) {
            return Flux.empty();
        }

        // JSON 블록 시작 감지
        if (chunk.contains("```json") || chunk.contains("===JSON시작===") ||
                chunk.contains("===JSON") || chunk.trim().startsWith("{\"")) {
            inJsonBlock = true;
            jsonDepth += countChar(chunk, '{') - countChar(chunk, '}');
            return Flux.empty(); // JSON은 클라이언트로 전송하지 않음
        }

        // JSON 블록 내부
        if (inJsonBlock) {
            jsonDepth += countChar(chunk, '{') - countChar(chunk, '}');

            // JSON 블록 종료 확인
            if (jsonDepth <= 0 || chunk.contains("```") || chunk.contains("===JSON끝===")) {
                inJsonBlock = false;
                jsonDepth = 0;
            }
            return Flux.empty(); // JSON은 클라이언트로 전송하지 않음
        }

        // 일반 텍스트 처리
        String cleanChunk = cleanAndFilterChunk(chunk);
        if (cleanChunk.trim().isEmpty()) {
            return Flux.empty();
        }

        buffer.append(cleanChunk);

        // 완성된 문장 추출
        extractCompleteSentences();

        // 완성된 문장들 반환
        List<String> result = new ArrayList<>(completeSentences);
        completeSentences.clear();

        return Flux.fromIterable(result);
    }

    /**
     * 청크 정리 및 필터링
     */
    private String cleanAndFilterChunk(String chunk) {
        if (chunk == null) return "";

        String cleaned = chunk;

        // JSON 관련 마커 제거 (Lab 진행 상황 메시지는 보존)
        cleaned = cleaned.replaceAll("===JSON[^=]*===", "");
        cleaned = cleaned.replaceAll("```json[\\s\\S]*?```", "");

        // Lab 진행 상황 메시지는 보존하도록 수정
        // 기존: === 패턴을 모두 제거
        // 수정: ===JSON=== 패턴만 제거하고 일반 === 패턴은 보존

        // TODO: PROGRESS 문자열 근본 원인 해결 후 이 코드 제거 예정

        // 특수 문자 정리
        cleaned = cleaned.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");

        return cleaned;
    }

    /**
     * 완성된 문장 추출 - 줄 단위 및 패턴 기반
     */
    private void extractCompleteSentences() {
        String text = buffer.toString();

        // 줄 단위로 분리하여 처리
        String[] lines = text.split("\\n");
        StringBuilder remainingBuffer = new StringBuilder();

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();

            // 완성된 줄인지 확인
            if (isCompleteLine(line)) {
                if (isValidSentence(line)) {
                    completeSentences.add(line);
                }
            } else {
                // 미완성 줄이면 버퍼에 다시 추가
                if (i == lines.length - 1) {
                    // 마지막 줄이면 미완성일 수 있으므로 버퍼에 유지
                    remainingBuffer.append(line);
                } else {
                    // 중간에 미완성 줄이 있으면 다음 줄과 합쳐서 처리
                    if (isValidSentence(line)) {
                        completeSentences.add(line);
                    }
                }
            }
        }

        // 버퍼 업데이트
        buffer.setLength(0);
        if (remainingBuffer.length() > 0) {
            buffer.append(remainingBuffer.toString());
        }
    }

    /**
     * 완성된 줄인지 확인
     */
    private boolean isCompleteLine(String line) {
        if (line == null || line.trim().isEmpty()) {
            return false;
        }

        // 특별 패턴 확인 (=== 또는 ### 패턴)
        if (line.contains("===") || line.contains("###")) {
            return true;
        }

        // 한국어 문장 종결어미 확인
        for (String ending : KOREAN_ENDINGS) {
            if (line.endsWith(ending)) {
                return true;
            }
        }

        // 영어 문장 종결자 확인
        if (line.endsWith(".") || line.endsWith("!") || line.endsWith("?")) {
            return true;
        }

        return false;
    }


    /**
     * 유효한 문장인지 확인
     */
    private boolean isValidSentence(String sentence) {
        if (sentence == null || sentence.trim().isEmpty()) return false;

        String trimmed = sentence.trim();

        // 너무 짧은 문장 제외 (단, 특별 패턴은 예외)
        if (trimmed.length() < 3 && !containsSpecialPattern(trimmed)) return false;

        // 단순 구두점만 있는 경우 제외
        if (trimmed.matches("^[.,!?;:]+$")) return false;

        // 특별 패턴 확인 (Lab 진행 상황 메시지)
        if (containsSpecialPattern(trimmed)) {
            return true;
        }

        // 의미 있는 텍스트가 포함되어 있는지 확인
        return trimmed.matches(".*[가-힣a-zA-Z0-9]+.*");
    }

    /**
     * 특별 패턴 포함 여부 확인
     */
    private boolean containsSpecialPattern(String text) {
        if (text == null || text.trim().isEmpty()) return false;

        // === 패턴 (Lab 진행 상황)
        if (text.contains("===")) {
            return true;
        }

        // ### 패턴 (진행 단계)
        if (text.contains("###")) {
            return true;
        }

        // Lab 관련 키워드
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

    /**
     * 문자 개수 세기
     */
    private int countChar(String str, char ch) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == ch) count++;
        }
        return count;
    }

    /**
     * 버퍼에 남은 내용을 모두 반환
     */
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

