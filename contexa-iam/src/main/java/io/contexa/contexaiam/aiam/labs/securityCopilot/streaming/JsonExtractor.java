package io.contexa.contexaiam.aiam.labs.securityCopilot.streaming;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JsonExtractor {

    public static String extractJson(String rawText) {
        if (rawText == null || rawText.isEmpty()) return "{}";

        String searchText = rawText;

        // 마커 제거
        if (searchText.contains("###FINAL_RESPONSE###")) {
            searchText = searchText.substring(searchText.indexOf("###FINAL_RESPONSE###") + "###FINAL_RESPONSE###".length());
        }

        searchText = searchText.trim();

        // JSON 시작 위치 찾기
        int startIndex = searchText.indexOf('{');
        if (startIndex == -1) return "{}";

        // 스택 기반 파싱으로 JSON 끝 찾기
        int braceDepth = 0;
        int bracketDepth = 0;
        boolean inString = false;
        boolean escaped = false;
        int endIndex = -1;

        for (int i = startIndex; i < searchText.length(); i++) {
            char c = searchText.charAt(i);

            // 이스케이프 문자 처리
            if (escaped) {
                escaped = false;
                continue;
            }

            if (c == '\\' && inString) {
                escaped = true;
                continue;
            }

            // 문자열 내부 체크
            if (c == '"' && !escaped) {
                inString = !inString;
                continue;
            }

            // 문자열 내부가 아닐 때만 중괄호/대괄호 카운트
            if (!inString) {
                switch (c) {
                    case '{':
                        braceDepth++;
                        break;
                    case '}':
                        braceDepth--;
                        if (braceDepth == 0 && bracketDepth == 0) {
                            endIndex = i;
                            break;
                        }
                        break;
                    case '[':
                        bracketDepth++;
                        break;
                    case ']':
                        bracketDepth--;
                        break;
                }

                // JSON이 완료되면 루프 종료
                if (endIndex != -1) {
                    break;
                }
            }
        }

        if (endIndex != -1) {
            String extracted = searchText.substring(startIndex, endIndex + 1);
            log.debug("JSON 추출 완료. 길이: {}, 시작: {}, 끝: {}",
                    extracted.length(), startIndex, endIndex);
            return extracted;
        }

        // 완전한 JSON을 찾지 못한 경우
        log.warn("완성된 JSON을 찾지 못함. Depth - braces: {}, brackets: {}",
                braceDepth, bracketDepth);

        // 코드 블록이 있다면 그 안에서만 찾기
        if (rawText.contains("```")) {
            int codeStart = rawText.indexOf("```");
            int codeEnd = rawText.indexOf("```", codeStart + 3);
            if (codeEnd > codeStart) {
                String codeBlock = rawText.substring(codeStart + 3, codeEnd);
                if (codeBlock.startsWith("json")) {
                    codeBlock = codeBlock.substring(4).trim();
                }
                log.info("코드 블록 내에서 재시도");
                return extractJson(codeBlock);
            }
        }

        return searchText.substring(startIndex);
    }
}