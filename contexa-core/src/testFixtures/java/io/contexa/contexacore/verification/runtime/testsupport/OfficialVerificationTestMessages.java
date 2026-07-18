package io.contexa.contexacore.verification.runtime.testsupport;

import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import java.util.Arrays;

public final class OfficialVerificationTestMessages {

    private OfficialVerificationTestMessages() {
    }

    public static OfficialVerificationMessageResolver deterministic() {
        return (key, args) -> {
            String arguments = args == null || args.length == 0
                    ? ""
                    : " " + Arrays.stream(args)
                            .map(String::valueOf)
                            .reduce((left, right) -> left + " " + right)
                            .orElse("");
            return switch (key) {
                case "enterprise.pqa.runtimeVerification.preflight.failed" ->
                        "PREFLIGHT_FINAL_PROMPT_CONTRACT failed:" + arguments;
                case "verification.finalPrompt.comparison.selectableLabel" -> "선택 비교 항목";
                case "verification.finalPrompt.comparison.noActualValue" ->
                        String.valueOf(args[0]) + " 값은 제공된 실제 값이 없어 비교 충돌로 판단하지 않습니다.";
                case "verification.finalPrompt.fragment.omitted" -> "생략됨";
                case "verification.finalPrompt.fragment.valueConnector" -> "값은";
                case "verification.finalPrompt.truncation.none" -> "감지된 잘림 표식과 자리표시자는 0개입니다.";
                case "verification.finalPrompt.value.present" -> "있음";
                case "verification.finalPrompt.value.absent" -> "없음";
                case "verification.finalPrompt.format.confirmed" ->
                        "시스템 지시문에서 확인된 응답 형식 항목: " + args[0];
                case "verification.finalPrompt.inspection.genericItem" -> "검사 항목";
                case "verification.finalPrompt.value.named" -> args[0] + " 값은 " + args[1];
                case "verification.finalPrompt.prompt.section" -> "프롬프트 섹션";
                case "verification.finalPrompt.truncation.foundCount" ->
                        "잘림 표식 또는 자리표시자가 포함된 프롬프트 항목 " + args[0] + "개가 발견되었습니다.";
                case "verification.finalPrompt.prompt.found" -> "발견됨";
                case "verification.finalPrompt.prompt.expression" -> "프롬프트 표현";
                default -> "테스트 검증 문구 (" + key + ")" + arguments;
            };
        };
    }
}