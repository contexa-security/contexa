package io.contexa.demo.experience.report.render;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.demo.experience.report.dto.StoredReport;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@Component
@Profile("portal")
public class HtmlReportRenderer implements ReportRenderer {

    private final DocumentCodec documents;
    private final String template;
    private final String stylesheet;

    public HtmlReportRenderer(DocumentCodec documents) throws IOException {
        this.documents = documents;
        this.template = new ClassPathResource("lab/report/report.html").getContentAsString(StandardCharsets.UTF_8);
        this.stylesheet = new ClassPathResource("lab/report/report.css").getContentAsString(StandardCharsets.UTF_8);
    }

    @Override
    public String html(StoredReport report, String language) {
        boolean english = "en".equals(language);
        String unknown = english ? "Not collected" : "미수집";
        String rows = report.payload().execution().steps().stream().map(step -> {
            var source = report.payload().sources().stream()
                    .filter(value -> step.arm().equals(value.arm())
                            && step.requestId() != null && step.requestId().equals(value.requestId()))
                    .findFirst().orElse(null);
            var evidence = source == null ? null : source.evidence();
            String actions = evidence == null || evidence.path("decisions").isEmpty() ? unknown
                    : StreamSupport.stream(evidence.path("decisions").spliterator(), false)
                            .map(decision -> describeDecision(decision, english, unknown))
                            .collect(Collectors.joining(", "));
            return "<tr><th scope=\"row\">" + escape(step.arm()) + "</th><td>"
                    + escape(step.state()) + "</td><td>" + escape(step.httpStatus() == null ? unknown : step.httpStatus())
                    + "</td><td>" + escape(actions) + "</td><td>"
                    + escape(step.failureType() == null ? "—" : step.failureType()) + "</td></tr>";
        }).collect(Collectors.joining());
        return template.replace("{{language}}", english ? "en" : "ko")
                .replace("{{style}}", stylesheet)
                .replace("{{title}}", english ? "Experience report" : "체험 결과 보고서")
                .replace("{{description}}", english
                        ? "An immutable record of one execution. HTTP results, engine decisions and reviewer opinions are distinct."
                        : "한 실행의 원본을 고정한 기록입니다. HTTP 결과·엔진 결정·검토자의 의견은 서로 다른 정보입니다.")
                .replace("{{captured}}", english ? "Captured at" : "기록 시점")
                .replace("{{time}}", escape(report.createdAt()))
                .replace("{{run}}", escape(report.runId()))
                .replace("{{hash}}", escape(report.contentSha256() + " · " + report.archiveState()))
                .replace("{{state}}", escape(report.payload().execution().run().state()))
                .replace("{{environment}}", english ? "Environment" : "환경")
                .replace("{{response}}", english ? "Execution state" : "실행 상태")
                .replace("{{decision}}", english ? "Recorded final decision" : "기록된 최종 결정")
                .replace("{{failure}}", english ? "Technical failure" : "기술 실패")
                .replace("{{note}}", english
                        ? "This snapshot may be incomplete. Sources were read sequentially; later results require a new report. Client receipt values are self-reported. No effectiveness score or independent approval is implied. Opinions are stored separately and do not change this report."
                        : "이 기록은 불완전할 수 있습니다. 원본은 순서대로 조회했으며 이후 도착한 결과는 새 보고서가 필요합니다. 브라우저 수신 값은 클라이언트 보고입니다. 성능 점수나 독립 검증 통과를 뜻하지 않습니다. 의견은 별도로 저장되며 이 보고서를 변경하지 않습니다.")
                .replace("{{reproduce}}", english
                        ? "To compare again, create a new run and recheck the account, sessions, data, model, policy and actual history. This export does not restore authentication, security actions or learning."
                        : "다시 비교하려면 새 실행에서 계정·세션·업무 자료·모델·정책·실제 이력을 확인하세요. 이 파일로 인증·보안 제어·학습 상태를 복원하지 않습니다.")
                .replace("{{original}}", english ? "Original record and limitations" : "원본 기록과 한계")
                .replace("{{rows}}", rows)
                .replace("{{json}}", escape(documents.write(report)));
    }

    private String describeDecision(JsonNode decision, boolean english, String unknown) {
        String description = decision.path("finalAction").asText(unknown);
        if (decision.path("technicalFallback").asBoolean()) {
            description += english ? " (technical fallback)" : " (기술적 대체 처리)";
        } else if (isFalse(decision.path("success")) || isFalse(decision.path("llmDecisionPresent"))) {
            description += english ? " (model response not accepted)" : " (모델 응답 미채택)";
        }
        if (decision.path("failureType").isTextual()) {
            description += " · " + decision.path("failureType").asText();
        }
        return description;
    }

    private boolean isFalse(JsonNode value) {
        return value.isBoolean() && !value.asBoolean();
    }

    private String escape(Object value) {
        return String.valueOf(value).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }
}
