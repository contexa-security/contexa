package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;

import java.util.Map;

@Controller
@RequestMapping("/admin/custom-llm")
@RequiredArgsConstructor
public class CustomLLMController {

    private final AICoreOperations<StudioQueryContext> aiProcessor;
    private final StandardStreamingService streamingService;

    @GetMapping
    public String customLLMPage(Model model) {
        model.addAttribute("activePage", "custom-llm");
        return "admin/custom-llm";
    }

    @PostMapping(value = "/api/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @ResponseBody
    public Flux<ServerSentEvent<String>> streamLLM(@RequestBody Map<String, String> request) {
        String query = request.get("query");

        if (query == null || query.trim().isEmpty()) {
            return streamingService.errorStream("VALIDATION_ERROR", "Query is required");
        }

        AIRequest<StudioQueryContext> aiRequest = createStreamingRequest(query);
        return streamingService.stream(aiRequest, aiProcessor);
    }

    private AIRequest<StudioQueryContext> createStreamingRequest(String query) {
        StudioQueryContext context = new StudioQueryContext.Builder().build();
        AIRequest<StudioQueryContext> request = new AIRequest<>(context, new TemplateType("CustomLLMStream"), new DiagnosisType("CustomLLMStream"));
        request.setNaturalLanguageQuery(query);
        return request;
    }
}
