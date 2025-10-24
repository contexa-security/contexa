package io.contexa.contexacore.std.llm.dynamic;

import lombok.RequiredArgsConstructor;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AIController {

    private final AIModelManager aiModelManager;

    @PostMapping("/ai/chat")
    public ResponseEntity<?> chat(
            @RequestParam(required = false) String model,
            @RequestParam(required = false) String taskType,
            @RequestBody String prompt) {

        try {
            ChatResponse response;

            if (model != null) {
                // 특정 모델 지정
                response = aiModelManager.chat(
                        AIModelManager.AIModelType.valueOf(model.toUpperCase()),
                        prompt
                );
            } else if (taskType != null) {
                // 작업 유형에 따라 자동 선택
                response = aiModelManager.chatWithBestModel(
                        AIModelManager.TaskType.valueOf(taskType.toUpperCase()),
                        prompt
                );
            } else {
                // 가장 빠른 모델 사용
                response = aiModelManager.chatWithFastest(prompt);
            }

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(e.getMessage());
        }
    }
}
