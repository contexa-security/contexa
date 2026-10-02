package io.contexa.demo.comparison.manifest.options.source;

import io.contexa.demo.comparison.manifest.options.dto.ChatOptionsSnapshot;
import org.springframework.ai.chat.prompt.ChatOptions;

public interface ChatOptionsSnapshotQuery {

    boolean supports(ChatOptions options);

    ChatOptionsSnapshot capture(ChatOptions options);
}
