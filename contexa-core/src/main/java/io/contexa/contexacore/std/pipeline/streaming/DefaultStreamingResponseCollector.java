package io.contexa.contexacore.std.pipeline.streaming;

import java.util.concurrent.ConcurrentLinkedQueue;

public class DefaultStreamingResponseCollector implements StreamingResponseCollector {

    private final ConcurrentLinkedQueue<String> chunks = new ConcurrentLinkedQueue<>();
    private final StringBuilder fullResponse = new StringBuilder();
    private boolean complete = false;

    @Override
    public void collect(String chunk) {
        if (chunk != null && !complete) {
            chunks.add(chunk);
            fullResponse.append(chunk);
        }
    }

    @Override
    public String getFullResponse() {
        return fullResponse.toString();
    }

    @Override
    public void reset() {
        chunks.clear();
        fullResponse.setLength(0);
        complete = false;
    }

    @Override
    public boolean isComplete() {
        return complete;
    }

    public void markComplete() {
        this.complete = true;
    }
}