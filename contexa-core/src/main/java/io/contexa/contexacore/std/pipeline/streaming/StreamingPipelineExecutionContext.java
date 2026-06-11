/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.pipeline.streaming;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import lombok.Getter;
import lombok.Setter;
import reactor.core.publisher.Sinks;

@Getter
@Setter
public class StreamingPipelineExecutionContext extends PipelineExecutionContext
        implements StreamingPipelineContext {

    private boolean streamingMode = false;
    private Sinks.Many<String> streamSink;

    public StreamingPipelineExecutionContext(String requestId) {
        super(requestId);
    }

    @Override
    public void enableStreamingMode() {
        this.streamingMode = true;
    }

    @Override
    public boolean isStreamingMode() {
        return streamingMode;
    }

    @Override
    public void setStreamSink(Sinks.Many<String> sink) {
        this.streamSink = sink;
    }

    @Override
    public Sinks.Many<String> getStreamSink() {
        return streamSink;
    }
}
