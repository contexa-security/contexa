package io.contexa.contexacore.std.pipeline.streaming;

import reactor.core.publisher.Flux;

/**
 * Interface for processing streaming chunks.
 * Implementations transform raw streaming data into processed output.
 */
public interface ChunkProcessor {

    /**
     * Processes the upstream flux of chunks.
     *
     * @param upstream the source flux of raw chunks
     * @return processed flux of chunks
     */
    Flux<String> process(Flux<String> upstream);

    /**
     * Returns the processor type identifier.
     *
     * @return the processor type string
     */
    String getProcessorType();
}
