package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacommon.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The metadata the composer writes to: a guarded map of an attempt is kept, any other map that is not ordered is copied. */
class PromptEvidenceComposerMetadataTest {

    /** QF-55: the metadata of an attempt is a guarded map; a step that makes it writable keeps it, with its lock. */
    @Test
    void aGuardedMetadataIsKeptAndNotReplacedByAMapWithoutALock() {
        Map<String, Object> guarded = Collections.synchronizedMap(new LinkedHashMap<>());
        guarded.put("kept", "yes");
        SecurityEvent event = SecurityEvent.builder().metadata(guarded).build();

        Map<String, Object> writable = PromptEvidenceComposer.ensureMutableMetadata(event);

        assertThat(writable).isSameAs(guarded);
        assertThat(event.getMetadata()).isSameAs(guarded);
        assertThat(SecurityEvent.isGuardedMetadata(event.getMetadata())).isTrue();
    }

    @Test
    void anOrderedMapIsKeptAsItWas() {
        Map<String, Object> ordered = new LinkedHashMap<>();
        ordered.put("kept", "yes");
        SecurityEvent event = SecurityEvent.builder().metadata(ordered).build();

        assertThat(PromptEvidenceComposer.ensureMutableMetadata(event)).isSameAs(ordered);
    }

    @Test
    void aMapThatCannotBeWrittenToIsStillReplacedByAWritableCopy() {
        SecurityEvent event = SecurityEvent.builder().metadata(Map.of("kept", "yes")).build();

        Map<String, Object> writable = PromptEvidenceComposer.ensureMutableMetadata(event);
        writable.put("added", "too");

        assertThat(event.getMetadata()).isSameAs(writable).containsEntry("kept", "yes").containsEntry("added", "too");
    }
}
