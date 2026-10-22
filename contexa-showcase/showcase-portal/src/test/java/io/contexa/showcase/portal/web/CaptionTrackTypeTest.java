package io.contexa.showcase.portal.web;

import org.junit.jupiter.api.Test;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The guide videos (가이드영상-계획.md): the caption tracks go out as text/vtt, and the container's other types stay
 * (the video's webm among them).
 */
class CaptionTrackTypeTest {

    @Test
    void captionTracksAreServedAsWebVttAndTheDefaultTypesStay() {
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
        SinglePageApplicationConfiguration.captionTrackType().customize(factory);
        assertThat(factory.getMimeMappings().get("vtt")).isEqualTo("text/vtt");
        assertThat(factory.getMimeMappings().get("webm")).isEqualTo("video/webm");
        assertThat(factory.getMimeMappings().get("json")).isEqualTo("application/json");
    }
}
