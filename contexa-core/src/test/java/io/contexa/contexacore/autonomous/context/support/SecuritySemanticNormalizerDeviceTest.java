package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** W2-4: the operating system in one vocabulary and the device as one dimension, the browser on the system. */
class SecuritySemanticNormalizerDeviceTest {

    @Test
    void everySystemNameReadsInOneVocabulary() {
        assertThat(SecuritySemanticNormalizer.normalizeOperatingSystem("Windows")).isEqualTo("WINDOWS");
        assertThat(SecuritySemanticNormalizer.normalizeOperatingSystem("Windows 11")).isEqualTo("WINDOWS");
        assertThat(SecuritySemanticNormalizer.normalizeOperatingSystem("macOS")).isEqualTo("MAC");
        assertThat(SecuritySemanticNormalizer.normalizeOperatingSystem("Mac OS X")).isEqualTo("MAC");
        assertThat(SecuritySemanticNormalizer.normalizeOperatingSystem("iPadOS")).isEqualTo("IOS");
        assertThat(SecuritySemanticNormalizer.normalizeOperatingSystem("CrOS")).isEqualTo("CHROMEOS");
        assertThat(SecuritySemanticNormalizer.normalizeOperatingSystem("FreeBSD")).isEqualTo("FREEBSD");
        // A device class or an unknown is no system: the next value is read instead.
        assertThat(SecuritySemanticNormalizer.normalizeOperatingSystem("DESKTOP")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeOperatingSystem("Desktop", "Linux")).isEqualTo("LINUX");
        assertThat(SecuritySemanticNormalizer.normalizeOperatingSystem("unknown", null)).isNull();
    }

    @Test
    void theDeviceIsTheBrowserOnTheSystem() {
        assertThat(SecuritySemanticNormalizer.device("Chrome/140", "Windows")).isEqualTo("Chrome/140 on WINDOWS");
        assertThat(SecuritySemanticNormalizer.device("Chrome/140", null)).isEqualTo("Chrome/140");
        assertThat(SecuritySemanticNormalizer.device(null, "WINDOWS")).isNull();

        List<String> seen = List.of("Chrome/140 on WINDOWS", "Safari/18 on MAC");
        assertThat(SecuritySemanticNormalizer.deviceSeen(seen, "Safari/18 on MAC")).isTrue();
        // Each part seen before, the pair never: a new device.
        assertThat(SecuritySemanticNormalizer.deviceSeen(seen, "Safari/18 on WINDOWS")).isFalse();
        // A device whose system is unknown is held by a device of the same browser.
        assertThat(SecuritySemanticNormalizer.deviceSeen(seen, "Chrome/140")).isTrue();
        assertThat(SecuritySemanticNormalizer.deviceSeen(seen, "Firefox/131")).isFalse();
    }

    @Test
    void theNetworkZoneIsTheHostsWordInOneVocabulary() {
        assertThat(NetworkZone.nameOf("office")).isEqualTo("CORPORATE");
        assertThat(NetworkZone.nameOf("TRAVEL")).isEqualTo("TRAVEL");
        assertThat(NetworkZone.nameOf("business-trip")).isEqualTo("TRAVEL");
        assertThat(NetworkZone.nameOf("external")).isEqualTo("EXTERNAL");
        assertThat(NetworkZone.nameOf("lobby")).isNull();
        assertThat(NetworkZone.nameOf(null)).isNull();
    }
}
