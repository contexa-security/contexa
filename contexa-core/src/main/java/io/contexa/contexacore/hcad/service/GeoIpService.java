package io.contexa.contexacore.hcad.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.model.CityResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.concurrent.TimeUnit;

/**
 * GeoIP lookup service with Caffeine cache for performance.
 * Uses MaxMind GeoLite2-City database in memory-mapped mode.
 * Gracefully degrades when database file is unavailable.
 */
@Slf4j
public class GeoIpService implements Closeable {

    private final DatabaseReader reader;

    private final Cache<String, GeoLocation> cache = Caffeine.newBuilder()
            .maximumSize(10_000)
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();

    private static final GeoLocation UNKNOWN = new GeoLocation(null, null, null, null);

    public GeoIpService(String dbPath) {
        DatabaseReader r = null;
        if (dbPath != null) {
            File dbFile = new File(dbPath);
            if (dbFile.exists() && dbFile.isFile()) {
                try {
                    r = new DatabaseReader.Builder(dbFile)
                            .fileMode(com.maxmind.db.Reader.FileMode.MEMORY_MAPPED)
                            .build();
                    log.error("[GeoIpService] GeoLite2 database loaded: {}", dbPath);
                } catch (IOException e) {
                    log.error("[GeoIpService] Failed to load GeoLite2 database: {}", dbPath, e);
                }
            } else {
                log.error("[GeoIpService] GeoLite2 database not found at: {}. GeoIP disabled.", dbPath);
            }
        } else {
            log.error("[GeoIpService] No GeoLite2 database path configured. GeoIP disabled.");
        }
        this.reader = r;
    }

    /**
     * Lookup geographic location for an IP address.
     * Returns cached result if available. Returns UNKNOWN for private/loopback IPs.
     */
    public GeoLocation lookup(String ip) {
        if (ip == null || ip.isBlank() || reader == null) {
            return UNKNOWN;
        }

        if (isPrivateOrLoopback(ip)) {
            return UNKNOWN;
        }

        return cache.get(ip, this::doLookup);
    }

    private GeoLocation doLookup(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            CityResponse response = reader.city(addr);

            String country = response.getCountry() != null ? response.getCountry().getName() : null;
            String city = response.getCity() != null ? response.getCity().getName() : null;
            Double lat = response.getLocation() != null ? response.getLocation().getLatitude() : null;
            Double lon = response.getLocation() != null ? response.getLocation().getLongitude() : null;

            return new GeoLocation(country, city, lat, lon);
        } catch (AddressNotFoundException e) {
            return UNKNOWN;
        } catch (Exception e) {
            log.error("[GeoIpService] GeoIP lookup failed: ip={}", ip, e);
            return UNKNOWN;
        }
    }

    private static boolean isPrivateOrLoopback(String ip) {
        if (ip.startsWith("127.") || "::1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip)) {
            return true;
        }
        if (ip.startsWith("10.") || ip.startsWith("192.168.")) {
            return true;
        }
        if (ip.startsWith("172.")) {
            try {
                int second = Integer.parseInt(ip.split("\\.")[1]);
                return second >= 16 && second <= 31;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return false;
    }

    /**
     * Calculate distance in kilometers between two coordinates using Haversine formula.
     */
    public static double distanceKm(double lat1, double lon1, double lat2, double lon2) {
        double earthRadius = 6371.0;
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(dLon / 2) * Math.sin(dLon / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return earthRadius * c;
    }

    /**
     * Check if travel between two locations is physically impossible given elapsed time.
     * Threshold: 1000 km/h (faster than any commercial flight).
     */
    public static boolean isImpossibleTravel(double distanceKm, long elapsedMs) {
        if (elapsedMs <= 0 || distanceKm <= 100) {
            return false;
        }
        double elapsedHours = elapsedMs / 3_600_000.0;
        double speedKmh = distanceKm / elapsedHours;
        return speedKmh > 1000.0;
    }

    @Override
    public void close() {
        if (reader != null) {
            try {
                reader.close();
            } catch (IOException e) {
                log.error("[GeoIpService] Failed to close GeoIP database", e);
            }
        }
    }

    /**
     * Geographic location result.
     */
    public record GeoLocation(String country, String city, Double latitude, Double longitude) {
        public boolean isKnown() {
            return country != null || city != null;
        }

        public boolean hasCoordinates() {
            return latitude != null && longitude != null;
        }
    }
}
