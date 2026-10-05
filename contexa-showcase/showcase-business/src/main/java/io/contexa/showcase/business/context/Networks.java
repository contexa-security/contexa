package io.contexa.showcase.business.context;

/** IPv4 network membership for the company's network facts (office and travel networks are IPv4 CIDR blocks). */
public final class Networks {

    private Networks() {
    }

    /** Whether the address lies in the CIDR block; false for anything that is not a valid IPv4 address or block. */
    public static boolean contains(String cidr, String address) {
        if (cidr == null || address == null) {
            return false;
        }
        int slash = cidr.indexOf('/');
        if (slash < 0) {
            return false;
        }
        Long network = toLong(cidr.substring(0, slash));
        Long host = toLong(address);
        int prefix;
        try {
            prefix = Integer.parseInt(cidr.substring(slash + 1));
        } catch (NumberFormatException e) {
            return false;
        }
        if (network == null || host == null || prefix < 0 || prefix > 32) {
            return false;
        }
        long mask = prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return (network & mask) == (host & mask);
    }

    private static Long toLong(String address) {
        String[] parts = address.trim().split("\\.");
        if (parts.length != 4) {
            return null;
        }
        long value = 0;
        for (String part : parts) {
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                return null;
            }
            if (octet < 0 || octet > 255) {
                return null;
            }
            value = (value << 8) | octet;
        }
        return value;
    }
}
