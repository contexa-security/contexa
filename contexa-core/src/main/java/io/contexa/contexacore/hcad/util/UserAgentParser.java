package io.contexa.contexacore.hcad.util;

public final class UserAgentParser {

    private static final String[] BROWSER_KEYWORDS = {
        "Edg/",      
        "Chrome/",   
        "Firefox/",  
        "Safari/",   
        "Opera/",    
        "MSIE ",     
        "Trident/"   
    };

    private static final String[] OS_KEYWORDS = {
        "Android",      
        "iPhone",       
        "iPad",         
        "iPod",         
        "iOS",          
        "Windows",      
        "Macintosh",    
        "Mac OS",       
        "CrOS",         
        "Linux"         
    };

    private static final String[][] OS_NORMALIZE_MAP = {
        {"Android", "Android"},
        {"iPhone", "iOS"},
        {"iPad", "iOS"},
        {"iPod", "iOS"},
        {"iOS", "iOS"},
        {"Windows", "Windows"},
        {"Macintosh", "Mac"},
        {"Mac OS", "Mac"},
        {"CrOS", "ChromeOS"},
        {"Linux", "Linux"}
    };

    private UserAgentParser() {
        
    }

    public static String extractSignature(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Browser (Desktop)";
        }

        String browser = extractBrowser(userAgent);
        String os = extractOS(userAgent);

        return browser + " (" + os + ")";
    }

    public static String extractBrowser(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Browser";
        }

        if (userAgent.contains("Edg/")) {
            String version = extractMajorVersion(userAgent, "Edg/");
            return "Edge/" + version;
        }

        if (userAgent.contains("Chrome/") && !userAgent.contains("Edg/")) {
            String version = extractMajorVersion(userAgent, "Chrome/");
            return "Chrome/" + version;
        }

        if (userAgent.contains("Firefox/")) {
            String version = extractMajorVersion(userAgent, "Firefox/");
            return "Firefox/" + version;
        }

        if (userAgent.contains("Safari/") && !userAgent.contains("Chrome") && !userAgent.contains("Edg")) {
            String version = extractMajorVersion(userAgent, "Version/");
            return "Safari/" + version;
        }

        if (userAgent.contains("Opera/") || userAgent.contains("OPR/")) {
            String prefix = userAgent.contains("OPR/") ? "OPR/" : "Opera/";
            String version = extractMajorVersion(userAgent, prefix);
            return "Opera/" + version;
        }

        if (userAgent.contains("MSIE ") || userAgent.contains("Trident/")) {
            return "IE/11";  
        }

        return "Browser";
    }

    public static String extractOS(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Desktop";
        }

        if (userAgent.contains("Android")) {
            return "Android";
        }
        if (userAgent.contains("iPhone") || userAgent.contains("iPad")
                || userAgent.contains("iPod") || userAgent.contains("iOS")) {
            return "iOS";
        }

        if (userAgent.contains("Windows")) {
            return "Windows";
        }
        if (userAgent.contains("Macintosh") || userAgent.contains("Mac OS")) {
            return "Mac";
        }
        if (userAgent.contains("CrOS")) {
            return "ChromeOS";
        }
        if (userAgent.contains("Linux")) {
            return "Linux";
        }

        if (userAgent.contains("Mobile") || userAgent.contains("Tablet")) {
            return "Mobile";
        }

        return "Desktop";
    }

    public static boolean isSimilar(String ua1, String ua2) {
        if (ua1 == null || ua2 == null) {
            return false;
        }

        String browser1 = extractBrowserName(ua1);
        String browser2 = extractBrowserName(ua2);

        if (browser1 == null || browser2 == null) {
            return false;
        }
        if (!browser1.equals(browser2)) {
            return false;  
        }

        String os1 = extractOS(ua1);
        String os2 = extractOS(ua2);

        if (!os1.equals(os2)) {
            return false;
        }

        return true;
    }

    public static String extractBrowserFromSignature(String signature) {
        if (signature == null) {
            return null;
        }
        int spaceIdx = signature.indexOf(" ");
        if (spaceIdx > 0) {
            return signature.substring(0, spaceIdx);
        }
        return signature;
    }

    public static String extractOSFromSignature(String signature) {
        if (signature == null) {
            return null;
        }
        int openParen = signature.indexOf("(");
        int closeParen = signature.indexOf(")");
        if (openParen > 0 && closeParen > openParen) {
            return signature.substring(openParen + 1, closeParen);
        }
        return null;
    }

    public static String extractBrowserName(String userAgent) {
        if (userAgent == null) {
            return null;
        }

        if (userAgent.contains("(") && userAgent.contains(")")) {
            String browser = extractBrowserFromSignature(userAgent);
            if (browser != null && browser.contains("/")) {
                return browser.split("/")[0];
            }
            return browser;
        }

        for (String keyword : new String[]{"Edge", "Edg", "Chrome", "Firefox", "Safari", "Opera", "MSIE", "Trident"}) {
            if (userAgent.contains(keyword)) {
                
                if (keyword.equals("Edg")) {
                    return "Edge";
                }
                
                if (keyword.equals("Trident")) {
                    return "IE";
                }
                return keyword;
            }
        }

        return null;
    }

    private static String extractMajorVersion(String userAgent, String prefix) {
        int idx = userAgent.indexOf(prefix);
        if (idx == -1) {
            return "0";
        }

        int start = idx + prefix.length();
        if (start >= userAgent.length()) {
            return "0";
        }

        int end = start;
        while (end < userAgent.length()) {
            char c = userAgent.charAt(end);
            if (c == '.' || c == ' ' || !Character.isDigit(c)) {
                break;
            }
            end++;
        }

        if (end == start) {
            return "0";
        }

        return userAgent.substring(start, end);
    }
}
