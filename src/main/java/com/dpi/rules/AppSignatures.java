package com.dpi.rules;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small built-in table mapping a human-friendly app name (as you'd pass
 * to --block-app) to the domain keywords that show up in that app's TLS
 * SNI. This is illustrative, not exhaustive - real DPI deployments keep
 * much larger, regularly-updated signature databases.
 */
public final class AppSignatures {

    private static final Map<String, List<String>> SIGNATURES = new LinkedHashMap<>();

    static {
        SIGNATURES.put("youtube", List.of("youtube.com", "googlevideo.com", "ytimg.com"));
        SIGNATURES.put("netflix", List.of("netflix.com", "nflxvideo.net", "nflximg.net"));
        SIGNATURES.put("tiktok", List.of("tiktok.com", "tiktokcdn.com", "byteoversea.com"));
        SIGNATURES.put("instagram", List.of("instagram.com", "cdninstagram.com"));
        SIGNATURES.put("facebook", List.of("facebook.com", "fbcdn.net"));
        SIGNATURES.put("twitter", List.of("twitter.com", "x.com", "twimg.com"));
        SIGNATURES.put("whatsapp", List.of("whatsapp.com", "whatsapp.net"));
        SIGNATURES.put("spotify", List.of("spotify.com", "scdn.co"));
        SIGNATURES.put("twitch", List.of("twitch.tv", "ttvnw.net"));
        SIGNATURES.put("primevideo", List.of("primevideo.com", "aiv-cdn.net"));
        SIGNATURES.put("disneyplus", List.of("disneyplus.com", "bamgrid.com"));
        SIGNATURES.put("steam", List.of("steampowered.com", "steamcontent.com"));
    }

    private AppSignatures() {
    }

    /**
     * Returns the domain keywords for a named app, or an empty list if the
     * name is not one of the built-ins (in which case the caller may still
     * treat the raw name itself as a domain keyword).
     */
    public static List<String> keywordsFor(String appName) {
        return SIGNATURES.getOrDefault(appName.toLowerCase(), List.of());
    }

    public static boolean isKnownApp(String appName) {
        return SIGNATURES.containsKey(appName.toLowerCase());
    }
}
