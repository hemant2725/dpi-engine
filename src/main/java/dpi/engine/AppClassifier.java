package dpi.engine;

import dpi.model.AppType;

/**
 * Maps extracted host/SNI strings to application types.
 */
public class AppClassifier {
    public static AppType classify(String hostOrSni, int dstPort) {
        if (hostOrSni != null && !hostOrSni.isEmpty()) {
            String h = hostOrSni.toLowerCase();
            if (h.contains("youtube") || h.contains("ytimg") || h.contains("googlevideo")) return AppType.YOUTUBE;
            if (h.contains("facebook") || h.contains("fbcdn") || h.contains("instagram")) return AppType.FACEBOOK;
            if (h.contains("google") || h.contains("googleapis") || h.contains("gstatic")) return AppType.GOOGLE;
            if (h.contains("twitter") || h.contains("twimg")) return AppType.TWITTER;
            if (h.contains("netflix") || h.contains("nflxvideo")) return AppType.NETFLIX;
            if (h.contains("tiktok") || h.contains("tiktokcdn")) return AppType.TIKTOK;
            if (h.contains("github")) return AppType.GITHUB;
            if (h.contains("amazon") || h.contains("amazonaws")) return AppType.AMAZON;
        }
        if (dstPort == 443) return AppType.HTTPS;
        if (dstPort == 80) return AppType.HTTP;
        if (dstPort == 53) return AppType.DNS;
        return AppType.UNKNOWN;
    }
}