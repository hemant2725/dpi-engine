package dpi.model;

/**
 * Enumeration of supported application types for traffic classification.
 */
public enum AppType {
    UNKNOWN, HTTP, HTTPS, DNS,
    YOUTUBE, FACEBOOK, GOOGLE, TWITTER,
    NETFLIX, TIKTOK, GITHUB, AMAZON;

    @Override
    public String toString() {
        return switch (this) {
            case YOUTUBE -> "YouTube";
            case FACEBOOK -> "Facebook";
            case GOOGLE -> "Google";
            case TWITTER -> "Twitter";
            case NETFLIX -> "Netflix";
            case TIKTOK -> "TikTok";
            case GITHUB -> "GitHub";
            case AMAZON -> "Amazon";
            default -> name();
        };
    }
}