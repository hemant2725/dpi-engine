package dpi.model;

/**
 * Mutable per-flow state used by the DPI pipeline.
 */
public class Flow {
    private AppType appType = AppType.UNKNOWN;
    private long packetCount;
    private long byteCount;
    private String sni;
    private boolean blocked;

    public AppType getAppType() {
        return appType;
    }

    public void setAppType(AppType appType) {
        this.appType = appType;
    }

    public long getPacketCount() {
        return packetCount;
    }

    public void incrementPacketCount() {
        this.packetCount++;
    }

    public long getByteCount() {
        return byteCount;
    }

    public void addByteCount(long bytes) {
        this.byteCount += bytes;
    }

    public String getSni() {
        return sni;
    }

    public void setSni(String sni) {
        this.sni = sni;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }
}
