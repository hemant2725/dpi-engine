package dpi.engine;

import dpi.model.AppType;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Holds blocking rules by IP, application type, and domain substring.
 */
public class RuleManager {
    private final Set<Integer> blockedIps = new HashSet<>();
    private final Set<AppType> blockedApps = new HashSet<>();
    private final List<String> blockedDomains;

    public RuleManager(List<String> blockedDomains) {
        this.blockedDomains = blockedDomains != null ? blockedDomains : List.of();
    }

    public void blockIp(String ip) {
        blockedIps.add(ipToInt(ip));
    }

    public void blockApp(AppType app) {
        blockedApps.add(app);
    }

    /**
     * Evaluates all rule types against a flow.
     */
    public boolean isBlocked(int srcIp, AppType appType, String sni) {
        if (blockedIps.contains(srcIp)) return true;
        if (appType != null && blockedApps.contains(appType)) return true;
        if (sni != null && !sni.isEmpty()) {
            String lower = sni.toLowerCase();
            for (String d : blockedDomains) {
                if (lower.contains(d.toLowerCase())) return true;
            }
        }
        return false;
    }

    public boolean isAppBlocked(AppType app) {
        return blockedApps.contains(app);
    }

    private static int ipToInt(String ip) {
        String[] parts = ip.split("\\.");
        int addr = 0;
        for (int i = 0; i < 4; i++) {
            addr = (addr << 8) | (Integer.parseInt(parts[i]) & 0xFF);
        }
        return addr;
    }
}
