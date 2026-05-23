package dpi.engine;

import dpi.model.AppType;
import dpi.model.FiveTuple;
import dpi.model.Flow;

import java.util.HashMap;
import java.util.Map;

/**
 * Single-threaded flow table used by the simple DPI engine.
 */
public class ConnectionTracker {
    private final Map<FiveTuple, Flow> flows = new HashMap<>();

    public Flow getOrCreate(FiveTuple tuple) {
        return flows.computeIfAbsent(tuple, k -> {
            Flow f = new Flow();
            f.setAppType(AppType.UNKNOWN);
            return f;
        });
    }

    public Map<FiveTuple, Flow> getFlows() {
        return flows;
    }
}