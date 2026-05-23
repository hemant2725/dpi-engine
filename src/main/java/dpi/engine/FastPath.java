package dpi.engine;

import dpi.inspector.HttpHostExtractor;
import dpi.inspector.SniExtractor;
import dpi.model.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * FastPath worker: owns a private flow table (no locks).
 * Parses, classifies, applies rules, and forwards allowed packets.
 */
public class FastPath implements Runnable {
    private final ThreadSafeQueue<ParsedPacket> inputQueue;
    private final ThreadSafeQueue<RawPacket> outputQueue;
    private final RuleManager ruleManager;
    private final int id;
    private final Map<FiveTuple, Flow> flowTable = new HashMap<>();
    private final AtomicLong globalForwarded;
    private final AtomicLong globalDropped;

    public FastPath(ThreadSafeQueue<ParsedPacket> inputQueue,
                    ThreadSafeQueue<RawPacket> outputQueue,
                    RuleManager ruleManager,
                    int id,
                    AtomicLong globalForwarded,
                    AtomicLong globalDropped) {
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
        this.ruleManager = ruleManager;
        this.id = id;
        this.globalForwarded = globalForwarded;
        this.globalDropped = globalDropped;
    }

    @Override
    public void run() {
        try {
            while (true) {
                ParsedPacket p = inputQueue.take();
                if (p == null || p.rawData() == null) { // poison
                    outputQueue.put(new RawPacket(null, 0, 0));
                    break;
                }
                process(p);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void process(ParsedPacket packet) throws InterruptedException {
        // Non-IP bypass
        if (packet.fiveTuple() == null) {
            outputQueue.put(packet.toRawPacket());
            globalForwarded.incrementAndGet();
            return;
        }

        FiveTuple tuple = packet.fiveTuple();
        Flow flow = flowTable.computeIfAbsent(tuple, k -> {
            Flow f = new Flow();
            f.setAppType(AppType.UNKNOWN);
            return f;
        });

        flow.incrementPacketCount();
        flow.addByteCount(packet.rawData().length);

        String host = null;
        if (packet.hasPayload()) {
            int dstPort = tuple.dstPort() & 0xFFFF;
            Optional<String> sni = SniExtractor.extract(packet.rawData(), packet.payloadOffset(), packet.payloadLength(), dstPort);
            if (sni.isPresent()) {
                host = sni.get();
                flow.setSni(host);
            } else {
                Optional<String> h = HttpHostExtractor.extract(packet.rawData(), packet.payloadOffset(), packet.payloadLength());
                if (h.isPresent()) {
                    host = h.get();
                    flow.setSni(host);
                }
            }
        }

        int dstPort = tuple.dstPort() & 0xFFFF;
        AppType app = AppClassifier.classify(host, dstPort);
        if (flow.getAppType() == AppType.UNKNOWN || flow.getAppType() == AppType.HTTP || flow.getAppType() == AppType.HTTPS) {
            flow.setAppType(app);
        }

        boolean blocked = ruleManager.isBlocked(tuple.srcIp(), flow.getAppType(), flow.getSni());
        if (blocked) {
            flow.setBlocked(true);
            globalDropped.incrementAndGet();
        } else {
            outputQueue.put(packet.toRawPacket());
            globalForwarded.incrementAndGet();
        }
    }

    public Map<FiveTuple, Flow> getFlowTable() {
        return flowTable;
    }
}
