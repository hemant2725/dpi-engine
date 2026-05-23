package dpi.engine;

import dpi.model.ParsedPacket;

/**
 * Load-balancer thread: routes parsed packets to FastPath queues
 * using consistent hashing on the 5-tuple.
 */
public class LoadBalancer implements Runnable {
    private final ThreadSafeQueue<ParsedPacket> inputQueue;
    private final ThreadSafeQueue<ParsedPacket>[] outputQueues;
    private final int fpsPerLb;

    public LoadBalancer(ThreadSafeQueue<ParsedPacket> inputQueue,
                        ThreadSafeQueue<ParsedPacket>[] outputQueues,
                        int fpsPerLb) {
        this.inputQueue = inputQueue;
        this.outputQueues = outputQueues;
        this.fpsPerLb = fpsPerLb;
    }

    @Override
    public void run() {
        try {
            while (true) {
                ParsedPacket p = inputQueue.take();
                if (p == null || p.rawData() == null) { // poison pill
                    for (int i = 0; i < fpsPerLb; i++) {
                        outputQueues[i].put(p);
                    }
                    break;
                }
                // Non-IP packets route to FP 0
                if (p.fiveTuple() == null) {
                    outputQueues[0].put(p);
                    continue;
                }
                int hash = p.fiveTuple().hashCode();
                int idx = Math.floorMod(hash, fpsPerLb);
                outputQueues[idx].put(p);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
