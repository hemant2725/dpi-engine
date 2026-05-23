package dpi.engine;

import java.util.concurrent.LinkedBlockingQueue;

/**
 * Generic bounded blocking queue wrapper (capacity 10,000).
 */
public class ThreadSafeQueue<T> {
    public static final int CAPACITY = 10000;
    private final LinkedBlockingQueue<T> queue = new LinkedBlockingQueue<>(CAPACITY);

    public void put(T item) throws InterruptedException {
        queue.put(item);
    }

    public T take() throws InterruptedException {
        return queue.take();
    }

    public int size() {
        return queue.size();
    }
}