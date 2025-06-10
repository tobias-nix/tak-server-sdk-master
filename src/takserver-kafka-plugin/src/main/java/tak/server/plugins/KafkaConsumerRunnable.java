package tak.server.plugins;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.errors.WakeupException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

public class KafkaConsumerRunnable implements Runnable
{
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final KafkaConsumer<String, String> consumer;
    private final String topic;
    private final Consumer<ConsumerRecord<String, String>> onMsgCallback;
    private final Duration TIMEOUT = Duration.ofMillis(5000);

    public KafkaConsumerRunnable(KafkaConsumer<String, String> consumer, String topic,
                           Consumer<ConsumerRecord<String, String>> onMsgCallback) {
        this.consumer = consumer;
        this.topic = topic;
        this.onMsgCallback = onMsgCallback;
    }

    @Override
    public void run() {
        try {
            consumer.subscribe(Arrays.asList(topic));
            while (!closed.get()) {
                ConsumerRecords<String, String> records = consumer.poll(TIMEOUT);
                for (ConsumerRecord<String, String> record : records) {
                    onMsgCallback.accept(record);
                }
            }
        }
        catch (WakeupException e) {
            if (!closed.get()) throw e;
        }
        finally {
            consumer.close();
        }
    }

    public void stop() {
        closed.set(true);
        consumer.wakeup();
    }
}
