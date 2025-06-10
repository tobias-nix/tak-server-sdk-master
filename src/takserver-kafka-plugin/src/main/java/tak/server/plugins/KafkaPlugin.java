package tak.server.plugins;

import atakmap.commoncommo.protobuf.v1.Takmessage.TakMessage;
import atakmap.commoncommo.protobuf.v1.MessageOuterClass;
import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import tak.server.cot.CotEventContainer;
import tak.server.proto.StreamingProtoBufHelper;


@TakServerPlugin(name = "TAK Server Kafka Plugin", description = "")
@SuppressWarnings("unused")
public class KafkaPlugin extends MessageSenderReceiverBase {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private String kafkaHost;
    private String kafkaConsumerTopic;
    private String kafkaProducerTopic;
    private Set<String> groups;

    private ExecutorService executor = Executors.newFixedThreadPool(1);
    private KafkaConsumerRunnable kafkaConsumer;
    private KafkaProducer<String, String> kafkaProducer;

    @SuppressWarnings("unchecked")
    public KafkaPlugin() {
        if (config.containsProperty("kafkaHost")) {
            kafkaHost = (String)config.getProperty("kafkaHost");
        }

        if (config.containsProperty("kafkaConsumerTopic")) {
            kafkaConsumerTopic = (String)config.getProperty("kafkaConsumerTopic");
        }

        if (config.containsProperty("kafkaProducerTopic")) {
            kafkaProducerTopic = (String)config.getProperty("kafkaProducerTopic");
        }

        if (config.containsProperty("groups")) {
            groups = new HashSet<String>((List<String>) config.getProperty("groups"));
        }

        logger.info("kafkaHost: {}", kafkaHost);
        logger.info("kafkaConsumerTopic: {}", kafkaConsumerTopic);
        logger.info("kafkaProducerTopic: {}", kafkaProducerTopic);
    }

    @Override
    public void onMessage(Message message) {
        CotEventContainer cotEventContainer = StreamingProtoBufHelper.proto2cot(message.getPayload());
        String cotXml = cotEventContainer.asXml();

        logger.info("Plugin message received: " + cotXml);

        ProducerRecord<String, String> producerRecord = new ProducerRecord<>(kafkaProducerTopic, cotXml);
        kafkaProducer.send(producerRecord);
        kafkaProducer.flush();
    }

    private void onKafkaMessage(ConsumerRecord<String, String> record) {
        try {
            String cot = record.value();
            logger.info("onMessage received {}", cot);
            final Message message = getConverter().cotStringToDataMessage(cot, groups,
                    Integer.toString(System.identityHashCode(this)));
            send(message);
        } catch (Exception e) {
            logger.error("exception in onMessage", e);
        }
    }

    @Override
    public void start() {

        Properties props = new Properties();
        props.setProperty("bootstrap.servers", kafkaHost);
        props.setProperty("group.id", "kafka-tak-plugin");
        props.setProperty("enable.auto.commit", "true");
        props.setProperty("auto.commit.interval.ms", "1000");

        Thread.currentThread().setContextClassLoader(null);
        props.setProperty("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        props.setProperty("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");

        props.setProperty("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.setProperty("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");


        kafkaConsumer = new KafkaConsumerRunnable(new KafkaConsumer<String, String>(props), kafkaConsumerTopic, this::onKafkaMessage);
        executor.execute(kafkaConsumer);

        kafkaProducer = new KafkaProducer<String, String>(props);
    }

    @Override
    public void stop() {
        kafkaConsumer.stop();
        executor.shutdown();

        kafkaProducer.close();
    }
}