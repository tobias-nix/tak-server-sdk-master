package tak.server.plugins;

import java.lang.invoke.MethodHandles;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;

/**
 * Plugin that forwards messages it receives, appending a message count to them in their xml detail.
 */
@TakServerPlugin(name="Message Forwarder Plugin", description="This plugin will forward messages it receives")
public class MessageForwarderPlugin extends MessageSenderReceiverBase {

	// This plugin does scheduled work below, using this worker pool
	private static final ScheduledExecutorService worker = Executors.newScheduledThreadPool(1);
	private ScheduledFuture<?> future;

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	private Set<String> inputGroups = null;
	private Set<String> outputGroups = null;

	private final ArrayBlockingQueue<Message> messageQueue;
	private int messageCount = 0;

	@SuppressWarnings("unchecked")
	public MessageForwarderPlugin() {

		if (config.containsProperty("inputGroups")) {
			inputGroups = new HashSet<>((List<String>) config.getProperty("inputGroups"));
		}

		if (config.containsProperty("outputGroups")) {
		    outputGroups = new HashSet<>((List<String>) config.getProperty("outputGroups"));
		}

		int queueSize = 1000;
		if (config.containsProperty("queueSize")) {
		    queueSize = (int) config.getProperty("queueSize");
		}

		messageQueue = new ArrayBlockingQueue<>(queueSize);

		logger.info("Properties: {}", config.getProperties());
	}

	/**
	 * Starts the plugin. Retrieve messages from a local queue and processes them, and sends them back out. If there are no
	 * messages being received,the plugin will wait until there are or until it is stopped.
	 */
	@Override
	public void start() {

		logger.info("Starting {}", getClass().getName());

        try {
            future = worker.scheduleWithFixedDelay(() -> {
                try {
                    logger.info("Plugin scheduler has received {} messages so far and is waiting for new messages... ", messageCount);
                    Message incomingMessage = messageQueue.take(); // blocks on waiting for a message

                    logger.info("Got message #{} from queue", messageCount);
                    Message message = generateMessage(incomingMessage);
                    send(message);
					logger.info("Message sent from plugin to TAK server: {}", message);

                } catch (InterruptedException e) {
                    logger.error("Plugin has been interrupted while waiting for a message ", e);
                }
            }, 0, 10, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            logger.error("error initializing periodic data sender ", e);
        }

	}

	/**
	 * Takes a message and adds the current message count of the plugin and provenance to prevent looping.
	 *
	 * @param incomingMessage the received message to be processed.
	 * @return The processed message with appended message count and provenance
	 */
	protected Message generateMessage(Message incomingMessage) {
		messageCount += 1;
		Message.Builder messageBuilder = incomingMessage.toBuilder();

		if (outputGroups != null) {
			messageBuilder.clearGroups();
			outputGroups.forEach(messageBuilder::addGroups);
		}

		String xmlDetail = messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().getXmlDetail();
		xmlDetail += "<messageCount>" + messageCount + "</messageCount>";
		messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().clearXmlDetail();
		messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().setXmlDetail(xmlDetail);
		messageBuilder.addProvenance(MessageForwarderPlugin.class.getName()); //Adding provenance to prevent looping

		return messageBuilder.build();
	}

	/**
	 * Receives messages and adds them to a queue. Checks the provenance to make sure that the message didn't originate
	 * from the plugin itself.
	 *
	 * @param message the message received by the plugin
	 */
	@Override
	public void onMessage(Message message) {

		logger.info("Message received from TAK server: {}", message);

		// Provenance is checked to prevent looping
		if (!message.toBuilder().getProvenanceList().contains(MessageForwarderPlugin.class.getName())) {
			boolean hasInputGroup = false;
			if (inputGroups != null) {
				for (String group : inputGroups) {
					if (inputGroups.contains(group)) {
						hasInputGroup = true;
						break;
					}
				}
			}
			if (inputGroups == null || hasInputGroup) {
				logger.info("Put message in queue...");
				messageQueue.offer(message);
			}
		}
	}

	/**
	 * Stops the plugin and cancels future tasks.
	 */
	@Override
	public void stop() {
	    if (future != null) {
	        future.cancel(true);
	    }
	}

}
