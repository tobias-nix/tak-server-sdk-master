package tak.server.plugins;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Intercepts messages and adds a counter to its xml detail
 */
@TakServerPlugin(name="Message Interceptor Counter Plugin", description="This plugin will intercept messages, and mark them with an atomic counter of messages intercepted")
public class MessageInterceptorCounterPlugin extends MessageInterceptorBase {

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	private Set<String> inputGroups = null;
	private Set<String> outputGroups = null;
	
	private final AtomicInteger testCounter = new AtomicInteger();

	@SuppressWarnings("unchecked")
	public MessageInterceptorCounterPlugin() {

		if (config.containsProperty("inputGroups")) {
			inputGroups = new HashSet<>((List<String>) config.getProperty("inputGroups"));
		}
		if (config.containsProperty("outputGroups")) {
		    outputGroups = new HashSet<>((List<String>) config.getProperty("outputGroups"));
		}

		logger.info("Properties: {}", config.getProperties());
	}

	@Override
	public void start() {

		logger.info("Starting {}", getClass().getName());

	}

	/**
	 * Intercepts a message and adds a counter to the xml detail
	 *
	 * @param message the intercepted message to be modified
	 * @return the intercepted message with counter appended to its xml detail
	 */
	@Override
	public Message intercept(Message message) {

		testCounter.incrementAndGet();

		if (logger.isDebugEnabled()) {
			logger.debug("Got message #{} from queue", testCounter.get());
		}
		Message.Builder mb = message.toBuilder();

		String xmlDetail = mb.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().getXmlDetail();
		xmlDetail += "<messageCount>" + testCounter.get() + "</messageCount>"; 
		mb.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().clearXmlDetail();
		mb.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().setXmlDetail(xmlDetail);  // inject the counter value into the message
		// provenance will be used to prevent loops
		mb.addProvenance(getClass().getName());
		
		if (logger.isDebugEnabled()) {
			logger.debug("Message sent from plugin to TAK server: {}", message);
		}

		return mb.build();

	}

	@Override
	public void stop() {

	}

}
