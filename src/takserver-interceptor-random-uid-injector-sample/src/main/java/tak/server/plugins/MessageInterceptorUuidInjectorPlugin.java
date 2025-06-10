package tak.server.plugins;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Plugin that intercepts a message and injects a random UUID into its message detail.
 */
@TakServerPlugin(name="Message Interceptor UUID Injector Plugin", description="This plugin will intercept messages, and inject a random UUID in the XML detail field.")
public class MessageInterceptorUuidInjectorPlugin extends MessageInterceptorBase {

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	private Set<String> inputGroups = null;
	private Set<String> outputGroups = null;

	@SuppressWarnings("unchecked")
	public MessageInterceptorUuidInjectorPlugin() {

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
	 * Intercepts a message and injects a random UUID into the xml message detail
	 *
	 * @param message the intercepted message to inject with a random UUID
	 * @return the modified message with random UUID in its xml detail
	 */
	@Override
	public Message intercept(Message message) {
		Message.Builder mb = message.toBuilder();

		 String xmlDetail = mb.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().getXmlDetail();
         xmlDetail += "<myUuid>" + UUID.randomUUID() + "</myUuid>";
         mb.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().clearXmlDetail();
         mb.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().setXmlDetail(xmlDetail);
         // provenance will be used to prevent loops
         mb.addProvenance(MessageInterceptorUuidInjectorPlugin.class.getName());
		
 		return mb.build();
	}

	@Override
	public void stop() {

	}

}
