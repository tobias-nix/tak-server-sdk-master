package tak.server.plugins;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;

import java.lang.invoke.MethodHandles;

/**
 * Barebones plugin for receiving and logging messages
 */
@TakServerPlugin
public class MessageLoggingReceiverPlugin extends MessageReceiverBase {

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	public MessageLoggingReceiverPlugin() throws ReservedConfigurationException {
		logger.info("create {}", getClass().getName());
	}

	@Override
	public void start() {
		logger.info("{} started", getClass().getName());
	}

	/**
	 * Logs the received message from tak server.
	 *
	 * @param message the received message that will be logged
	 */
	@Override
	public void onMessage(Message message) {

		logger.info("plugin message received: {}", message);
	}

	@Override
	public void stop() {
		
	}
}