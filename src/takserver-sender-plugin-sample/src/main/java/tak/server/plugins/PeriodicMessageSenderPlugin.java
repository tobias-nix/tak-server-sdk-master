package tak.server.plugins;

import java.lang.invoke.MethodHandles;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;

/**
 * A plugin that periodically sends messages on a set interval.
 */
@TakServerPlugin(
		name = "Periodic Sender Example",
		description = "Example plugin that sends data on a time interval")
public class PeriodicMessageSenderPlugin extends MessageSenderBase {

	private final long interval; // periodic message sending interval (ms)
	private static final long DEFAULT_INTERVAL = 2000L;
	private Set<String> groups;

	private final List<String> callsigns;
	private final List<String> uids;
	private ScheduledFuture<?> future;

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	private static final ScheduledExecutorService worker = Executors.newScheduledThreadPool(1);

	private int messageCount = 0;

	private static final String SA = "<event version=\"2.0\" uid=\"ANDROID-352413144215585\" type=\"a-f-G-U-C\" how=\"m-g\" time=\"2020-02-12T13:16:07Z\" start=\"2020-02-12T13:16:05Z\" stale=\"2020-02-12T13:16:50Z\"><point lat=\"40.255716\" lon=\"-72.045306\" hae=\"-22.22983896651138\" ce=\"4.9\" le=\"9999999.0\"/><detail><__group name=\"Dark Blue\" role=\"Team Member\"/><precisionlocation geopointsrc=\"GPS\" altsrc=\"GPS\"/><status battery=\"32\"/><takv device=\"SAMSUNG SM-G975U1\" platform=\"ATAK-CIV\" os=\"29\" version=\"3.12.0-45691.45691-CIV\"/><track speed=\"0.0\" course=\"344.72362164876733\"/><contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/></detail></event>";

	@SuppressWarnings("unchecked")
	public PeriodicMessageSenderPlugin() {
		if (config.containsProperty("interval")) {
			interval = (int) config.getProperty("interval");
		}
		else {
			interval = DEFAULT_INTERVAL;
		}

		if (config.containsProperty("groups")) {
			groups = new HashSet<>((List<String>) config.getProperty("groups"));
		}

		callsigns = (List<String>) config.getProperty("callsigns");

		uids = (List<String>) config.getProperty("uids");
	}

	/**
	 * Starts the plugin. Send messages on a set time interval until the plugin is stopped.
	 */
	@Override
	public void start() {

		logger.info("uids: {}", uids);
		logger.info("callsigns: {}", callsigns);
		logger.info("starting {}", getClass().getName());

		try {

			final Message message = getConverter().cotStringToDataMessage(SA, groups, Integer.toString(System.identityHashCode(this)));

			future = worker.scheduleWithFixedDelay(() -> {

				Message generatedMessage = generateMessage(message);

				logger.info("message: {}", generatedMessage);

				send(generatedMessage);

			}, 0, interval, TimeUnit.MILLISECONDS);
			

		} catch (Exception e) {
			logger.error("error initializing periodic data sender ", e);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Modifies a cot message to contain the active count of messages that the plugin has sent. Stores this count in
	 * the xml detail of the message.
	 *
	 * @param message the original message to be modified
	 * @return the new message with message sent count
	 */
	protected Message generateMessage(Message message) {

		messageCount += 1;

		Message.Builder messageBuilder = message.toBuilder();

		String xmlDetail = messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().getXmlDetail();
		xmlDetail += "<messageCount>" + messageCount + "</messageCount>";

		messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().clearXmlDetail();
		messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().setXmlDetail(xmlDetail);

		if (callsigns != null && !callsigns.isEmpty()) {

			messageBuilder.addAllDestCallsigns(callsigns);
		}

		if (uids != null && !uids.isEmpty()) {

			messageBuilder.addAllDestClientUids(uids);
		}

		return messageBuilder.build();
	}

	/**
	 * Stops the plugin and cancels all future tasks.
	 */
	@Override
	public void stop() {
		if (future != null) {
	 		future.cancel(true);
		}
	}
}
