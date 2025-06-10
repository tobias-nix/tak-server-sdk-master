package tak.server.plugins;

import atakmap.commoncommo.protobuf.v1.DetailOuterClass;
import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;
import org.dom4j.DocumentException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;


/**
 * Demonstrates operations on datafeeds, then sends periodic messages to one of the datafeeds. The plugin will cancel
 * operation after 30 seconds of sending periodic messages
 */
@TakServerPlugin(
		name = "Data Feed Plugin Example",
		description = "Example plugin that creates/deletes datafeeds and sends messages to a datafeed on a time interval. " +
				"Self-stop after 30 seconds")
public class DataFeedMessageSenderPlugin extends MessageSenderBase {

	private long sendingIntervalMillis = 10_000;
	protected Set<String> groups;

	private final List<String> groupNames = List.of("__ANON__");

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	private static final ScheduledExecutorService worker = Executors.newScheduledThreadPool(1);

	private static final String SA = "<event version=\"2.0\" uid=\"ANDROID-352413144215586\" type=\"a-f-G-U-C\" how=\"m-g\" time=\"2020-02-12T13:16:07Z\" start=\"2020-02-12T13:16:05Z\" stale=\"2020-02-12T13:16:50Z\"><point lat=\"40.255716\" lon=\"-72.045306\" hae=\"-22.22983896651138\" ce=\"4.9\" le=\"9999999.0\"/><detail><__group name=\"Dark Blue\" role=\"Team Member\"/><precisionlocation geopointsrc=\"GPS\" altsrc=\"GPS\"/><status battery=\"32\"/><takv device=\"SAMSUNG SM-G975U1\" platform=\"ATAK-CIV\" os=\"29\" version=\"3.12.0-45691.45691-CIV\"/><track speed=\"0.0\" course=\"344.72362164876733\"/><contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/></detail></event>";

	private ScheduledFuture<?> future;

	private String feedUuid1 = "f0977622-c944-4fb2-9315-2e3e1a154890";
	private String feedUuid2 = "436d14b5-6601-4a19-8c15-21194eb7c84f";
	private String feedUuid3 = "1f5aadfe-77ba-11ec-90d6-0242ac120003";
	
	@SuppressWarnings("unchecked")
	public DataFeedMessageSenderPlugin() {
		if (config.containsProperty("interval")) {
			sendingIntervalMillis = (int) config.getProperty("interval");
		}

		if (config.containsProperty("groups")) {
			groups = new HashSet<>((List<String>) config.getProperty("groups"));
		}
		
		if (config.containsProperty("feedUuid1")) {
			feedUuid1 = (String)config.getProperty("feedUuid1");
		}
		
		if (config.containsProperty("feedUuid2")) {
			feedUuid2 = (String)config.getProperty("feedUuid2");
		}
		
		if (config.containsProperty("feedUuid3")) {
			feedUuid3 = (String)config.getProperty("feedUuid3");
		}
	}

	/**
	 * Runs the plugin, demonstrating the operations that can create, modify, or delete datafeeds. Sends data periodically
	 * to one of the datafeeds
	 */
	@Override
	public void start() {
		logger.info("Starting plugin {}", getClass().getName());

		logger.info("================================================");
		queryAllDataFeeds();

		createSampleDataFeeds();

		logger.info("================================================");
		logger.info("Querying all plugin datafeeds after creating new datafeeds");
		queryAllDataFeeds();

		logger.info("================================================");
		logger.info("Querying all plugin datafeeds again (to test if caching works)");
		queryAllDataFeeds();

		logger.info("================================================");
		logger.info("Deleting plugin datafeed uuid {}", feedUuid2);
		getPluginDataFeedApi().delete(feedUuid2, groupNames);
		logger.info("Successfully deleted plugin datafeed uuid {}", feedUuid2);

		logger.info("Deleting plugin datafeed uuid {}", feedUuid3);
		getPluginDataFeedApi().delete(feedUuid3, groupNames);
		logger.info("Successfully deleted plugin datafeed uuid {}", feedUuid3);

		logger.info("================================================");
		logger.info("Querying all plugin datafeeds after deleting 2 datafeeds");
		queryAllDataFeeds();

		try {
			sendPeriodicMessage(feedUuid1);
		} catch (DocumentException e) {
			logger.error("Error initializing periodic data sender. The cot message converter was unable to convert the string into a cot message ", e);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Queries all available datafeeds and logs them
	 */
	protected void queryAllDataFeeds() {
		Collection<PluginDataFeed> allFeeds = getPluginDataFeedApi().getAllPluginDataFeeds();
		logger.info("Number of datafeeds: {}", allFeeds.size());
		logger.info("Active datafeeds: ");

		for (PluginDataFeed dataFeed: allFeeds) {
			logger.info("\t - Datafeed: {}", dataFeed.toString());
		}
	}

	/**
	 * Creates 3 sample datafeeds of different configurations and logs successful creations
	 */
	protected void createSampleDataFeeds() {
		PluginDataFeedApi pluginDataFeedApi = getPluginDataFeedApi();

		logger.info("================================================");
		String datafeedName1 = "testDataFeedFromPlugin1";
		List<String> tags1 = new ArrayList<>();
		tags1.add("sampleTag1");
		tags1.add("sampleTag2");
		logger.info("Creating new datafeed with uuid: {}", feedUuid1);
		PluginDataFeed myPluginDataFeed1 = pluginDataFeedApi.create(feedUuid1, datafeedName1, tags1, true, true, groupNames);
		logger.info("Successfully created datafeed: {}", myPluginDataFeed1.toString());

		String datafeedName2 = "testDataFeedFromPlugin2";
		List<String> tags2 = new ArrayList<>();
		tags2.add("sampleTagA");
		tags2.add("sampleTagB");
		tags2.add("sampleTagC");
		logger.info("Creating new datafeed with uuid: {}", feedUuid2);
		PluginDataFeed myPluginDataFeed2 = pluginDataFeedApi.create(feedUuid2, datafeedName2, tags2, false,
				false, groupNames);
		logger.info("Successfully created datafeed: {}", myPluginDataFeed2.toString());

		String datafeedName3 = "testDataFeedFromPlugin3";
		logger.info("Creating new datafeed with uuid: {}", feedUuid3);
		PluginDataFeed myPluginDataFeed3 = pluginDataFeedApi.create(feedUuid3, datafeedName3, new ArrayList<>(),
				true, false, groupNames);
		logger.info("Successfully created datafeed: {}", myPluginDataFeed3.toString());
	}

	/**
	 * Injects a counter in a messages xml detail
	 * @param message the message to inject with the counter
	 * @param count the current count
	 * @return the message with counter in its xml detail
	 */
	protected Message injectXmlDetail(Message message, AtomicInteger count)
	{
		Message.Builder messageBuilder = message.toBuilder();
        DetailOuterClass.Detail.Builder detailBuilder = messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder();

		String xmlDetail = detailBuilder.getXmlDetail();
		xmlDetail += "<messageCount>" + count.incrementAndGet() + "</messageCount>";
		detailBuilder.setXmlDetail(xmlDetail);
		return messageBuilder.build();
	}

	/**
	 * Schedules two tasks: The first to send a periodic message over a set interval to a given feed. The second schedules the plugin
	 * to self stop after 30 seconds
	 *
	 * @param feedUuid the feed uuid to send messages to
	 * @throws DocumentException if the message converter is unable to convert the string into a cot message, an exception
	 * is thrown
	 */
	private void sendPeriodicMessage(String feedUuid) throws DocumentException {
		final AtomicInteger count = new AtomicInteger();

		final Message message = getConverter().cotStringToDataMessage(SA, groups, Integer.toString(System.identityHashCode(this)));

		future = worker.scheduleWithFixedDelay(() -> {
			Message injectedMessage = injectXmlDetail(message, count);
			logger.info("message: {}", injectedMessage);

			send(injectedMessage, feedUuid);
			logger.info("Sent message to datafeed UUID: {}", feedUuid);

		}, 3000, sendingIntervalMillis, TimeUnit.MILLISECONDS);

		ScheduledFuture<?> futureStop = worker.schedule(() -> {
			logger.info("Self stop...");
			selfStop();
			logger.info("Done with self stop...");
		}, 30_000, TimeUnit.MILLISECONDS);
	}

	protected long getSendingIntervalMillis() {
		return sendingIntervalMillis;
	}

	protected void setSendingIntervalMillis(long sendingIntervalMillis) {
		this.sendingIntervalMillis = sendingIntervalMillis;
	}

	/**
	 * Stops the plugin and cancels all future scheduled tasks, if any, and deletes the datafeed
	 */
	@Override
	public void stop() {
		if (future != null) {
	 		future.cancel(true);
		}
		
		try {
			logger.info("Deleting datafeed {}", feedUuid1);
			PluginDataFeedApi pluginDataFeedApi = getPluginDataFeedApi();
			pluginDataFeedApi.delete(feedUuid1, groupNames);
			logger.info("Deleted datafeed {}", feedUuid1);
		} catch (Exception e) {
			logger.error("Error when deleting datafeed uuid {}", feedUuid1, e);
		}
	}
}
