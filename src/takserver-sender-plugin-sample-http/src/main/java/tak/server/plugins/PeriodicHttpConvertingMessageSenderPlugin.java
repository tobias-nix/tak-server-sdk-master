package tak.server.plugins;

import java.lang.invoke.MethodHandles;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.collect.Lists;
import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpRequests;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import com.bbn.cot.CotParserCreator;
//import com.bbn.marti.nio.util.StreamingProtoBufHelper;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;

/**
 * Plugin that polls an HTTP web service over a set interval, and converts the responses into COT messages to send to tak server.
 */
@TakServerPlugin(name="HTTP Converting Message Sender Plugin", description="This plugin will poll an HTTP web service, convert responses into CoT messages, and send through TAK Server.")
public class PeriodicHttpConvertingMessageSenderPlugin extends MessageSenderBase {

	private static final ScheduledExecutorService worker = Executors.newScheduledThreadPool(1);

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	private static final long DEFAULT_INTERVAL = 2000;

	private List<HttpTarget> httpTargets;

	private ScheduledFuture<?> future;

	private static final String SA = "<event version=\"2.0\" uid=\"ANDROID-352413144215585\" type=\"a-f-G-U-C\" how=\"m-g\" time=\"2020-02-12T13:16:07Z\" start=\"2020-02-12T13:16:05Z\" stale=\"2020-02-12T13:16:50Z\"><point lat=\"40.255716\" lon=\"-72.045306\" hae=\"-22.22983896651138\" ce=\"4.9\" le=\"9999999.0\"/><detail><__group name=\"Dark Blue\" role=\"Team Member\"/><precisionlocation geopointsrc=\"GPS\" altsrc=\"GPS\"/><status battery=\"32\"/><takv device=\"SAMSUNG SM-G975U1\" platform=\"ATAK-CIV\" os=\"29\" version=\"3.12.0-45691.45691-CIV\"/><track speed=\"0.0\" course=\"344.72362164876733\"/><contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/></detail></event>";

	private final long checkingInterval;
	private Set<String> groups;


	@SuppressWarnings("unchecked")
	public PeriodicHttpConvertingMessageSenderPlugin() {

		if (config.containsProperty("interval")) {
			checkingInterval = (int) config.getProperty("interval");
		}
		else {
			checkingInterval = DEFAULT_INTERVAL;
		}

		if (config.containsProperty("groups")) {
			groups = new HashSet<>((List<String>) config.getProperty("groups"));
		}

		if (config.containsProperty("http.targets")) {
			httpTargets = parseTargetsIntoList((List<Map<String, Map<String, List<String>>>>) config.getProperty("http.targets"));
		}

		logger.info("Properties: {}", config.getProperties());
		logger.info("sending interval: {}, groups: {}", checkingInterval, groups);
	}

	/**
	 * Starts the plugin. Converts HTTP responses from web services, converts them into COT messages, and sends the
	 * messages to tak server
	 */
	@Override
	public void start() {

		logger.info("starting {}", getClass().getName());

		try {

			AtomicInteger count = new AtomicInteger();

			final Message message = getConverter().cotStringToDataMessage(SA, groups, Integer.toString(System.identityHashCode(this)));

			future = worker.scheduleWithFixedDelay(() -> createClient(message, count), 0, checkingInterval, TimeUnit.MILLISECONDS);


		} catch (Exception e) {
			logger.error("error initializing periodic data sender", e);
		}

	}

	/**
	 * Creates a http client that will make http requests to a set of http targets and inject the response into a COT
	 * message
	 *
	 * @param message the message that will be injected with the http response and message count
	 * @param count the current count of messages sent by the plugin
	 */
	protected void createClient(Message message, AtomicInteger count)
	{
		try (CloseableHttpAsyncClient client = getHttpClient()) {

			logger.info("http client: {}", client);
			client.start();

			Message modifiedMessage = injectXmlDetail(message, count);
			Message.Builder messageBuilder = modifiedMessage.toBuilder();

			if (httpTargets == null) {
				httpTargets = new ArrayList<>();
			}
			logger.info("Targets: {} -> type: {}", httpTargets, httpTargets.getClass().getName());

			try {
				for (HttpTarget httpTarget : httpTargets) {
					final HttpHost httpHost = new HttpHost(httpTarget.getAddress());
					List<String> requestUris = httpTarget.getUris();

					for (final String requestUri: requestUris) {
						final SimpleHttpRequest httpGet = SimpleHttpRequests.get(httpHost, requestUri);
						logger.info("Executing request {} {}", httpGet.getMethod(), httpGet.getUri());
						final Future<SimpleHttpResponse> futureResponse = createHttpResponse(client, httpGet, requestUri, messageBuilder);
						futureResponse.get();
					}
				}
			} catch (Exception e) {
				logger.info("exception making HTTP request", e);
			}
		} catch (Exception e) {
			logger.error("http client exception", e);
		}
	}

	/**
	 * Takes a message and a counter and injects the count within the messages xml detail
	 *
	 * @param message the message that will be injected with the xml detail
	 * @param count the count that will be injected into the xml detail
	 * @return the modified message with a message count contained within its xml detail
	 */
	protected Message injectXmlDetail(Message message, AtomicInteger count)
	{
		Message.Builder messageBuilder = message.toBuilder();
		String xmlDetail = messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().getXmlDetail();
		xmlDetail += "<messageCount>" + count.incrementAndGet() + "</messageCount>";
		messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().clearXmlDetail();
		messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().setXmlDetail(xmlDetail);
		return messageBuilder.build();
	}

	/**
	 * Creates a future object that waits for a http response from a web service, converts it to tak message, and send
	 * it to tak server. The entire body of the http response is placed within the message's callsign field.
	 *
	 * @param client the client that will be making the request
	 * @param httpGet the get request that the client will make
	 * @param requestUri the Uri that the client requested a response from
	 * @param messageBuilder the Message Builder that will create the tak message
	 * @return the future http response
	 */
	private Future<SimpleHttpResponse> createHttpResponse(CloseableHttpAsyncClient client, SimpleHttpRequest httpGet, String requestUri, Message.Builder messageBuilder) {
		return client.execute(httpGet, new FutureCallback<>()
		{

			@Override
			public void completed(final SimpleHttpResponse response)
			{

				try
				{
					logger.info("{}->{}", requestUri, response.getCode());
					logger.info("response: {}", response.getBody().getBodyText());

					messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().clearXmlDetail();

					messageBuilder.getPayloadBuilder().getCotEventBuilder().getDetailBuilder().getContactBuilder().setCallsign(response.getBody().getBodyText());

					Message message = messageBuilder.build();

					logger.info("message to send: {}", message);

					send(message);
				} catch (Exception e)
				{
					logger.error("exception processing HTTP response into TAK proto message", e);
				}
			}

			@Override
			public void failed(final Exception ex)
			{
				logger.error("{}->{}", requestUri, ex);
			}

			@Override
			public void cancelled()
			{
				logger.error("{} cancelled", requestUri);
			}
		});
	}

	private CloseableHttpAsyncClient getHttpClient() {
		final IOReactorConfig ioReactorConfig = IOReactorConfig.custom()
				.setSoTimeout(Timeout.ofSeconds(5))
				.build();

		return HttpAsyncClients.custom()
				.setIOReactorConfig(ioReactorConfig)
				.build();
	}

	/**
	 * Stops the plugin and cancels all future tasks
	 */
	@Override
	public void stop() {
		if (future != null) {
			future.cancel(true);
		}
	}

	protected static class HttpTarget
	{
		private final String address;
		private final List<String> uris;

		public HttpTarget(Map<String, Map<String, List<String>>> targetData)
		{
			address = Lists.newArrayList(targetData.keySet()).get(0);
			uris = targetData.get(address).get("uris");
		}

		public String getAddress()
		{
			return address;
		}

		public List<String> getUris()
		{
			return Collections.unmodifiableList(uris);
		}

	}

	protected List<HttpTarget> parseTargetsIntoList(List<Map<String, Map<String, List<String>>>> targets)
	{
		List<HttpTarget> httpTargets = new ArrayList<>();
		for (Map<String, Map<String, List<String>>> targetInfo : targets)
		{
			httpTargets.add(new HttpTarget(targetInfo));
		}
		return httpTargets;
	}
}
