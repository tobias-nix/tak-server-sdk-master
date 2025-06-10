package tak.server.plugins;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;
import com.google.common.base.Strings;
import org.dom4j.DocumentException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * This is a bare-bones plugin that demonstrates how to submit XML data to a plugin through a REST endpoint.
 * For purpose of illustration, the XML data that is submitted is expected to be CoT XML.
 * 
 */
@TakServerPlugin(
		name = "Submit Data Example",
		description = "Example plugin that processes data submitted through Plugin Data API")
public class SubmitDataPlugin extends MessageSenderBase {
	
	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	private ConcurrentMap<String, String> scopeDataMap;
	
	@Override
	public void start() {
		logger.info("starting {}", getClass().getName());
	}

	@Override
	public void stop() {
		logger.info("stopping {}", getClass().getName());
	}

	/**
	 * Submits data to be stored with an associated scope
	 *
	 * @param allRequestParams A map of request parameters. Must contain the key "scope" and some value.
	 * @param data The String content that will be stored.
	 * @param contentType The content type of the request. The content type must be "application/xml".
	 */
	@Override
	public void onSubmitData(Map<String, String> allRequestParams, String data, String contentType) {

		if (checkData(data) && checkValidParameters(allRequestParams, contentType)) return;
		
		String scope = allRequestParams.get("scope");

		logger.info("data submitted to plugin: {} scope: {} content type: {}", data, scope, contentType);
		
		if (contentType.equalsIgnoreCase("application/xml")) {
				 
			try {
				// convert the CoT string into a Message
				Message message = cotToMessage(data);

				logger.info("parsed message: {}", message.getPayload());
				if (scopeDataMap == null) {
					scopeDataMap = new ConcurrentHashMap<>();
				}
				scopeDataMap.put(scope, message.getPayload().toString());

			} catch (Exception e) {
				logger.error("exception parsing XML data ", e);
			}

		}
	}

	/**
	 * Submits data to be stored with the associated scope and returned as plugin response.
	 *
	 * @param allRequestParams A map of request parameters. Must contain the key "scope" and the desired scope.
	 * @param data The String content that will be stored within the scope.
	 * @param contentType The content type of the request. The content type can be "application/xml" or "application/json".
	 * @return The response from the plugin containing the data submitted and the content type. Will return as an empty
	 * plugin response if unable to process.
	 */
	@Override
	public PluginResponse onSubmitDataWithResult(Map<String, String> allRequestParams, String data, String contentType) {
		
		PluginResponse result = new PluginResponse();

		if (checkData(data) && checkValidParameters(allRequestParams, contentType)) return result;
		
		String scope = allRequestParams.get("scope");

		logger.info("data submitted to plugin: {} scope: {} content type: {}", data, scope, contentType);

		try {
			Message message = cotToMessage(data);

			logger.info("parsed message: {}", message.getPayload());
			if (scopeDataMap == null) {
				scopeDataMap = new ConcurrentHashMap<>();
			}

			String messagePayload = message.getPayload().toString();

			scopeDataMap.put(scope, messagePayload);
			result.setData(messagePayload);

			if (contentType.equalsIgnoreCase("application/xml")) {
				result.setContentType(contentType);
			}
			else{
				result.setContentType("application/json");
			}
		}
		catch (Exception e) {
			logger.error("exception parsing XML data ", e);
		}

		return result;
	}

	/**
	 * Updates the data for a given scope. The scope must already be present in the data structure in order to be updated.
	 *
	 * @param allRequestParams The request parameters. Must contain a key of "scope" and the scope you are trying to access
	 * @param data The data that a given scope will be updated to.
	 * @param contentType The content type of the request. Must be "application/xml".
	 */
	@Override
	public void onUpdateData(Map<String, String> allRequestParams, String data, String contentType) {

		if (checkData(data) && checkValidParameters(allRequestParams, contentType)) return;
		
		String scope = allRequestParams.get("scope");

		logger.info("data updated in plugin: {} scope: {} content type: {}", data, scope, contentType);
		
		if (contentType.equalsIgnoreCase("application/xml")) {
				 
			try {
				Message message = cotToMessage(data);

				logger.info("parsed message: {}", message.getPayload());
				if (scopeDataMap != null && scopeDataMap.containsKey(scope)) {
					scopeDataMap.put(scope, message.getPayload().toString());
				}

			} catch (Exception e) {
				logger.error("exception parsing XML data ", e);
			}

		}
	}

	/**
	 * Returns the requested data as a plugin response if the associated scope is present in the data structure.
	 *
	 * @param allRequestParams The request parameters. Must contain a key of "scope" and the scope you are trying to
	 *                         request.
	 * @param contentType The content type of the request. Can either be "application/xml" "application/json".
	 * @return The plugin response containing the requested data and content type if contained within the data structure.
	 * Will return as an empty plugin response if unable to process request.
	 */
	@Override
	public PluginResponse onRequestData(Map<String, String> allRequestParams, String contentType) {
		
		PluginResponse result = new PluginResponse();
		String scope = allRequestParams.get("scope");

		if (checkScope(scope) && checkValidParameters(allRequestParams, contentType)) return result;

		logger.info("data requested from plugin: scope: {} content type: {}", scope, contentType);

		try {
			result.setData(scopeDataMap.get(scope));
			if (contentType.equalsIgnoreCase("application/xml")) {
				result.setContentType(contentType);
			}
			else {
				result.setContentType("application/json");
			}
		}
		catch (Exception e) {
			logger.error("exception parsing XML data ", e);
		}
		return result;
	}

	/**
	 * Removes the data from the data structure if the associated scope is present.
	 *
	 * @param allRequestParams The request parameters. Must contain the key "scope" with value of the scope that is to
	 *                         be deleted.
	 * @param contentType The content type of the request. Must be "application/xml".
	 */
	@Override
	public void onDeleteData(Map<String, String> allRequestParams, String contentType) {

		String scope = allRequestParams.get("scope");

		if(checkScope(scope) && checkValidParameters(allRequestParams, contentType)) return;

		logger.info("request delete data from plugin scope: {} content type: {}", scope, contentType);
		
		if (contentType.equalsIgnoreCase("application/xml")) {
				 
			try {
				scopeDataMap.remove(scope);
			} catch (Exception e) {
				logger.error("exception parsing XML data ", e);
			}
		}
	}

	private Message cotToMessage(String data) throws DocumentException, NullPointerException{
		return getConverter().cotStringToDataMessage(data, new HashSet<>(),
				Integer.toString(System.identityHashCode(this)));
	}

	private boolean checkData(String data)
	{
		if (Strings.isNullOrEmpty(data)) {
			logger.error("empty data submitted");
			return true;
		}
		else {
			return false;
		}
	}

	private boolean checkScope(String scope)
	{
		if (scopeDataMap == null || scopeDataMap.get(scope) == null) {
			logger.info("no data stored in plugin for {}", scope);
			return true;
		}
		else {
			return false;
		}
	}

	private boolean checkValidParameters(Map<String, String> allRequestParams, String contentType)
	{
		if (Strings.isNullOrEmpty(contentType)) {
			logger.error("content type must not be empty.");
			return true;
		}
		else if (allRequestParams == null || allRequestParams.isEmpty()) {
			logger.error("no request parameters provided");
			return true;
		}
		else if (!allRequestParams.containsKey("scope")) {
			logger.error("scope parameter must be provided");
			return true;
		}
		return false;
	}

	protected ConcurrentMap<String, String> getScopeDataMap() {
		return scopeDataMap;
	}

	protected void setScopeDataMap(ConcurrentHashMap<String, String> scopeDataMap) {
		this.scopeDataMap = scopeDataMap;
	}
}
