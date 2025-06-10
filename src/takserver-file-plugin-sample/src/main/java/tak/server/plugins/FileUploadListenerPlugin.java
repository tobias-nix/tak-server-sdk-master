package tak.server.plugins;

import com.bbn.marti.sync.Metadata;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;

/**
 * Plugin that listens for a file upload event and logs the file metadata, content, and hash of the uploaded file
 */
@TakServerPlugin(
		name = "File Upload Listener Example",
		description = "Example plugin that listens to file upload event")
public class FileUploadListenerPlugin extends MessageSenderBase {
	
	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
	@Override
	public void start() {
		logger.info("starting {}", getClass().getName());
	}

	@Override
	public void stop() {
		logger.info("stopping {}", getClass().getName());
	}

	/**
	 * Plugin received notification of a file upload event. Implementation of this function is provided by the plugin.
	 * @param metadata the metadata of the file uploaded
	 */
	@Override
	public void onFileUploadEvent(Metadata metadata) {
		logger.info("Call onFileUploadEvent method() in plugin class {}", getClass().getName());
		logger.info("Metadata received on file upload event: {} ", metadata.toString());
		
		if (pluginFileApi == null) {
			logger.error("pluginFileApi is null");
			return;
		}
		try {
			String hash = metadata.getFirst(Metadata.Field.Hash);
			logger.info("Hash value: {} ", hash);

			try (InputStream inputStream2 = pluginFileApi.readFileContent(hash)){
				String fileContentRead = IOUtils.toString(inputStream2, StandardCharsets.UTF_8);
				logger.info("~~~ onFileUploadEvent: Read file content from hash: {}", fileContentRead);
			}
		}catch (Exception e) {
			logger.error("Error onFileUploadEvent", e);
		}
		
	}
}
