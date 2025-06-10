package tak.server.plugins;

import java.io.ByteArrayInputStream;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.apache.commons.io.IOUtils;
import java.io.InputStream;
import java.sql.Timestamp;

import com.bbn.marti.sync.Metadata.Field;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.bbn.marti.sync.Metadata;

/**
 * A bare-bones plugin that demonstrates how to perform CRUD and search on files.
 * 
 */
@TakServerPlugin(
		name = "File Plugin Example",
		description = "Example plugin that performs CRUD and search on files")
public class FilePlugin extends MessageSenderBase {
	
	private String hash = null;

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	/**
	 * Runs the File Plugin example. Goes through the process of creating a file, reading it from a hash, modifying its
	 * metadata and searching for files within certain parameters
	 */
	@Override
	public void start() {
		logger.info("Starting plugin {} ...", getClass().getName());
		if (pluginFileApi == null) {
			logger.error("pluginFileApi is null");
			return;
		}

		try {
			logger.info("Creating new file");
			createFileExample();
			logger.info("Done creating new file with hash: {}", hash);
			logger.info("=========================================");

			try (InputStream inputStream2 = pluginFileApi.readFileContent(hash)){
				String fileContentRead = IOUtils.toString(inputStream2, StandardCharsets.UTF_8);
				logger.info("Read file content from hash: {}", fileContentRead);
			}
			logger.info("=========================================");
			
			logger.info("Querying metadata from hash: {}", hash);
			List<Metadata> metadataList = pluginFileApi.getMetadataByHash(hash);
			metadataList.forEach(metadata1 -> logger.info("\tMetadata: {}", metadata1.toJSONObject()));
			logger.info("Done querying metadata");
			logger.info("=========================================");
			
			logger.info("Updating metadata");
			pluginFileApi.updateMetadata(hash, "CreatorUid", "creatorPluginTest2");
			logger.info("Done Updating metadata");

			logger.info("=========================================");
			
			logger.info("Querying metadata again after updating");
			metadataList = pluginFileApi.getMetadataByHash(hash);
			metadataList.forEach(metadata1 -> logger.info("\tMetadata after updating: {}", metadata1.toJSONObject()));
			logger.info("Done querying metadata");
			logger.info("=========================================");

			logger.info("Searching...");
			Map<Field, String> metadataConstraints = new EnumMap<>(Field.class);
			metadataConstraints.put(Metadata.Field.MIMEType,  "text/plain");
			searchExample(null, null, metadataConstraints, null, null, null,
					null, false, null, "ExCheck");
			logger.info("End search results");
			logger.info("=========================================");

		} catch (Exception e) {
			logger.error("An error has occurred with the File Plugin API: ", e);
		}
		
	}

	/**
	 * Stops the plugin and removes the file from the API
	 */
	@Override
	public void stop() {
		logger.info("Stopping plugin {}", getClass().getName());
		if (hash != null) {
			try {
				logger.info("Deleting file hash: {}", hash);
				pluginFileApi.deleteFile(hash);
				logger.info("Deleted file hash: {}", hash);
			} catch (Exception e) {
				logger.error("Error while attempting to delete file hash from Plugin File API: ", e);
			}
		}
	}

	/**
	 * Creates metadata that can be used with a file. Note that this is not the full extent of fields that are available
	 * within the {@link com.bbn.marti.sync.Metadata} object.
	 *
	 * @param id The name of the file. Also defines the user id
	 * @param keywords The keywords to be searched for
	 * @param pluginClassName the class name for the plugin
	 * @param creatorId the name of what created the file in the API
	 * @param latitude latitude represented in decimal
	 * @param longitude longitude represented in decimal
	 * @param tool the tool used
	 * @return the metadata for the file with fields entered based on parameters
	 */
	public Metadata createFileMetadata(String id, String[] keywords, String mimeType, String pluginClassName, String creatorId,
									   Double latitude, Double longitude, String tool) {

		Metadata metadata = new Metadata();
		metadata.set(Metadata.Field.DownloadPath, id + ".txt");
		metadata.set(Metadata.Field.Name, id);
		metadata.set(Metadata.Field.MIMEType, mimeType);
		metadata.set(Metadata.Field.UID, new String[]{id});
		metadata.set(Metadata.Field.Keywords, keywords);
		metadata.set(Metadata.Field.PluginClassName, pluginClassName);
		metadata.set(Metadata.Field.CreatorUid, creatorId);
		metadata.set(Metadata.Field.Latitude, latitude);
		metadata.set(Metadata.Field.Longitude, longitude);
		metadata.set(Metadata.Field.Tool, tool);

		return metadata;
	}

	/**
	 * Demonstrates the basic usage of new file creation
	 */
	private void createFileExample() {
		String fileContent = "This is a dummy file content";

		Metadata metadata = createFileMetadata("testFilePlugin", null, "text/plain",
				"tak.server.plugins.FileUploadListenerPlugin", "creatorPluginTest1",
				0.1, -0.1, "ExCheck");

		try (InputStream inputStream = new ByteArrayInputStream(fileContent.getBytes(StandardCharsets.UTF_8))) {
			Metadata returnMetadata = pluginFileApi.newFile(metadata, inputStream);
			hash = returnMetadata.getFirst(Metadata.Field.Hash);
		} catch (Exception e) {
			logger.error("Error while trying to create file in the Plugin File API: ", e);
		}
	}

	/**
	 * Demonstrates the basics of using the search method of the pluginFileApi
	 *
	 * @param minimumAltitude the maximum altitude in the range to search
	 * @param maximumAltitude the minimum altitude in the range to search
	 * @param metadataConstraints the metadata constraints to be searched
	 * @param bBox the bounding box
	 * @param circle the area within a circle that will be searched
	 * @param minimumTime the minimum time of the search range
	 * @param maximumTime the maximum time of the search range
	 * @param latestOnly enable to only search the latest results
	 * @param missionName the name of the mission that will be searched
	 * @param tool the tool used
	 */
	private void searchExample(Double minimumAltitude, Double maximumAltitude, Map<Field, String> metadataConstraints,
							   Double[] bBox, Double[] circle, Timestamp minimumTime, Timestamp maximumTime, Boolean latestOnly,
							  String missionName, String tool) {
		try {
			SortedMap<String, List<Metadata>> searchResults = pluginFileApi.search(minimumAltitude, maximumAltitude,
					metadataConstraints, bBox, circle, minimumTime, maximumTime, latestOnly, missionName, tool);
			logger.info("Search results:");
			searchResults.forEach((key, listMetadata) -> {
				logger.info("\t+ Uid: {}", key);
				listMetadata.forEach(mt-> logger.info("\t\t++Metadata: {}", mt.toJSONObject()));
			});
		}catch (Exception e) {
			logger.error("Error in searching for file in Plugin File API: ", e);
		}

	}
	
}
