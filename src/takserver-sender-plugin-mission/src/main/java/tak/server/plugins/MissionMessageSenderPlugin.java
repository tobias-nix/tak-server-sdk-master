package tak.server.plugins;

import com.bbn.marti.maplayer.model.MapLayer;
import com.bbn.marti.remote.sync.MissionContent;
import com.bbn.marti.sync.model.Mission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Example plugin that create, deletes, and modifies missions.
 */
@TakServerPlugin(
		name = "Mission Plugin Example",
		description = "Example plugin that creates/deletes mission.")
public class MissionMessageSenderPlugin extends MessageSenderBase {

	private static final String MISSION_NAME = "mission_from_plugin_1";
	private static final String CREATOR_UID = "mission_plugin_1";
	private static final String PARENT_NAME = "mission_from_plugin_3";
	private static final String DATA_FEED_UID = "6749afe0-867b-44fa-ac87-a4d47e3a6b0f";

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	/**
	 * Starts the plugin. Demonstrates the creation and operations that can be performed on mission data
	 */
	@Override
	public void start() {

		logger.info("Start plugin {}", getClass().getName());

		if (pluginMissionApi == null) {
			logger.error("pluginMissionApi is null");
			return;
		}

		queryMissions();

		logger.info("======================================= ");
		logger.info("Creating mission... ");
		Mission mission = createMission(MISSION_NAME, "Sample mission created by plugin");
		if (mission != null) {
			logger.info("Mission {} created", MISSION_NAME);
		}else {
			logger.info("Cannot create mission {}", MISSION_NAME);
		}

		queryMissions();

		try {
			logger.info("======================================= ");

			logger.info("Reading mission {} ... ", MISSION_NAME);
			Mission readMission = pluginMissionApi.readMission(MISSION_NAME, true, false, null, null, null);
			logger.info("Mission : {}", readMission.toString());

		} catch (Exception e) {
			logger.error("ERROR reading mission ", e);
		}

		addMissionContentExample();

		missionKeywordExample();

		logger.info("======================================= ");
		logger.info("Creating parent mission {}... ", PARENT_NAME);
		Mission parentMission = createMission(PARENT_NAME, "Sample parent mission created from plugin");
		if (parentMission != null) {
			logger.info("Mission {} created", PARENT_NAME);
		}else {
			logger.info("Cannot create mission {}", PARENT_NAME);
		}

		setParentChildMission(MISSION_NAME, PARENT_NAME);

		createDatafeedSample();

		mapLayerExample();

	}

	/**
	 * Creates a sample mission and submits it to the pluginMissionApi
	 *
	 * @param missionName the name of the mission
	 * @param description the description of the plugin
	 * @return the created mission
	 */
	protected Mission createMission(String missionName, String description) {

		String[] groupNames = new String[1];
		groupNames[0] = "__ANON__";

		String chatRoom = "chatRoom1";
		String baseLayer = "";
		String bbox ="";
		List<String> boundingPolygon = new ArrayList<>();
		boundingPolygon.add("0,0");
		boundingPolygon.add("10,10");
		boundingPolygon.add("0,10");

		String path = "";
		String classification = "";
		String tool = "public";
		String password = "password@ABC123";
		String role = "MISSION_OWNER";
		Long expiration = System.currentTimeMillis() + 1_000_000L;
		byte[] missionPackage = new byte[100];

		try
		{
			return pluginMissionApi.createMission(missionName, CREATOR_UID,
					groupNames, description, chatRoom, baseLayer,
					bbox, boundingPolygon, path, classification,
					tool, password, role, expiration, missionPackage);
		}catch (Exception e) {
			logger.error("Unable to create mission");
			return null;
		}
	}

	/**
	 * Demonstrates the creation, setting, and removal of keywords
	 */
	protected void missionKeywordExample() {
		logger.info("Adding Keywords for {} ... ", MISSION_NAME);
		List<String> keywords = Arrays.asList("keyword1", "keyword2", "keyword3");

		try {
			Mission setKeywordsMission = pluginMissionApi.setKeywords(MISSION_NAME, keywords, CREATOR_UID);
			logger.info("setKeywordsMission : {}", setKeywordsMission.toString());

			logger.info("Removing Keyword for {} ... ", MISSION_NAME);
			Mission removeKeywordMission = pluginMissionApi.removeKeyword(MISSION_NAME, "keyword2", CREATOR_UID);
			logger.info("removeKeywordMission : {}", removeKeywordMission.toString());
		} catch (Exception e) {
			logger.error("Unable to add keywords ", e);
		}
	}

	/**
	 * Queries all datafeeds and logs them
	 */
	protected void queryDatafeeds() {
		logger.info("Querying all datafeeds");
		Collection<PluginDataFeed> allFeedsBefore = getPluginDataFeedApi().getAllPluginDataFeeds();
		logger.info("Number of datafeeds: {}", allFeedsBefore.size());

		for (PluginDataFeed dataFeed: allFeedsBefore) {
			logger.info("\t + Datafeed: {}", dataFeed.toString());
		}
	}

	/**
	 * Queries all missions and logs them.
	 */
	protected void queryMissions() {
		logger.info("Querying all missions... ");
		try
		{
			List<Mission> allMissions = pluginMissionApi.getAllMissions(true, true, "public");
			logger.info("Number of existing missions: {}", allMissions.size());
			for (Mission mission : allMissions)
			{
				logger.info("\t + Mission: {}", mission.toString());
			}
		}catch (Exception e) {
			logger.error("Unable to query missions: ", e);
		}
	}

	/**
	 * Demonstrates setting a mission as the child/parent of another mission and retrieving parent/children of a mission.
	 *
	 * @param parentName the mission to be set as the parent
	 * @param childName the mission to be set as the child
	 */
	protected void setParentChildMission(String parentName, String childName) {
		try
		{
			logger.info("Set Parent for {} ... ", childName);
			pluginMissionApi.setParent(childName, parentName);

			logger.info("Get parent for {} ... ", childName);
			Mission parent = pluginMissionApi.getParent(childName);
			logger.info("Parent : {}", parent.getName());

			logger.info("Get children for {} ... ", parentName);
			Set<Mission> children = pluginMissionApi.getChildren(parentName);
			for (Mission child : children)
			{
				logger.info("\t + Child : {}", child.getName());
			}
		}catch (Exception e) {
			logger.error("Unable to complete parent/child operations ", e);
		}
	}

	/**
	 * Demonstrates operations that can be performed on a map layer that include creating, deleting, and updating
	 */
	protected void mapLayerExample() {
		try {
			logger.info("Creating mapLayer ...");
			MapLayer sampleMapLayer = initSampleMapLayer();
			MapLayer mapLayer1 = pluginMissionApi.createMapLayer(MISSION_NAME, CREATOR_UID, sampleMapLayer);
			logger.info("mapLayer1: {}", mapLayer1.toString());

			logger.info("Updating mapLayer ...");
			mapLayer1.setUrl("http://127.0.0.1/dummyURL2");
			mapLayer1.setName("mapLayerName2");
			mapLayer1.setDescription("Sample mapLayer 2 from plugin");
			MapLayer mapLayer2 = pluginMissionApi.updateMapLayer(MISSION_NAME, CREATOR_UID, mapLayer1);
			logger.info("mapLayer2: {}", mapLayer2.toString());

			logger.info("Deleting mapLayer2 from mission...");
			pluginMissionApi.deleteMapLayer(MISSION_NAME, CREATOR_UID, mapLayer2.getUid());
			logger.info("Deleted mapLayer2 from mission");

		} catch(Exception e) {
			logger.error("ERROR with MapLayer operations", e);
		}
	}

	/**
	 * Demonstrates how to add content to a mission
	 */
	protected void addMissionContentExample() {
		logger.info("======================================= ");
		logger.info("Adding MissionContent for {} ... ", MISSION_NAME);

		MissionContent missionContent = new MissionContent();
		missionContent.getHashes().add("61b73917465b6fea39d69f45bc40e59c34c098d1b819697079cb8d913005b50a"); // for file (field: contents)

		try {
			Mission addedContentMission = pluginMissionApi.addMissionContent(MISSION_NAME, missionContent , CREATOR_UID);
			logger.info("addedContentMission : {}", addedContentMission.toString());

		} catch (Exception e) {
			logger.error("ERROR Adding MissionContent ", e);
		}
	}

	/**
	 * Example of how to create a datafeed and add it to a mission
	 */
	protected void createDatafeedSample() {

		try {
			logger.info("======================================= ");

			logger.info("Creating new datafeed with uuid: {}", DATA_FEED_UID);
			String datafeedName = "dataFeed_from_plugin_mission_test";
			List<String> tags = new ArrayList<>();
			tags.add("pluginMissionTest");
			getPluginDataFeedApi().create(DATA_FEED_UID, datafeedName, tags, true, true);

			queryDatafeeds();

			logger.info("Adding Feed {} to mission {} ", DATA_FEED_UID, MISSION_NAME);
			pluginMissionApi.addFeed(MISSION_NAME, CREATOR_UID, DATA_FEED_UID, null, null, null);
			logger.info("Added Feed {} to mission {} ", DATA_FEED_UID, MISSION_NAME);

		} catch (Exception e) {
			logger.error("ERROR with adding Feed to mission", e);
		}
	}

	/**
	 * Creates a sample map layer with all the necessary parameters
	 * @return the completed sample map layer
	 */
	private MapLayer initSampleMapLayer() {
		MapLayer mapLayer = new MapLayer();
		mapLayer.setName("mapLayerName1");
		mapLayer.setEnabled(true);
		mapLayer.setBackgroundColor("BLACK");
		mapLayer.setDescription("Sample mapLayer from plugin");
		mapLayer.setCreatorUid(CREATOR_UID);
		mapLayer.setUrl("http://127.0.0.1/dummyURL1");
		mapLayer.setCoordinateSystem("");
		mapLayer.setCreateTime(new Date());
		mapLayer.setAdditionalParameters("");
		mapLayer.setDefaultLayer(false);
		mapLayer.setIgnoreErrors(true);
		mapLayer.setEast(1.2);
		mapLayer.setNorth(1.0);
		mapLayer.setSouth(2.0);
		mapLayer.setWest(3.0);
		mapLayer.setVersion("0.0.1");
		mapLayer.setModifiedTime(new Date());
		return mapLayer;
	}

	/**
	 * Stops the plugin and deletes all associated missions, feeds, keywords, and contents, then queries all missions in
	 * the api once complete
	 */
	@Override
	public void stop() {

		if (pluginMissionApi == null) {
			logger.error("pluginMissionApi is null");
			return;
		}
		try {
			logger.info("Remove Feed for {} ... ", MISSION_NAME);
			pluginMissionApi.removeFeed(MISSION_NAME, DATA_FEED_UID, CREATOR_UID);

			logger.info("Clear Parent for {} ... ", MISSION_NAME);
			pluginMissionApi.clearParent(MISSION_NAME);

			logger.info("Clearing Keyword for {} ... ", MISSION_NAME);
			Mission clearedKeywordMission = pluginMissionApi.clearKeywords(MISSION_NAME, CREATOR_UID);
			logger.info("clearedKeywordMission : {}", clearedKeywordMission.toString());

			logger.info("======================================= ");
			logger.info("Removing MissionContent for {} ... ", MISSION_NAME);

			Mission deletedContentMission = pluginMissionApi.removeMissionContent(MISSION_NAME, "61b73917465b6fea39d69f45bc40e59c34c098d1b819697079cb8d913005b50a", null, CREATOR_UID);
			logger.info("deletedContentMission : {}", deletedContentMission.toString());

			logger.info("======================================= ");

			logger.info("Deleting mission... ");
			pluginMissionApi.deleteMission(MISSION_NAME, CREATOR_UID, true);
			logger.info("Deleting parent mission... ");
			pluginMissionApi.deleteMission(PARENT_NAME, CREATOR_UID, true);
			logger.info("Missions deleted");
			logger.info("======================================= ");

			logger.info("Querying all missions after deleting missions... ");
			List<Mission> allMissions = pluginMissionApi.getAllMissions(true, true, "public");
			logger.info("Number of missions: {}", allMissions.size());
			for (Mission mission: allMissions) {
				logger.info("\t + Mission: {}", mission.toString());
			}
			logger.info("======================================= ");

		}catch(Exception e) {
			logger.error("Error on stopping plugin", e);
		}
	}

}
