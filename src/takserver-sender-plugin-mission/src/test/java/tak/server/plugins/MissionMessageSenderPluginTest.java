package tak.server.plugins;

import com.bbn.marti.maplayer.model.MapLayer;
import com.bbn.marti.remote.sync.MissionContent;
import com.bbn.marti.sync.model.Mission;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class MissionMessageSenderPluginTest
{
    private static final String CREATOR_UID = "mission_plugin_1";

    @InjectMocks
    MissionMessageSenderPlugin plugin = new MissionMessageSenderPlugin();

    @Mock
    PluginMissionApi pluginMissionApi;

    @Mock
    PluginDataFeedApi pluginDataFeedApi;

    @Before
    public void startUp() throws Exception
    {
        when(pluginMissionApi.addMissionContent(anyString(), any(MissionContent.class), anyString())).thenReturn(new Mission());
        when(pluginMissionApi.createMapLayer(anyString(), anyString(), any(MapLayer.class))).thenReturn(initSampleMapLayer());
        when(pluginMissionApi.updateMapLayer(anyString(), anyString(), any(MapLayer.class))).thenReturn(initSampleMapLayer());
        when(pluginMissionApi.getParent(anyString())).thenReturn(new Mission());
        when(pluginMissionApi.getChildren(anyString())).thenReturn(createMissionSet());
        when(pluginMissionApi.setKeywords(anyString(), anyList(), anyString())).thenReturn(new Mission());
        when(pluginMissionApi.removeKeyword(anyString(), anyString(), anyString())).thenReturn(new Mission());
        when(pluginMissionApi.getAllMissions(anyBoolean(), anyBoolean(), anyString())).thenReturn(createMissionList());
        //accepts a standard read mission request and returns a blank sample mission
        when(pluginMissionApi.readMission("mission_from_plugin_1", true, false, null, null, null)).thenReturn(createMission());
        when(pluginDataFeedApi.getAllPluginDataFeeds()).thenReturn(createDatafeedList());

    }

    @Test
    public void createMissionShouldCallAPI() throws Exception
    {
        String missionName = "test mission";
        String description = "this is a test mission";
        String creatorUID = "mission_plugin_1";
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

        plugin.createMission(missionName, description);
        verify(pluginMissionApi, times(1)).createMission(missionName, creatorUID,
                groupNames, description, chatRoom, baseLayer,
                bbox, boundingPolygon, path, classification,
                tool, password, role, expiration, missionPackage);
    }

    @Test
    public void missionKeywordExampleShouldCallAPI()
    {
        plugin.missionKeywordExample();
        verify(pluginMissionApi, times(1)).setKeywords(anyString(), anyList(), anyString());
        verify(pluginMissionApi, times(1)).removeKeyword(anyString(), anyString(), anyString());
    }

    @Test
    public void queryDataFeedsShouldCallAPI()
    {
        plugin.queryDatafeeds();
        verify(pluginDataFeedApi, times(1)).getAllPluginDataFeeds();
    }

    @Test
    public void queryMissionShouldCallAPI() throws Exception
    {
        plugin.queryMissions();
        verify(pluginMissionApi, times(1)).getAllMissions(true, true, "public");
    }

    @Test
    public void setParentChildMissionShouldCallAPITwice() throws Exception
    {

        plugin.setParentChildMission("parent", "child");
        verify(pluginMissionApi, times(1)).setParent("child", "parent");
        verify(pluginMissionApi, times(1)).getParent("child");
        verify(pluginMissionApi, times(1)).getChildren("parent");
    }

    @Test
    public void mapLayerExampleShouldCallAPI() throws Exception
    {


        plugin.mapLayerExample();
        verify(pluginMissionApi, times(1)).createMapLayer(anyString(), anyString(), any(MapLayer.class));
        verify(pluginMissionApi, times(1)).updateMapLayer(anyString(), anyString(), any(MapLayer.class));
        verify(pluginMissionApi, times(1)).deleteMapLayer("mission_from_plugin_1", "mission_plugin_1", null);
    }

    @Test
    public void addMissionContentExampleShouldCallAPI() throws Exception
    {
        plugin.addMissionContentExample();
        verify(pluginMissionApi, times(1)).addMissionContent(anyString(), any(MissionContent.class), anyString());
    }

    @Test
    public void createDataFeedSample()
    {
        plugin.createDatafeedSample();
        verify(pluginDataFeedApi, times(1)).create(anyString(), anyString(), anyList(), anyBoolean(), anyBoolean());
        verify(pluginMissionApi, times(1)).addFeed("mission_from_plugin_1", "mission_plugin_1", "6749afe0-867b-44fa-ac87-a4d47e3a6b0f", null, null, null);
    }

    @Test
    public void startShouldNotThrowException()
    {
        plugin.start();
    }

    @Test
    public void stopShouldNotThrowException() throws Exception
    {
        when(pluginMissionApi.clearKeywords(anyString(), anyString())).thenReturn(createMission());
        when(pluginMissionApi.removeMissionContent("mission_from_plugin_1", "61b73917465b6fea39d69f45bc40e59c34c098d1b819697079cb8d913005b50a", null, CREATOR_UID)).thenReturn(createMission());

        plugin.stop();
        verify(pluginMissionApi, times(1)).removeFeed(anyString(), anyString(), anyString());
        verify(pluginMissionApi, times(1)).clearParent(anyString());
        verify(pluginMissionApi, times(1)).clearKeywords(anyString(), anyString());
        verify(pluginMissionApi, times(2)).deleteMission(anyString(), anyString(), anyBoolean());
        verify(pluginMissionApi, times(1)).getAllMissions(true, true, "public");
    }

    private Set<Mission> createMissionSet()
    {
        return Set.of(createMission(), createMission());
    }

    private List<Mission> createMissionList()
    {
        return List.of(createMission(), createMission(), createMission());
    }

    private Mission createMission()
    {
        return new Mission();
    }

    private PluginDataFeed createSampleDatafeed()
    {
        String uuid = "f0977622-c944-4fb2-9315-2e3e1a154890";
        String datafeedName = "testDataFeedFromPlugin1";
        List<String> groupNames = List.of("__ANON__");
        return new PluginDataFeed(uuid, datafeedName, List.of("sampleTag1", "sampleTag2"), false, false, groupNames, false);
    }

    private List<PluginDataFeed> createDatafeedList()
    {
        return List.of(createSampleDatafeed(), createSampleDatafeed(), createSampleDatafeed());
    }

    private MapLayer initSampleMapLayer() 
    {
        MapLayer mapLayer = new MapLayer();
        mapLayer.setName("mapLayerName1");
        mapLayer.setCreatorUid("test");
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
}