package tak.server.plugins;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;
import org.dom4j.DocumentException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import tak.server.plugins.messaging.MessageConverter;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class DataFeedMessageSenderPluginTest
{

    private static final String SA = "<event version=\"2.0\" uid=\"ANDROID-352413144215585\" type=\"a-f-G-U-C\" how=\"m-g\" time=\"2020-02-12T13:16:07Z\" start=\"2020-02-12T13:16:05Z\" stale=\"2020-02-12T13:16:50Z\"><point lat=\"40.255716\" lon=\"-72.045306\" hae=\"-22.22983896651138\" ce=\"4.9\" le=\"9999999.0\"/><detail><__group name=\"Dark Blue\" role=\"Team Member\"/><precisionlocation geopointsrc=\"GPS\" altsrc=\"GPS\"/><status battery=\"32\"/><takv device=\"SAMSUNG SM-G975U1\" platform=\"ATAK-CIV\" os=\"29\" version=\"3.12.0-45691.45691-CIV\"/><track speed=\"0.0\" course=\"344.72362164876733\"/><contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/></detail></event>";

    @Mock
    PluginDataFeedApi pluginDataFeedApi;

    @Mock
    MessageConverter converter;

    @InjectMocks
    DataFeedMessageSenderPlugin plugin = new DataFeedMessageSenderPlugin();

    @Before
    public void beforeTest()
    {
        when(pluginDataFeedApi.create(anyString(), anyString(), anyList(), anyBoolean(), anyBoolean(), anyList())).thenReturn(createSampleDatafeed());
        when(pluginDataFeedApi.getAllPluginDataFeeds()).thenReturn(createDatafeedList());
    }

    @Test
    public void startShouldNotThrowException()
    {
        plugin.start();
    }

    @Test
    public void createSampleDataFeedsShouldCallAPIThreeTimes()
    {
        plugin.createSampleDataFeeds();
        verify(pluginDataFeedApi, times(3)).create(anyString(), anyString(), anyList(), anyBoolean(), anyBoolean(), anyList());
    }

    @Test
    public void queryAllDataFeedsShouldCallApi()
    {
        plugin.queryAllDataFeeds();
        verify(pluginDataFeedApi, times(1)).getAllPluginDataFeeds();
    }

    @Test
    public void injectXmlDetailShouldReturnMessageWithDetail() throws DocumentException
    {
        AtomicInteger count = new AtomicInteger();
        Message message = plugin.injectXmlDetail(createMessage(), count);
        String expectedReturn = "<contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/><messageCount>1</messageCount>";
        assertEquals(expectedReturn, message.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

    @Test
    public void injectXmlDetailShouldReturnMessageWithDifferentCountInDetail() throws DocumentException
    {
        AtomicInteger count = new AtomicInteger();
        Message firstMessage = plugin.injectXmlDetail(createMessage(), count);
        Message secondMessage = plugin.injectXmlDetail(createMessage(), count);

        assertNotSame(secondMessage.getPayload().getCotEvent().getDetail().getXmlDetail(), firstMessage.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

    @Test
    public void stopShouldNotThrowException()
    {
        plugin.stop();
    }

    private PluginDataFeed createSampleDatafeed()
    {
        String uuid = "f0977622-c944-4fb2-9315-2e3e1a154890";
        String datafeedName = "testDataFeedFromPlugin1";
        List<String> groupNames = List.of("__ANON__");
        List<String> tags = new ArrayList<>();
        tags.add("sampleTag1");
        tags.add("sampleTag2");
        return new PluginDataFeed(uuid, datafeedName, tags, false, false, groupNames, false);
    }

    private List<PluginDataFeed> createDatafeedList()
    {
        List<PluginDataFeed> pluginDataFeedList = new ArrayList<>();
        pluginDataFeedList.add(createSampleDatafeed());
        pluginDataFeedList.add(createSampleDatafeed());
        pluginDataFeedList.add(createSampleDatafeed());
        return pluginDataFeedList;
    }

    private Message createMessage() throws DocumentException
    {
        return new MessageConverter().cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(this)));
    }
}