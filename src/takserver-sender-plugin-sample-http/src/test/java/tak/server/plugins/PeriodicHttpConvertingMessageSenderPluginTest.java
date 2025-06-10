package tak.server.plugins;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;
import org.dom4j.DocumentException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import tak.server.plugins.messaging.MessageConverter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(MockitoJUnitRunner.class)
public class PeriodicHttpConvertingMessageSenderPluginTest
{
    @InjectMocks @Spy
    PeriodicHttpConvertingMessageSenderPlugin plugin;

    @Spy
    MessageConverter converter;

    @Mock
    PluginConfiguration config;

    private static final String SA = "<event version=\"2.0\" uid=\"ANDROID-352413144215585\" type=\"a-f-G-U-C\" how=\"m-g\" time=\"2020-02-12T13:16:07Z\" start=\"2020-02-12T13:16:05Z\" stale=\"2020-02-12T13:16:50Z\"><point lat=\"40.255716\" lon=\"-72.045306\" hae=\"-22.22983896651138\" ce=\"4.9\" le=\"9999999.0\"/><detail></detail></event>";

    private List<Map<String, Map<String, List<String>>>> targets;

    @Before
    public void startUp()
    {
        targets = new ArrayList<>();
        addTarget();
    }

    @Test
    public void startShouldNotThrowException()
    {
        plugin.start();
    }

    @Test
    public void createClientShouldNotThrowException() throws DocumentException
    {
        AtomicInteger count = new AtomicInteger();
        MessageConverter messageConverter = new MessageConverter();
        Message message = messageConverter.cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(this)));
        plugin.createClient(message, count);
    }

    @Test
    public void injectXmlDetailShouldReturnValidMessage() throws DocumentException
    {
        AtomicInteger count = new AtomicInteger();
        MessageConverter messageConverter = new MessageConverter();
        Message message = plugin.injectXmlDetail(messageConverter.cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(plugin))), count);
        assertEquals("<messageCount>1</messageCount>", message.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

    @Test
    public void injectXmlDetailShouldBeInOrder() throws DocumentException
    {
        AtomicInteger count = new AtomicInteger();
        MessageConverter messageConverter = new MessageConverter();
        Message message1 = plugin.injectXmlDetail(messageConverter.cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(plugin))), count);
        Message message2 = plugin.injectXmlDetail(messageConverter.cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(plugin))), count);
        assertEquals("<messageCount>1</messageCount>", message1.getPayload().getCotEvent().getDetail().getXmlDetail());
        assertEquals("<messageCount>2</messageCount>", message2.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

    @Test
    public void parseTargetsIntoList()
    {
        List<PeriodicHttpConvertingMessageSenderPlugin.HttpTarget> httpTargets = plugin.parseTargetsIntoList(targets);
        assertEquals(1, httpTargets.size());
        assertEquals("httpbin.org", httpTargets.get(0).getAddress());
        assertEquals(Arrays.asList("/", "/ip", "/user-agent", "headers"), httpTargets.get(0).getUris());
    }

    @Test
    public void parseTargetsIntoListShouldContainTwoTargets()
    {
        addTarget();
        List<PeriodicHttpConvertingMessageSenderPlugin.HttpTarget> httpTargets = plugin.parseTargetsIntoList(targets);
        assertEquals(2, httpTargets.size());
    }

    @Test
    public void getTargetInfoShouldNotBeNull()
    {
        List<PeriodicHttpConvertingMessageSenderPlugin.HttpTarget> httpTargets = plugin.parseTargetsIntoList(targets);
        assertNotNull(httpTargets.get(0));
    }

    @Test
    public void targetShouldHaveAddress()
    {
        List<PeriodicHttpConvertingMessageSenderPlugin.HttpTarget> httpTargets = plugin.parseTargetsIntoList(targets);
        assertEquals("httpbin.org", httpTargets.get(0).getAddress());
    }

    @Test
    public void targetShouldHaveUris()
    {
        List<PeriodicHttpConvertingMessageSenderPlugin.HttpTarget> httpTargets = plugin.parseTargetsIntoList(targets);
        List<String> expectedList = Arrays.asList("/", "/ip", "/user-agent", "headers");
        assertEquals(expectedList, httpTargets.get(0).getUris());
    }

    private void addTarget()
    {
        List<String> uris = Arrays.asList("/", "/ip", "/user-agent", "headers");
        Map<String, List<String>> info = new HashMap<>();
        info.put("uris", uris);
        Map<String, Map<String, List<String>>> http = new HashMap<>();
        http.put("httpbin.org", info);
        targets.add(http);
    }
}