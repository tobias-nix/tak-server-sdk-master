package tak.server.plugins;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;
import org.dom4j.DocumentException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import tak.server.plugins.messaging.MessageConverter;

import java.util.HashSet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class MessageForwarderPluginTest {

    @InjectMocks @Spy
    MessageForwarderPlugin plugin;
    @Spy
    MessageConverter converter = new MessageConverter();

    MessageConverter messageConverter = new MessageConverter();

    private static final String SA = "<event version=\"2.0\" uid=\"ANDROID-352413144215585\" type=\"a-f-G-U-C\" how=\"m-g\" time=\"2020-02-12T13:16:07Z\" start=\"2020-02-12T13:16:05Z\" stale=\"2020-02-12T13:16:50Z\"><point lat=\"40.255716\" lon=\"-72.045306\" hae=\"-22.22983896651138\" ce=\"4.9\" le=\"9999999.0\"/><detail><__group name=\"Dark Blue\" role=\"Team Member\"/><precisionlocation geopointsrc=\"GPS\" altsrc=\"GPS\"/><status battery=\"32\"/><takv device=\"SAMSUNG SM-G975U1\" platform=\"ATAK-CIV\" os=\"29\" version=\"3.12.0-45691.45691-CIV\"/><track speed=\"0.0\" course=\"344.72362164876733\"/><contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/></detail></event>";

    @Test
    public void startShouldGenerateMessage() throws DocumentException
    {
        plugin.onMessage(messageConverter.cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(plugin))));
        plugin.start();
        verify(plugin, times(1)).generateMessage(any(Message.class));
    }

    @Test
    public void generateMessageShouldReturnValidMessageWithCount() throws DocumentException {
        Message message = plugin.generateMessage(converter.cotStringToDataMessage(SA, new HashSet<>(),
                Integer.toString(System.identityHashCode(plugin))));
        assertNotNull(message);
        assertEquals("<contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/><messageCount>1</messageCount>",
                message.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

    @Test
    public void generateMessageShouldReturnCountInOrder() throws DocumentException {
        Message message1 = plugin.generateMessage(converter.cotStringToDataMessage(SA, new HashSet<>(),
                Integer.toString(System.identityHashCode(plugin))));
        Message message2 = plugin.generateMessage(converter.cotStringToDataMessage(SA, new HashSet<>(),
                Integer.toString(System.identityHashCode(plugin))));
        assertEquals("<contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/><messageCount>1</messageCount>",
                message1.getPayload().getCotEvent().getDetail().getXmlDetail());
        assertEquals("<contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/><messageCount>2</messageCount>",
                message2.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

}