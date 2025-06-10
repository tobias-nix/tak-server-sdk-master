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
import static org.junit.Assert.assertNotSame;

@RunWith(MockitoJUnitRunner.class)
public class PeriodicMessageSenderPluginTest
{
    @InjectMocks
    PeriodicMessageSenderPlugin plugin = new PeriodicMessageSenderPlugin();

    @Spy
    MessageConverter converter = new MessageConverter();

    private static final String SA = "<event version=\"2.0\" uid=\"ANDROID-352413144215586\" type=\"a-f-G-U-C\" how=\"m-g\" time=\"2020-02-12T13:16:07Z\" start=\"2020-02-12T13:16:05Z\" stale=\"2020-02-12T13:16:50Z\"><point lat=\"40.255716\" lon=\"-72.045306\" hae=\"-22.22983896651138\" ce=\"4.9\" le=\"9999999.0\"/><detail><__group name=\"Dark Blue\" role=\"Team Member\"/><precisionlocation geopointsrc=\"GPS\" altsrc=\"GPS\"/><status battery=\"32\"/><takv device=\"SAMSUNG SM-G975U1\" platform=\"ATAK-CIV\" os=\"29\" version=\"3.12.0-45691.45691-CIV\"/><track speed=\"0.0\" course=\"344.72362164876733\"/><contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/></detail></event>";

    @Test
    public void startShouldRun()
    {
        plugin.start();
    }

    @Test
    public void generateMessageShouldChangeBattery() throws DocumentException
    {
        Message message = new MessageConverter().cotStringToDataMessage(SA, new HashSet<>(),
                Integer.toString(System.identityHashCode(plugin)));
        Message processedMessage = plugin.generateMessage(message);
        assertNotSame(message.getPayload().getCotEvent().getDetail().getXmlDetail(),
                processedMessage.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

    @Test
    public void generateMessageBatteryShouldBeOne() throws DocumentException
    {
        Message message = new MessageConverter().cotStringToDataMessage(SA, new HashSet<>(),
                Integer.toString(System.identityHashCode(plugin)));
        Message processedMessage = plugin.generateMessage(message);
        assertEquals("<contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/><messageCount>1</messageCount>",
                processedMessage.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

    @Test
    public void generateMessageCountShouldBeInOrder() throws DocumentException {
        Message message = new MessageConverter().cotStringToDataMessage(SA, new HashSet<>(),
                Integer.toString(System.identityHashCode(plugin)));
        Message processedMessage1 = plugin.generateMessage(message);
        Message processedMessage2 = plugin.generateMessage(message);
        assertEquals("<contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/><messageCount>1</messageCount>",
                processedMessage1.getPayload().getCotEvent().getDetail().getXmlDetail());
        assertEquals("<contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/><messageCount>2</messageCount>",
                processedMessage2.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

    @Test
    public void stopShouldRun()
    {
        plugin.start();
        plugin.stop();
    }
}