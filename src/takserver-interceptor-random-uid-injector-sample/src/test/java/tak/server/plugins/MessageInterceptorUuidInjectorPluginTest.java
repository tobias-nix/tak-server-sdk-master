package tak.server.plugins;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass;
import org.dom4j.DocumentException;
import org.junit.Test;
import tak.server.plugins.messaging.MessageConverter;

import java.util.HashSet;

import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

public class MessageInterceptorUuidInjectorPluginTest {

    MessageInterceptorUuidInjectorPlugin plugin = new MessageInterceptorUuidInjectorPlugin();

    private final MessageConverter converter = new MessageConverter();

    private static final String SA = "<event version=\"2.0\" uid=\"ANDROID-352413144215585\" type=\"a-f-G-U-C\" " +
            "how=\"m-g\" time=\"2020-02-12T13:16:07Z\" start=\"2020-02-12T13:16:05Z\" stale=\"2020-02-12T13:16:50Z\">" +
            "<point lat=\"40.255716\" lon=\"-72.045306\" hae=\"-22.22983896651138\" ce=\"4.9\" le=\"9999999.0\"/><detail>" +
            "</detail></event>";

    @Test
    public void interceptShouldReturnValidUuid() throws DocumentException {
        MessageOuterClass.Message message = plugin.intercept(createMessage());
        assertTrue(message.getPayload().getCotEvent().getDetail().getXmlDetail().matches("^<myUuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}</myUuid>$"));
    }

    @Test
    public void interceptShouldReturnDifferentUuid() throws DocumentException {
        MessageOuterClass.Message firstMessage = plugin.intercept(createMessage());
        MessageOuterClass.Message secondMessage = plugin.intercept(createMessage());

        assertNotSame(secondMessage.getPayload().getCotEvent().getDetail().getXmlDetail(), firstMessage.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

    private MessageOuterClass.Message createMessage() throws DocumentException {
        return converter.cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(this)));
    }
}