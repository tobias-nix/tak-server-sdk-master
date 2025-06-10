package tak.server.plugins;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;
import org.dom4j.DocumentException;
import org.junit.Test;
import tak.server.plugins.messaging.MessageConverter;

import java.util.HashSet;

import static org.junit.Assert.*;

public class MessageInterceptorCounterPluginTest {

    private final MessageInterceptorCounterPlugin plugin = new MessageInterceptorCounterPlugin();

    private final MessageConverter converter = new MessageConverter();

    private static final String SA = "<event version=\"2.0\" uid=\"ANDROID-352413144215585\" type=\"a-f-G-U-C\" " +
            "how=\"m-g\" time=\"2020-02-12T13:16:07Z\" start=\"2020-02-12T13:16:05Z\" stale=\"2020-02-12T13:16:50Z\">" +
            "<point lat=\"40.255716\" lon=\"-72.045306\" hae=\"-22.22983896651138\" ce=\"4.9\" le=\"9999999.0\"/><detail>" +
            "</detail></event>";

    @Test
    public void interceptShouldReturnValidMessageCount() throws DocumentException {
        Message message = plugin.intercept(createMessage());

        assertEquals("<messageCount>1</messageCount>", message.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

    @Test
    public void interceptShouldReturnMessageCountOneThenTwo() throws DocumentException {
        Message firstMessage = plugin.intercept(createMessage());
        Message secondMessage = plugin.intercept(createMessage());

        assertEquals("<messageCount>1</messageCount>", firstMessage.getPayload().getCotEvent().getDetail().getXmlDetail());
        assertEquals("<messageCount>2</messageCount>", secondMessage.getPayload().getCotEvent().getDetail().getXmlDetail());
    }

    @Test(expected = NullPointerException.class)
    public void interceptNullMessageShouldThrowException() {
        plugin.intercept(null);
    }

    private Message createMessage() throws DocumentException {
        return converter.cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(this)));
    }
}