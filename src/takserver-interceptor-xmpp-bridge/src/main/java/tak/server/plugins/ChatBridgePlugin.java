package tak.server.plugins;

import atakmap.commoncommo.protobuf.v1.MessageOuterClass.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.jivesoftware.smack.AbstractXMPPConnection;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.StanzaListener;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.chat2.ChatManager;
import org.jivesoftware.smack.chat2.IncomingChatMessageListener;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.roster.Roster;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.jxmpp.jid.EntityBareJid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.stringprep.XmppStringprepException;

import tak.server.cot.CotEventContainer;
import tak.server.proto.StreamingProtoBufHelper;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Plugin that intercepts chat messages and forwards them to an XMPP server.
 */
@TakServerPlugin(name="Chat Bridge Plugin", description="This plugin forwards TAK chat messages to XMPP server")
public class ChatBridgePlugin extends MessageInterceptorBase {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    
    private String xmppHost;
    private String xmppUser;
    private String xmppPassword;
    private String xmppRecipient;
    private boolean useTls = true;
    private boolean ignoreCertErrors = false;
    private boolean logChatContents = false;
    private int xmppPort = 5222;
    
    // Neues Feld für den Interface-User
    private String interfaceUser;
    
    private AbstractXMPPConnection xmppConnection;
    private ChatManager chatManager;

    @SuppressWarnings("unchecked")
    public ChatBridgePlugin() {
        // Load configuration from YAML file
        if (config.containsProperty("xmppHost")) {
            xmppHost = (String) config.getProperty("xmppHost");
        }
        if (config.containsProperty("xmppUser")) {
            xmppUser = (String) config.getProperty("xmppUser");
        }
        if (config.containsProperty("xmppPassword")) {
            xmppPassword = (String) config.getProperty("xmppPassword");
        }
        if (config.containsProperty("xmppRecipient")) {
            xmppRecipient = (String) config.getProperty("xmppRecipient");
        }
        if (config.containsProperty("xmppPort")) {
            xmppPort = (int) config.getProperty("xmppPort");
        }
        if (config.containsProperty("useTls")) {
            useTls = (boolean) config.getProperty("useTls");
        }
        if (config.containsProperty("ignoreCertErrors")) {
            ignoreCertErrors = (boolean) config.getProperty("ignoreCertErrors");
        }
        if (config.containsProperty("logChatContents")) {
            logChatContents = (boolean) config.getProperty("logChatContents");
        }
        // Lese den neuen Parameter für den Interface User
        if (config.containsProperty("interfaceUser")) {
            interfaceUser = (String) config.getProperty("interfaceUser");
        }

        logger.info("ChatBridgePlugin initialized with config: xmppHost={}, xmppUser={}, xmppRecipient={}, xmppPort={}, interfaceUser={}",
                xmppHost, xmppUser, xmppRecipient, xmppPort, interfaceUser);
    }

    @Override
    public void start() {
        logger.info("Starting {}", getClass().getName());
        
        if (xmppHost == null || xmppUser == null || xmppPassword == null || xmppRecipient == null) {
            logger.error("ChatBridgePlugin configuration incomplete. Required: xmppHost, xmppUser, xmppPassword, xmppRecipient");
            return;
        }
        
        try {
            connectToXmpp();
            logger.info("Successfully connected to XMPP server: {}", xmppHost);
        } catch (Exception e) {
            logger.error("Failed to connect to XMPP server", e);
        }
    }

    @Override
    public Message intercept(Message message) {
        try {
            // Extract CoT XML from the message
            CotEventContainer cotEvent = StreamingProtoBufHelper.proto2cot(message.getPayload());
            String cotXml = cotEvent.asXml();
            
            // Check if this is a chat message
            if (cotXml.contains("<__chat") || cotXml.contains("<chat")) {
                String chatText = extractChatText(cotXml);
                String callsign = extractCallsign(cotXml);
                // Extrahiere den Zielnutzer aus dem CoT XML
                String recipient = extractRecipient(cotXml);
                
                // Nur weiterleiten, wenn der Empfänger dem definierten Interface User entspricht
                if (recipient != null && recipient.equals(interfaceUser)) {
                    if (chatText != null && callsign != null) {
                        if (logChatContents) {
                            logger.info("Intercepted chat message from {} to {}: {}", callsign, recipient, chatText);
                        } else {
                            logger.info("Intercepted chat message from {} to {}", callsign, recipient);
                        }
                        
                        // Forward to XMPP
                        forwardToXmpp(callsign, chatText);
                    }
                } else {
                    logger.debug("Nachricht nicht für Interface User (gefunden: {}) - wird nicht weitergeleitet", recipient);
                }
            }
        } catch (Exception e) {
            logger.error("Error processing intercepted message", e);
        }
        
        // Return the original message unchanged
        return message;
    }

    private String extractChatText(String cotXml) {
        // Regular expression to extract chat text from CoT XML
        Pattern pattern = Pattern.compile("(?:<chat|<__chat).*?>(.*?)<");
        Matcher matcher = pattern.matcher(cotXml);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
    
    private String extractCallsign(String cotXml) {
        // Extract callsign from the CoT XML
        Pattern pattern = Pattern.compile("<contact.*?callsign=\"(.*?)\"");
        Matcher matcher = pattern.matcher(cotXml);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "Unknown";
    }
    
    // Neue Methode: Extrahiere den Empfänger aus dem Chat-Element
    private String extractRecipient(String cotXml) {
        Pattern pattern = Pattern.compile("<(?:chat|__chat)[^>]*?to\\s*=\\s*\"(.*?)\"");
        Matcher matcher = pattern.matcher(cotXml);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
    
    private void forwardToXmpp(String callsign, String chatText) {
        if (xmppConnection == null || !xmppConnection.isConnected()) {
            logger.warn("XMPP connection not active, reconnecting...");
            try {
                connectToXmpp();
            } catch (Exception e) {
                logger.error("Failed to reconnect to XMPP server", e);
                return;
            }
        }
        
        try {
            EntityBareJid jid = JidCreate.entityBareFrom(xmppRecipient);
            chatManager.chatWith(jid).send("[TAK] " + callsign + ": " + chatText);
            logger.info("Successfully forwarded message to XMPP recipient {}", xmppRecipient);
        } catch (Exception e) {
            logger.error("Failed to send message to XMPP", e);
        }
    }
    
    private void connectToXmpp() throws XmppStringprepException, XMPPException, SmackException, IOException, InterruptedException {
        XMPPTCPConnectionConfiguration.Builder configBuilder = XMPPTCPConnectionConfiguration.builder()
            .setHost(xmppHost)
            .setPort(xmppPort)
            .setUsernameAndPassword(xmppUser, xmppPassword)
            .setXmppDomain(xmppHost)
            .setResource("TAKServer")
            .setSendPresence(true);
        
        if (ignoreCertErrors) {
            try {
                // Create a trust manager that does not validate certificate chains
                TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                    }
                };

                // Install the all-trusting trust manager
                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(null, trustAllCerts, new SecureRandom());
                
                configBuilder.setCustomSSLContext(sc)
                    .setHostnameVerifier(new HostnameVerifier() {
                        @Override
                        public boolean verify(String hostname, SSLSession session) {
                            return true;
                        }
                    });
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                logger.error("Error setting up SSL trust manager", e);
            }
        }
        
        if (!useTls) {
            configBuilder.setSecurityMode(ConnectionConfiguration.SecurityMode.disabled);
        }
        
        xmppConnection = new XMPPTCPConnection(configBuilder.build());
        xmppConnection.connect();
        xmppConnection.login();
        
        // Get chat manager for sending messages
        chatManager = ChatManager.getInstanceFor(xmppConnection);
        
        // Set presence to available
        Presence presence = new Presence(Presence.Type.available);
        presence.setStatus("TAK Server Bridge Online");
        xmppConnection.sendStanza(presence);
    }

    @Override
    public void stop() {
        logger.info("Stopping ChatBridgePlugin");
        if (xmppConnection != null && xmppConnection.isConnected()) {
            xmppConnection.disconnect();
        }
    }
}