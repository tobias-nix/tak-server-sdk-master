package tak.server.plugins;

import com.bbn.marti.sync.Metadata;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class FileUploadListenerPluginTest
{
    @InjectMocks
    FileUploadListenerPlugin plugin = new FileUploadListenerPlugin();

    @Mock
    PluginFileApi pluginFileApi;

    @Test
    public void startShouldNotThrowException()
    {
        plugin.start();
    }

    @Test
    public void stopShouldNotThrowException()
    {
        plugin.stop();
    }

    @Test
    public void onFileUploadEventShouldCatchException()
    {
        Metadata metadata = createFileMetadata("testFilePlugin", null, "text/plain",
                "tak.server.plugins.FileUploadListenerPlugin", "creatorPluginTest1",
                0.1, -0.1, "ExCheck");
        plugin.onFileUploadEvent(metadata);
    }

    private Metadata createFileMetadata(String id, String[] keywords, String mimeType, String pluginClassName, String creatorId,
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
}