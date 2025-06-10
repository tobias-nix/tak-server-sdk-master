package tak.server.plugins;

import com.bbn.marti.sync.Metadata;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class FilePluginTest {

    @InjectMocks
    FilePlugin filePlugin = new FilePlugin();

    @Mock
    PluginFileApi pluginFileApi;
    String testHash = "101AB";

    @Before
    public void setUpPluginAPI() throws Exception {
        List<Metadata> testList = new ArrayList<>();
        testList.add(createGoodFileWithContent());

        String fileContent = "This is a dummy file content";
        InputStream inputStream = new ByteArrayInputStream(fileContent.getBytes(StandardCharsets.UTF_8));

        when(pluginFileApi.newFile(any(Metadata.class), any(InputStream.class))).thenReturn(createGoodFileWithContent());
        when(pluginFileApi.readFileContent(testHash)).thenReturn(inputStream);
        when(pluginFileApi.getMetadataByHash(testHash)).thenReturn(testList);
    }

    @Before
    public void setSearchStubbing() throws Exception {
        Map<Metadata.Field, String> metadataConstraints = new EnumMap<>(Metadata.Field.class);
        metadataConstraints.put(Metadata.Field.MIMEType,  "text/plain");

        SortedMap<String, List<Metadata>> searchResult = new TreeMap<>();
        List<Metadata> testList = new ArrayList<>();
        testList.add(createGoodFileWithContent());
        searchResult.put(testHash, testList);

        when(pluginFileApi.search(null, null, metadataConstraints,
                null, null, null, null, false, null, "ExCheck")).thenReturn(searchResult);
    }

    @Test
    public void startShouldUseValidMetadataAndInputSteam() throws Exception {
        filePlugin.start();
        verify(pluginFileApi).newFile(any(Metadata.class), any(InputStream.class));
    }

    @Test
    public void startShouldUseValidHash() throws Exception {
        filePlugin.start();
        verify(pluginFileApi).readFileContent(testHash);
    }

    @Test
    public void stopShouldCallDelete() throws Exception
    {
        filePlugin.start();
        filePlugin.stop();
        verify(pluginFileApi, times(1)).deleteFile(testHash);
    }

    @Test
    public void stopShouldCatchException()
    {
        filePlugin.stop();
    }

    private Metadata createGoodFileWithContent()
    {
        Metadata metadata = new Metadata();
        String id = "testFilePlugin";
        metadata.set(Metadata.Field.DownloadPath, id + ".txt");
        metadata.set(Metadata.Field.Name, id);
        metadata.set(Metadata.Field.MIMEType, "text/plain");
        metadata.set(Metadata.Field.UID, new String[]{id});
        metadata.set(Metadata.Field.PluginClassName, "tak.server.plugins.FileUploadListenerPlugin");
        metadata.set(Metadata.Field.CreatorUid, "creatorPluginTest1");
        metadata.set(Metadata.Field.Latitude, "0.1");
        metadata.set(Metadata.Field.Longitude, -0.1);
        metadata.set(Metadata.Field.Hash, testHash);

        metadata.set(Metadata.Field.Tool, "ExCheck");
        return metadata;
    }
}