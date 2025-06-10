package tak.server.plugins;

import org.dom4j.DocumentException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import tak.server.plugins.messaging.MessageConverter;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SubmitDataPluginTest
{
    @InjectMocks
    SubmitDataPlugin plugin = new SubmitDataPlugin();

    private static final String APPLICATION_JSON = "application/json";
    private static final String APPLICATION_XML = "application/xml";

    private static final String SA = "<event version=\"2.0\" uid=\"ANDROID-352413144215585\" type=\"a-f-G-U-C\" how=\"m-g\" time=\"2020-02-12T13:16:07Z\" start=\"2020-02-12T13:16:05Z\" stale=\"2020-02-12T13:16:50Z\"><point lat=\"40.255716\" lon=\"-72.045306\" hae=\"-22.22983896651138\" ce=\"4.9\" le=\"9999999.0\"/><detail><__group name=\"Dark Blue\" role=\"Team Member\"/><precisionlocation geopointsrc=\"GPS\" altsrc=\"GPS\"/><status battery=\"32\"/><takv device=\"SAMSUNG SM-G975U1\" platform=\"ATAK-CIV\" os=\"29\" version=\"3.12.0-45691.45691-CIV\"/><track speed=\"0.0\" course=\"344.72362164876733\"/><contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/></detail></event>";

    private static final String SA_MODIFIED = "<event version=\"2.0\" uid=\"ANDROID-352413144215585\" type=\"a-f-G-U-C\" how=\"m-g\" time=\"2020-02-12T13:16:07Z\" start=\"2020-02-12T13:16:05Z\" stale=\"2020-02-12T13:16:50Z\"><point lat=\"40.255716\" lon=\"-72.045306\" hae=\"-22.22983896651138\" ce=\"4.9\" le=\"9999999.0\"/><detail><__group name=\"Dark Blue\" role=\"Team Member\"/><precisionlocation geopointsrc=\"GPS\" altsrc=\"GPS\"/><status battery=\"32\"/><takv device=\"SAMSUNG SM-G975U1\" platform=\"ATAK-CIV\" os=\"29\" version=\"3.12.0-45691.45691-CIV\"/><track speed=\"0.0\" course=\"324.72362164876733\"/><contact endpoint=\"*:-1:stcp\" phone=\"19999999999\" callsign=\"coolata\"/><uid Droid=\"coolata\"/></detail></event>";
    @Mock
    MessageConverter converter;
    private final Map<String, String> requestParams = new HashMap<>();

    @Before
    public void configurePlugin() throws DocumentException
    {
        when(converter.cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(plugin)))).thenReturn(
                new MessageConverter().cotStringToDataMessage(SA, new HashSet<>(),
                        Integer.toString(System.identityHashCode(plugin))));
        when(converter.cotStringToDataMessage(SA_MODIFIED, new HashSet<>(), Integer.toString(System.identityHashCode(plugin)))).thenReturn(
                new MessageConverter().cotStringToDataMessage(SA_MODIFIED, new HashSet<>(),
                        Integer.toString(System.identityHashCode(plugin))));
        requestParams.put("scope", "test");
    }

    @Test
    public void startShouldRun()
    {
        plugin.start();
    }

    @Test
    public void onSubmitDataShouldNotBeNull()
    {
        plugin.onSubmitData(requestParams, SA, APPLICATION_XML);
        assertNotNull(plugin.getScopeDataMap().get("test"));
    }

    @Test
    public void onSubmitDataShouldCatchException() throws DocumentException
    {
        when(converter.cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(plugin)))).thenThrow(new DocumentException());
        plugin.onSubmitData(requestParams, SA, APPLICATION_XML);
    }

    @Test
    public void onSubmitDataWithResultShouldReturnResult()
    {
        PluginResponse result = plugin.onSubmitDataWithResult(requestParams, SA, APPLICATION_XML);
        assertNotNull(result);
    }

    @Test
    public void onSubmitDataWithResultShouldSetContentJSON()
    {
        PluginResponse result = plugin.onSubmitDataWithResult(requestParams, SA, APPLICATION_JSON);
        assertEquals(APPLICATION_JSON, result.getContentType());
    }

    @Test
    public void onSubmitDataWithResultShouldCatchException() throws DocumentException
    {
        when(converter.cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(plugin)))).thenThrow(new DocumentException());
        plugin.onSubmitDataWithResult(requestParams, SA, APPLICATION_XML);
    }

    @Test
    public void onUpdateDataShouldModifyMap()
    {
        plugin.onSubmitData(requestParams, SA, APPLICATION_XML);
        Map<String, String> expectedParams = new HashMap<>();
        expectedParams.put("scope", "expected");
        plugin.onSubmitData(expectedParams, SA_MODIFIED, APPLICATION_XML);

        plugin.onUpdateData(requestParams, SA_MODIFIED, APPLICATION_XML);
        assertEquals(plugin.getScopeDataMap().get("expected"), plugin.getScopeDataMap().get("test"));
    }

    @Test
    public void onUpdateDataShouldCatchException() throws DocumentException
    {
        when(converter.cotStringToDataMessage(SA, new HashSet<>(), Integer.toString(System.identityHashCode(plugin)))).thenThrow(new DocumentException());
        plugin.onUpdateData(requestParams, SA, APPLICATION_XML);
    }

    @Test
    public void onUpdateDataWithNonMatchingDataShouldNotThrowException()
    {
        plugin.onUpdateData(requestParams, SA, APPLICATION_XML);
        assertNull(plugin.getScopeDataMap());
    }

    @Test
    public void onRequestDataShouldReturnData()
    {
        plugin.onSubmitData(requestParams, SA, APPLICATION_XML);
        PluginResponse response = plugin.onRequestData(requestParams, APPLICATION_XML);
        assertEquals(plugin.getScopeDataMap().get("test"), response.getData());
    }

    @Test
    public void onRequestDataShouldReturnContentTypeJSON()
    {
        plugin.onSubmitData(requestParams, SA, APPLICATION_XML);
        PluginResponse response = plugin.onRequestData(requestParams, APPLICATION_JSON);
        assertEquals(APPLICATION_JSON, response.getContentType());
    }

    @Test
    public void onRequestDataEmptyMapShouldCatchException()
    {
        plugin.onRequestData(requestParams, APPLICATION_XML);
    }

    @Test
    public void onDeleteData()
    {
        plugin.onSubmitData(requestParams, SA, APPLICATION_XML);
        plugin.onDeleteData(requestParams, APPLICATION_XML);
        assertNull(plugin.getScopeDataMap().get("test"));
    }

    @Test
    public void onDeleteDataShouldCatchException()
    {
        Map<String, String> deleteParams = new HashMap<>();
        deleteParams.put("scope", "delete");
        plugin.onDeleteData(deleteParams, APPLICATION_XML);
    }

    @Test
    public void checkDataShouldReturnTrue() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckDataMethod();
        Object[] methodArguments = {"this is test data"};
        submitDataPlugin.setScopeDataMap(new ConcurrentHashMap<>());
        submitDataPlugin.getScopeDataMap().put("testscope", "this is a test");
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertFalse(output);
    }

    @Test
    public void checkDataNullDataShouldReturnFalse() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckDataMethod();
        Object[] methodArguments = {null};
        submitDataPlugin.setScopeDataMap(new ConcurrentHashMap<>());
        submitDataPlugin.getScopeDataMap().put("testscope", "this is a test");
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertTrue(output);
    }

    @Test
    public void checkDataEmptyDataShouldReturnFalse() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckDataMethod();
        Object[] methodArguments = {""};
        submitDataPlugin.setScopeDataMap(new ConcurrentHashMap<>());
        submitDataPlugin.getScopeDataMap().put("testscope", "this is a test");
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertTrue(output);
    }
    @Test
    public void checkScopeShouldReturnTrue() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckScopeMethod();
        Object[] methodArguments = {"testscope"};
        submitDataPlugin.setScopeDataMap(new ConcurrentHashMap<>());
        submitDataPlugin.getScopeDataMap().put("testscope", "this is a test");
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertFalse(output);
    }

    @Test
    public void checkScopeEmptyDataMapShouldBeFalse() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckScopeMethod();
        Object[] methodArguments = {"testscope"};
        submitDataPlugin.setScopeDataMap(new ConcurrentHashMap<>());
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertTrue(output);
    }

    @Test
    public void checkScopeNullDataMapShouldBeFalse() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckScopeMethod();
        Object[] methodArguments = {"testscope"};
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertTrue(output);
    }
    @Test
    public void checkValidParametersShouldReturnTrue() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckValidParametersMethod();
        HashMap<String, String> testMap = new HashMap<>();
        testMap.put("scope", "testscope");
        Object[] methodArguments = {testMap, APPLICATION_XML};
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertFalse(output);
    }

    @Test
    public void checkValidParametersEmptyRequestParamsShouldBeFalse() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckValidParametersMethod();
        HashMap<String, String> testMap = new HashMap<>();
        Object[] methodArguments = {testMap, APPLICATION_XML};
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertTrue(output);
    }

    @Test
    public void checkValidParametersNullRequestParamsShouldBeFalse() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckValidParametersMethod();
        Object[] methodArguments = {null, APPLICATION_XML};
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertTrue(output);
    }

    @Test
    public void checkValidParametersBlankRequestParamsShouldBeFalse() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckValidParametersMethod();
        HashMap<String, String> testMap = new HashMap<>();
        testMap.put("", "");
        Object[] methodArguments = {testMap, APPLICATION_XML};
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertTrue(output);
    }

    @Test
    public void checkValidParametersEmptyContentType() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckValidParametersMethod();
        HashMap<String, String> testMap = new HashMap<>();
        testMap.put("scope", "testscope");
        Object[] methodArguments = {testMap, ""};
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertTrue(output);
    }

    @Test
    public void checkValidParametersNullContentType() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckValidParametersMethod();
        HashMap<String, String> testMap = new HashMap<>();
        testMap.put("scope", "testscope");
        Object[] methodArguments = {testMap, null};
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertTrue(output);
    }

    @Test
    public void checkValidParametersNoScopeShouldBeFalse() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        SubmitDataPlugin submitDataPlugin = new SubmitDataPlugin();
        Method method = generateCheckValidParametersMethod();
        HashMap<String, String> testMap = new HashMap<>();
        testMap.put("", "testscope");
        Object[] methodArguments = {testMap, APPLICATION_XML};
        boolean output = (boolean)method.invoke(submitDataPlugin, methodArguments);
        assertTrue(output);
    }

    @Test
    public void stopShouldRun()
    {
        plugin.stop();
    }

    public Method generateCheckValidParametersMethod() throws NoSuchMethodException {
        Method method = SubmitDataPlugin.class.getDeclaredMethod("checkValidParameters", Map.class, String.class);
        method.setAccessible(true);
        return method;
    }

    public Method generateCheckScopeMethod() throws NoSuchMethodException {
        Method method = SubmitDataPlugin.class.getDeclaredMethod("checkScope", String.class);
        method.setAccessible(true);
        return method;
    }

    public Method generateCheckDataMethod() throws NoSuchMethodException {
        Method method = SubmitDataPlugin.class.getDeclaredMethod("checkData", String.class);
        method.setAccessible(true);
        return method;
    }

}