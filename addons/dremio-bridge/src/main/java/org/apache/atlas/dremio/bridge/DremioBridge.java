package org.apache.atlas.dremio.bridge;

import com.dremio.common.utils.PathUtils;
import com.google.common.base.Function;
import com.google.common.collect.FluentIterable;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.atlas.ApplicationProperties;
import org.apache.atlas.AtlasClientV2;
import org.apache.atlas.AtlasServiceException;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.type.AtlasTypeUtil;
import org.apache.atlas.utils.AuthenticationUtil;
import org.apache.commons.cli.*;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DremioBridge {
    private static final Logger LOG = LoggerFactory.getLogger(DremioBridge.class);

    private static final int  EXIT_CODE_SUCCESS = 0;
    private static final int  EXIT_CODE_FAILED  = 1;
    private static final String DEFAULT_ATLAS_URL = "http://192.168.106.104:21000/";
    public static final String ATLAS_ENDPOINT  = "atlas.rest.address";
    private static final String DEFAULT_DREMIO_URL = "http://192.168.106.104:9047";
    private static String clusterName = "dremioBridgeTest";
    private static final Pattern PARSER = Pattern.compile("/([^/]+)/([^/]+)/[^/]+/(.*)");
    private static final Function<String, String> PATH_DECODER = new Function<String, String>() {
        public String apply(String input) {
            try {
                return URLDecoder.decode(input, "UTF-8");
            } catch (UnsupportedEncodingException var3) {
                throw new UnsupportedOperationException(var3);
            }
        }
    };

    private static CloseableHttpClient closeableHttpClient = null;
    private static String token;
    private static AtlasEntityBuilder builder = null;
    private static Map<String, AtlasEntity.AtlasEntityWithExtInfo> cachedCatalogMap = new HashMap<>();

    private static Map<String, AtlasEntity.AtlasEntityWithExtInfo> cachedSchemaMap = new HashMap<>();
    private static Map<String, AtlasEntity.AtlasEntityWithExtInfo> cachedTableMap= new HashMap<>();
    private static Map<String, AtlasEntity.AtlasEntityWithExtInfo> cachedColumnMap= new HashMap<>();

    private AtlasEntity.AtlasEntityWithExtInfo cluster;
    public static void main(String[] args) {
        int exitCode = EXIT_CODE_FAILED;
        AtlasClientV2 atlasClientV2 = null;
        try {
            Options options = new Options();
            options.addOption("d", "database", true, "Database name");
            options.addOption("t", "table", true, "Table name");

            CommandLine   cmd              = new DefaultParser().parse(options, args);
            String        databaseToImport = cmd.getOptionValue("d");
            String        tableToImport    = cmd.getOptionValue("t");
            Configuration atlasConf        = ApplicationProperties.get();
            String[]      atlasEndpoint    = atlasConf.getStringArray(ATLAS_ENDPOINT);

            if (atlasEndpoint == null || atlasEndpoint.length == 0) {
                atlasEndpoint = new String[] { DEFAULT_ATLAS_URL };
            }

            if (!AuthenticationUtil.isKerberosAuthenticationEnabled()) {
                String[] basicAuthUsernamePassword = new String[2];
                basicAuthUsernamePassword[0] = "admin";
                basicAuthUsernamePassword[1] = "admin";
                atlasClientV2 = new AtlasClientV2(atlasEndpoint, basicAuthUsernamePassword);

            } else {
                UserGroupInformation ugi = UserGroupInformation.getCurrentUser();

                atlasClientV2 = new AtlasClientV2(ugi, ugi.getShortUserName(), atlasEndpoint);
            }
            builder = new AtlasEntityBuilder(atlasClientV2);
            DremioBridge bridge = new DremioBridge();
            bridge.importDataBase();
            exitCode = EXIT_CODE_SUCCESS;
        } catch(ParseException e) {
            LOG.error("Failed to parse arguments. Error: ", e.getMessage());
        } catch(Exception e) {
            LOG.error("Import failed", e);
        } finally {
            if( atlasClientV2 !=null) {
                atlasClientV2.close();
            }
        }

        System.exit(exitCode);
    }

    private void importDataBase() throws Exception{
        List<String> databaseNames = null;
        login();
        createCluster();
        JsonObject jo = string2Object(get( "/api/v3/catalog"));
        JsonArray ja = jo.get("data").getAsJsonArray();
        Iterator<JsonElement>  jei = ja.iterator();
        while(jei.hasNext()){
            JsonObject je = jei.next().getAsJsonObject();
            if("SOURCE".equals(je.get("containerType").getAsString())){
                JsonObject jo1 = string2Object(get( "/apiv2/source/"+je.get("path").getAsJsonArray().get(0).getAsString()));
                impoortCatalog(jo1);

            } else if ("SPACE".equals(je.get("containerType").getAsString())){
                JsonObject jo1 = string2Object(get( "/apiv2/space/"+je.get("path").getAsJsonArray().get(0).getAsString()));
                impoortCatalog(jo1);
            }
        }

    }

    private void impoortCatalog(JsonObject jo) throws AtlasServiceException {
        // jo 实际是com.dremio.dac.model.namespace.NamespaceTree对象
        JsonArray folders = jo.get("contents").getAsJsonObject().get("folders").getAsJsonArray();
        Iterator<JsonElement> ite = folders.iterator();
        while(ite.hasNext()){
            JsonObject je1 = ite.next().getAsJsonObject();
            importFolder(je1);
        }
        JsonArray datasets = jo.get("contents").getAsJsonObject().get("datasets").getAsJsonArray();
        ite = datasets.iterator();
        while(ite.hasNext()){
            JsonObject je1 = ite.next().getAsJsonObject();
            importDataset(je1, "datasets");
        }
        JsonArray files = jo.get("contents").getAsJsonObject().get("files").getAsJsonArray();
        ite = files.iterator();
        while(ite.hasNext()){
            JsonObject je1 = ite.next().getAsJsonObject();
            importDataset(je1,"file");
        }
        JsonArray physicalDatasets = jo.get("contents").getAsJsonObject().get("physicalDatasets").getAsJsonArray();
        ite = physicalDatasets.iterator();
        while(ite.hasNext()){
            JsonObject je1 = ite.next().getAsJsonObject();
            importDataset(je1,"physicalDataset");

        }
    }
    private void importFolder(JsonObject jo) throws AtlasServiceException {
        JsonObject jo1 = string2Object(get( "/apiv2"+jo.get("urlPath").getAsString()));
        impoortCatalog(jo1);
    }

    private void importDataset(JsonObject jo, String type) throws AtlasServiceException{
        if("datasets".equals(type)){
            createTableFromDataset(jo);
        } else if ("file".equals(type)){
            createTableFromFile(jo);
        } else if("physicalDataset".equals(type)){
            createTableFromPhysicalDataset(jo);
        }
    }


    private AtlasEntity.AtlasEntityWithExtInfo createSchema(List<String> schemaList, String schemaType) throws AtlasServiceException {
        String schema = PathUtils.constructFullPath(schemaList) + "@" + clusterName;
        AtlasEntity.AtlasEntityWithExtInfo ret = cachedSchemaMap.get(schema);
        if (ret == null) {
            ret = builder.findEntity("rf_schema", schema);
                if ("table".equals(schemaType)) {
                    AtlasEntity.AtlasEntityWithExtInfo catalog = createCatalog(schemaList.get(0));
                    ret.getEntity().setAttribute("catalog", AtlasTypeUtil.getAtlasObjectId(catalog.getEntity()));
                }

                ret.getEntity().setAttribute("name", schema);
                ret.getEntity().setAttribute("qualifiedName", schema);
                ret.getEntity().setAttribute("createdAt", System.currentTimeMillis());
                ret.getEntity().setAttribute("fullPath", schemaList);
                ret.getEntity().setAttribute("cluster", AtlasTypeUtil.getAtlasObjectId(cluster.getEntity()));

                builder.createInstance(ret);
                ret = builder.findEntity("rf_schema", schema);

            cachedSchemaMap.put(schema, ret);
        }
        return ret;
    }
    private AtlasEntity.AtlasEntityWithExtInfo createTableFromDataset(JsonObject dataset) throws AtlasServiceException {
        JsonObject datasetConfig = dataset.get("datasetConfig").getAsJsonObject();
        List<AtlasEntity> inputs = new ArrayList<>();
        if(datasetConfig.get("parentsList") != null){
            JsonArray parents = datasetConfig.get("parentsList").getAsJsonArray();

            for(JsonElement parent : parents){
                List<String> parentPath = new ArrayList<>();
                parent.getAsJsonObject().get("datasetPathList").getAsJsonArray().forEach(path -> parentPath.add(path.getAsString()));
                String qualifiedName = PathUtils.constructFullPath(parentPath) + "@" + clusterName;
                AtlasEntity.AtlasEntityWithExtInfo pRet = cachedTableMap.get(qualifiedName);
                if(pRet == null){
                    pRet = builder.findEntity("rf_table", qualifiedName);
                    if(pRet.getEntity().getGuid().startsWith("-")){
                        pRet = createEmptyEntityforLineage(qualifiedName);
                    }
                }
                inputs.add(pRet.getEntity());
            }

        }

        List<String> fullPath = new ArrayList<>();
        datasetConfig.get("fullPathList").getAsJsonArray().forEach(path -> fullPath.add(path.getAsString()));

        String prefix = PathUtils.constructFullPath(fullPath);
        String qualifiedName = prefix + "@" + clusterName;
        AtlasEntity.AtlasEntityWithExtInfo ret = cachedTableMap.get(qualifiedName);
        if (ret == null) {
            ret = builder.findEntity("rf_table", qualifiedName);
        } else {
            return ret;
        }

        ret.getEntity().setAttribute("name", fullPath.get(fullPath.size()-1));
        ret.getEntity().setAttribute("qualifiedName", qualifiedName);
        ret.getEntity().setAttribute("owner", datasetConfig.get("owner").getAsString());
        ret.getEntity().setAttribute("createdAt", datasetConfig.get("createdAt").getAsLong());
        ret.getEntity().setAttribute("tableType", "view");
        if (datasetConfig.get("accelerated") != null){
            ret.getEntity().setAttribute("isAccelerated", datasetConfig.get("accelerated").getAsBoolean());
        }

        ret.getEntity().setAttribute("fullPath", fullPath);
//        ret.getEntity().setAttribute(ATTRIBUTE_MODIFY_TIME, datasetConfig.getLastModified());

        AtlasEntity schema = createSchema(fullPath.subList(0,fullPath.size()-1),"view").getEntity();
        ret.getEntity().setAttribute("tableSchema", AtlasTypeUtil.getAtlasObjectId(schema));
        ret.addReferredEntity(schema);
        List<AtlasEntity> columns = new ArrayList<>();

        if (datasetConfig.get("sqlFieldsList") != null) {
            JsonArray fields = datasetConfig.get("sqlFieldsList").getAsJsonArray();
            for (JsonElement f : fields) {
                AtlasEntity.AtlasEntityWithExtInfo column = createColumn(prefix, ret.getEntity(), f.getAsJsonObject().get("name").getAsString(), f.getAsJsonObject().get("type").getAsString());
                columns.add(column.getEntity());
                ret.addReferredEntity(column.getEntity());

            }
            ret.getEntity().setAttribute("columns", AtlasTypeUtil.getAtlasObjectIds(columns));
        }
        builder.createInstance(ret);
        ret = builder.findEntity("rf_table", qualifiedName);
        for (AtlasEntity atlasEntity : ret.getReferredEntities().values()) {
            cachedColumnMap.put(atlasEntity.getAttribute("qualifiedName").toString(), new AtlasEntity.AtlasEntityWithExtInfo(atlasEntity));
        }
        cachedTableMap.put(qualifiedName, ret);
        createProcess(fullPath.get(fullPath.size()-1), datasetConfig.get("sql").getAsString(), inputs, ret.getEntity());
        return ret;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createProcess(String outputName, String sql, List<AtlasEntity> inputs, AtlasEntity output) throws AtlasServiceException {
        String qualifiedName = outputName + ".process@" + clusterName;

        AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity("rf_process"));

        ret.getEntity().setAttribute("name", output.getAttribute("qualifiedName") + ".process");
        ret.getEntity().setAttribute("qualifiedName", qualifiedName);
        ret.getEntity().setAttribute("owner", "");
        ret.getEntity().setAttribute("sql", sql);

        // TODO
        // ret.getEntity().setAttribute(ATTRIBUTE_START_TIME, System.currentTimeMillis());
        // ret.getEntity().setAttribute(ATTRIBUTE_END_TIME, System.currentTimeMillis());
        // ret.getEntity().setAttribute(ATTRIBUTE_DURATION, 0L);

        ret.getEntity().setRelationshipAttribute("inputs", AtlasTypeUtil.getAtlasObjectIds(inputs));
        ret.getEntity().setRelationshipAttribute("outputs", AtlasTypeUtil.getAtlasObjectIds(Collections.singletonList(output)));

        builder.createInstance(ret);
        ret = builder.findEntity("rf_process", qualifiedName);

        return ret;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createEmptyEntityforLineage(String qualifiedName) throws AtlasServiceException {
        AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity("rf_table"));

        ret.getEntity().setAttribute("name", qualifiedName);
        ret.getEntity().setAttribute("qualifiedName", qualifiedName);
        builder.createInstance(ret);
        ret = builder.findEntity("rf_table", qualifiedName);
        return ret;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createTableFromFile(JsonObject dataset) throws AtlasServiceException {
        JsonObject datasetConfig = dataset.get("fileFormat").getAsJsonObject().get("fileFormat").getAsJsonObject();
        Matcher m = PARSER.matcher(dataset.get("urlPath").getAsString());
        List<String> fullPath = null ;

        if (m.matches()) {
            fullPath  = FluentIterable.from(new String[]{m.group(2)}).append(m.group(3).split("/")).transform(PATH_DECODER).toList();
        } else {
            throw new IllegalArgumentException("Not a valid filePath: " + dataset.get("urlPath").getAsString());
        }

        String prefix = PathUtils.constructFullPath(fullPath);
        String qualifiedName = prefix + "@" + clusterName;
        AtlasEntity.AtlasEntityWithExtInfo ret = cachedTableMap.get(qualifiedName);
        if (ret == null) {
            ret = builder.findEntity("rf_table", qualifiedName);
        } else {
            return ret;
        }

        ret.getEntity().setAttribute("name", fullPath.get(fullPath.size()-1));
        ret.getEntity().setAttribute("qualifiedName", qualifiedName);
        ret.getEntity().setAttribute("owner", datasetConfig.get("owner").getAsString());
        ret.getEntity().setAttribute("createdAt", datasetConfig.get("ctime").getAsLong());
        ret.getEntity().setAttribute("tableType", "table");

        ret.getEntity().setAttribute("fullPath", fullPath);
//        ret.getEntity().setAttribute(ATTRIBUTE_MODIFY_TIME, datasetConfig.getLastModified());

        AtlasEntity schema = createSchema(fullPath.subList(0,fullPath.size()-1),"table").getEntity();
        ret.getEntity().setAttribute("tableSchema", AtlasTypeUtil.getAtlasObjectId(schema));
        ret.addReferredEntity(schema);
        List<AtlasEntity> columns = new ArrayList<>();

        JsonObject summary = null;
        try {
            summary = string2Object(get("/apiv2/datasets/summary/" + URLEncoder.encode(StringUtils.join(fullPath,"/"), "UTF-8")));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        if (summary != null) {
            JsonArray fields = summary.get("fields").getAsJsonArray();
            for (JsonElement f : fields) {
                AtlasEntity.AtlasEntityWithExtInfo column = createColumn(prefix, ret.getEntity(), f.getAsJsonObject().get("name").getAsString(), f.getAsJsonObject().get("type").getAsString());
                columns.add(column.getEntity());
                ret.addReferredEntity(column.getEntity());

            }
            ret.getEntity().setAttribute("columns", AtlasTypeUtil.getAtlasObjectIds(columns));
        }
        builder.createInstance(ret);
        ret = builder.findEntity("rf_table", qualifiedName);
        for (AtlasEntity atlasEntity : ret.getReferredEntities().values()) {
            cachedColumnMap.put(atlasEntity.getAttribute("qualifiedName").toString(), new AtlasEntity.AtlasEntityWithExtInfo(atlasEntity));
        }
        cachedTableMap.put(qualifiedName, ret);
        return ret;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createTableFromPhysicalDataset(JsonObject dataset) throws AtlasServiceException {
        JsonObject datasetConfig = dataset.get("datasetConfig").getAsJsonObject();

        List<String> fullPath = new ArrayList<>() ;

        datasetConfig.get("fullPathList").getAsJsonArray().forEach(path -> fullPath.add(path.getAsString()));

        String prefix = PathUtils.constructFullPath(fullPath);
        String qualifiedName = prefix + "@" + clusterName;
        AtlasEntity.AtlasEntityWithExtInfo ret = cachedTableMap.get(qualifiedName);
        if (ret == null) {
            ret = builder.findEntity("rf_table", qualifiedName);
        } else {
            return ret;
        }

        ret.getEntity().setAttribute("name", fullPath.get(fullPath.size()-1));
        ret.getEntity().setAttribute("qualifiedName", qualifiedName);
        if(datasetConfig.get("formatSettings") != null){
            JsonObject formatSettings = datasetConfig.get("formatSettings").getAsJsonObject();
            ret.getEntity().setAttribute("owner", formatSettings.get("owner").getAsString());
            ret.getEntity().setAttribute("createdAt", formatSettings.get("ctime").getAsLong());
        }
        ret.getEntity().setAttribute("tableType", "table");

        ret.getEntity().setAttribute("fullPath", fullPath);
//        ret.getEntity().setAttribute(ATTRIBUTE_MODIFY_TIME, datasetConfig.getLastModified());

        AtlasEntity schema = createSchema(fullPath.subList(0,fullPath.size()-1),"table").getEntity();
        ret.getEntity().setAttribute("tableSchema", AtlasTypeUtil.getAtlasObjectId(schema));
        ret.addReferredEntity(schema);
        List<AtlasEntity> columns = new ArrayList<>();

        JsonObject summary = null;
        try {
            summary = string2Object(get("/apiv2/datasets/summary/" + URLEncoder.encode(StringUtils.join(fullPath,"/"), "UTF-8")));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        if (summary != null) {
            JsonArray fields = summary.get("fields").getAsJsonArray();
            for (JsonElement f : fields) {
                AtlasEntity.AtlasEntityWithExtInfo column = createColumn(prefix, ret.getEntity(), f.getAsJsonObject().get("name").getAsString(), f.getAsJsonObject().get("type").getAsString());
                columns.add(column.getEntity());
                ret.addReferredEntity(column.getEntity());

            }
            ret.getEntity().setAttribute("columns", AtlasTypeUtil.getAtlasObjectIds(columns));
        }
        builder.createInstance(ret);
        ret = builder.findEntity("rf_table", qualifiedName);
        for (AtlasEntity atlasEntity : ret.getReferredEntities().values()) {
            cachedColumnMap.put(atlasEntity.getAttribute("qualifiedName").toString(), new AtlasEntity.AtlasEntityWithExtInfo(atlasEntity));
        }
        cachedTableMap.put(qualifiedName, ret);
        return ret;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createColumn(String prefix, AtlasEntity table, String colName, String type) throws AtlasServiceException {
        String qualifiedName = prefix + "." + colName + "@" + clusterName;
        AtlasEntity.AtlasEntityWithExtInfo ret = cachedColumnMap.get(qualifiedName);
        if (ret == null) {
            ret = builder.findEntity("rf_column", qualifiedName);
        } else {
            return ret;
        }
        ret.getEntity().setAttribute("dataType", type);

        ret.getEntity().setAttribute("name", colName);
        ret.getEntity().setAttribute("qualifiedName", qualifiedName);
        ret.getEntity().setAttribute("table", AtlasTypeUtil.getAtlasObjectId(table));

        return ret;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createCluster() throws AtlasServiceException {
        AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity("rf_cluster"));
        ret.getEntity().setAttribute("name", clusterName);
        ret.getEntity().setAttribute("qualifiedName", clusterName);
        ret.getEntity().setAttribute("clusterType", "dremio");
        ret.getEntity().setAttribute("url", "");
        builder.createInstance(ret);
        cluster = builder.findEntity("rf_cluster", clusterName);
        return cluster;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createCatalog(String name) throws AtlasServiceException {
        String qualifiedName = name + "@" + clusterName;
        if(cachedCatalogMap.get(qualifiedName)!=null){
            return cachedCatalogMap.get(qualifiedName);
        }
        JsonObject source = null;
        try {
            source = string2Object(get("/apiv2/source/" + URLEncoder.encode(name, "UTF-8")));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity("rf_catalog"));

        ret.getEntity().setAttribute("name", name);
        ret.getEntity().setAttribute("qualifiedName", qualifiedName);
        ret.getEntity().setAttribute("sourceType", source.get("type").getAsString());
        ret.getEntity().setAttribute("isSource", true);
        ret.getEntity().setAttribute("createdAt", source.get("ctime").getAsLong());
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("sourceType", source.get("type").getAsString());
        ret.getEntity().setAttribute("parameters", parameters);

        ret.getEntity().setAttribute("cluster", AtlasTypeUtil.getAtlasObjectId(cluster.getEntity()));

        builder.createInstance(ret);
        ret = builder.findEntity("rf_catalog", qualifiedName);
        cachedCatalogMap.put(qualifiedName, ret);
        return ret;
    }

    private static JsonParser jsonParser=new JsonParser();

    public static JsonObject string2Object(String strJson) {
        if(StringUtils.isEmpty(strJson)){
            return null;
        }
        return jsonParser.parse(strJson).getAsJsonObject();
    }
    public boolean login(){
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("userName", "liss");
        jsonObject.addProperty("password", "1qaz@WSX");

        JsonObject resultJsonObject = string2Object(post("/apiv2/login", jsonObject));
        String tok = resultJsonObject.get("token").getAsString();
        token = tok;
        return true;
    }

    public String get(String api)
    {

        HttpGet httpGet = new HttpGet(DEFAULT_DREMIO_URL + api.replace("\"", "%22").replace("$","%24").replace(" ", "%20").replaceAll("\\+",  "%20"));
        httpGet.addHeader("Content-Type", "application/json");
        httpGet.addHeader("authorization","_dremio"+token);
        //send post return HttpResponse object
        HttpResponse response = null;

        // 创建HttpClientBuilder
        // HttpClient
        if(closeableHttpClient==null){
            HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
                RequestConfig requestConfig = RequestConfig.custom().setConnectionRequestTimeout(10000).setConnectTimeout(10000).setSocketTimeout(100000).build();
            httpClientBuilder.setDefaultRequestConfig(requestConfig);

            closeableHttpClient = httpClientBuilder.build();
        }
        try {
            response = closeableHttpClient.execute(httpGet);
        } catch (ClientProtocolException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


        if(response!=null)
        {
            HttpEntity entity = response.getEntity();
            String info=null;
            try
            {
                info = EntityUtils.toString(entity);

            } catch (org.apache.http.ParseException e)
            {
                e.printStackTrace();
            } catch (IOException e)
            {
                e.printStackTrace();
            }

            int res = response.getStatusLine().getStatusCode();
            if(res==200)
            {
                if(entity!=null)
                {
                    return info;
                }
            }
        }
        return "";
    }

    public String post(String api, JsonObject jsonParam)
    {
        JsonObject jsonObject = null;
        HttpPost httpPost = new HttpPost(DEFAULT_DREMIO_URL + api);
        httpPost.addHeader("Content-Type", "application/json");
        if(token != null){
            httpPost.addHeader("authorization","_dremio"+token);
        }

        StringEntity entity = new StringEntity(jsonParam.toString(), Consts.UTF_8);
        httpPost.setEntity(entity);

        //send post return HttpResponse object
        HttpResponse response = null;
        // HttpClient
        if(closeableHttpClient==null){
            HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
            RequestConfig requestConfig = RequestConfig.custom().setConnectionRequestTimeout(10000).setConnectTimeout(10000).setSocketTimeout(100000).build();
            httpClientBuilder.setDefaultRequestConfig(requestConfig);

            closeableHttpClient = httpClientBuilder.build();
        }

        try {
            response = closeableHttpClient.execute(httpPost);
        } catch (ClientProtocolException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        HttpEntity resultEntity = response.getEntity();
        String info=null;
        try
        {
            info = EntityUtils.toString(resultEntity);
        } catch (org.apache.http.ParseException e)
        {
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        }

        if(response!=null)
        {
            int res = response.getStatusLine().getStatusCode();
            if(res==200)
            {
                if(entity!=null)
                {
                    return info;
                }
            }
        }
        return "";
    }



}
