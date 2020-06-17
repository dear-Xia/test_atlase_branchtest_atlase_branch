package org.apache.atlas.dremio.bridge.test;

import com.dremio.common.utils.PathUtils;
import org.apache.atlas.AtlasServiceException;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasEntityHeader;
import org.apache.atlas.model.instance.AtlasObjectId;
import org.apache.atlas.model.instance.EntityMutationResponse;
import org.apache.atlas.type.AtlasTypeUtil;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.*;

public class DremioBridgeTest implements TestTypes {
    private static String clusterName = "dremioBridgeTest";
    private static String dataSetName = "testDataset";
    private static String schemaName = "testSchema";
    private static String tableName = "teatTable";

    private static String dataSetQualified = dataSetName + "@" + clusterName;
    private static String schemaQualified = dataSetName + "." + schemaName + "@" + clusterName;

    private static String atlasUrl = "http://192.168.106.104:21000/";
    private static String atlasUsername = "admin";
    private static String atlasPass = "admin";

    private final static String typesDef = "{\"structDefs\":[],\"classificationDefs\":[],\"entityDefs\":[{\"name\":\"test_cluster\",\"typeVersion\":\"1.0\",\"superTypes\":[\"Asset\"],\"attributeDefs\":[{\"name\":\"parameters\",\"typeName\":\"map<string,string>\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"clusterType\",\"typeName\":\"string\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":false,\"isUnique\":false},{\"name\":\"url\",\"typeName\":\"string\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":true,\"isUnique\":false}]},{\"name\":\"test_catalog\",\"superTypes\":[\"Asset\"],\"typeVersion\":\"1.0\",\"attributeDefs\":[{\"name\":\"cluster\",\"typeName\":\"test_cluster\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"isSource\",\"typeName\":\"boolean\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":true,\"isUnique\":false},{\"name\":\"sourceType\",\"typeName\":\"string\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":false,\"isUnique\":false},{\"name\":\"parameters\",\"typeName\":\"map<string,string>\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"createdAt\",\"typeName\":\"long\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":true,\"isUnique\":false}]},{\"name\":\"test_schema\",\"superTypes\":[\"Asset\"],\"typeVersion\":\"1.0\",\"attributeDefs\":[{\"name\":\"cluster\",\"typeName\":\"test_cluster\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"catalog\",\"typeName\":\"test_catalog\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"fullPath\",\"typeName\":\"array<string>\",\"cardinality\":\"LIST\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false}]},{\"name\":\"test_table\",\"superTypes\":[\"DataSet\"],\"typeVersion\":\"1.0\",\"attributeDefs\":[{\"name\":\"tableSchema\",\"typeName\":\"test_catalog\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"fullPath\",\"typeName\":\"array<string>\",\"cardinality\":\"LIST\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"createdAt\",\"typeName\":\"long\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"modifiedAt\",\"typeName\":\"long\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"comment\",\"typeName\":\"string\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"columns\",\"typeName\":\"array<test_column>\",\"cardinality\":\"SET\",\"constraints\":[{\"type\":\"ownedRef\"}],\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"tableType\",\"typeName\":\"string\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":true,\"isUnique\":false},{\"name\":\"viewVersion\",\"typeName\":\"string\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"isAccelerated\",\"typeName\":\"boolean\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":true,\"isUnique\":false}]},{\"name\":\"test_column\",\"superTypes\":[\"DataSet\"],\"typeVersion\":\"1.0\",\"attributeDefs\":[{\"name\":\"dataType\",\"typeName\":\"string\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":false,\"isUnique\":false},{\"name\":\"comment\",\"typeName\":\"string\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false},{\"name\":\"table\",\"typeName\":\"test_table\",\"cardinality\":\"SINGLE\",\"constraints\":[{\"type\":\"inverseRef\",\"params\":{\"attribute\":\"columns\"}}],\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false}]},{\"name\":\"test_process\",\"superTypes\":[\"Process\"],\"typeVersion\":\"1.0\",\"attributeDefs\":[{\"name\":\"startTime\",\"typeName\":\"long\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":true,\"isUnique\":false},{\"name\":\"endTime\",\"typeName\":\"long\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":true,\"isUnique\":false},{\"name\":\"duration\",\"typeName\":\"long\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":true,\"isUnique\":false},{\"name\":\"sql\",\"typeName\":\"string\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":true,\"isUnique\":false}]},{\"name\":\"test_column_lineage\",\"superTypes\":[\"Process\"],\"typeVersion\":\"1.0\",\"attributeDefs\":[{\"name\":\"process\",\"typeName\":\"test_process\",\"cardinality\":\"SINGLE\",\"isIndexable\":false,\"isOptional\":false,\"isUnique\":false},{\"name\":\"depenendencyType\",\"typeName\":\"string\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":true,\"isUnique\":false},{\"name\":\"expression\",\"typeName\":\"string\",\"cardinality\":\"SINGLE\",\"isIndexable\":true,\"isOptional\":true,\"isUnique\":false}]}],\"relationshipDefs\":[{\"name\":\"test_cluster_catalog\",\"typeVersion\":\"1.0\",\"relationshipCategory\":\"COMPOSITION\",\"endDef1\":{\"type\":\"test_catalog\",\"name\":\"cluster\",\"isContainer\":false,\"cardinality\":\"SINGLE\",\"isLegacyAttribute\":true},\"endDef2\":{\"type\":\"test_cluster\",\"name\":\"catalog\",\"isContainer\":true,\"cardinality\":\"SET\"},\"propagateTags\":\"NONE\"},{\"name\":\"test_table_schema\",\"typeVersion\":\"1.0\",\"relationshipCategory\":\"COMPOSITION\",\"endDef1\":{\"type\":\"test_table\",\"name\":\"tableSchema\",\"isContainer\":false,\"cardinality\":\"SINGLE\",\"isLegacyAttribute\":true},\"endDef2\":{\"type\":\"test_schema\",\"name\":\"tables\",\"isContainer\":true,\"cardinality\":\"SET\"},\"propagateTags\":\"NONE\"},{\"name\":\"test_catalog_schema\",\"typeVersion\":\"1.0\",\"relationshipCategory\":\"COMPOSITION\",\"endDef1\":{\"type\":\"test_schema\",\"name\":\"catalog\",\"isContainer\":false,\"cardinality\":\"SINGLE\",\"isLegacyAttribute\":true},\"endDef2\":{\"type\":\"test_catalog\",\"name\":\"tableSchemas\",\"isContainer\":true,\"cardinality\":\"SET\"},\"propagateTags\":\"NONE\"},{\"name\":\"test_table_columns\",\"typeVersion\":\"1.0\",\"relationshipCategory\":\"COMPOSITION\",\"endDef1\":{\"type\":\"test_table\",\"name\":\"columns\",\"isContainer\":true,\"cardinality\":\"SET\",\"isLegacyAttribute\":true},\"endDef2\":{\"type\":\"test_column\",\"name\":\"table\",\"isContainer\":false,\"cardinality\":\"SINGLE\",\"isLegacyAttribute\":true},\"propagateTags\":\"NONE\"},{\"name\":\"test_process_column_lineage\",\"typeVersion\":\"1.0\",\"relationshipCategory\":\"COMPOSITION\",\"endDef1\":{\"type\":\"test_process\",\"name\":\"columnLineages\",\"isContainer\":true,\"cardinality\":\"SET\"},\"endDef2\":{\"type\":\"test_column_lineage\",\"name\":\"tableLineages\",\"isContainer\":false,\"cardinality\":\"SINGLE\",\"isLegacyAttribute\":true},\"propagateTags\":\"NONE\"}]}";


    //    private DremioHookTest dremioHookTest = new DremioHookTest();
    private AtlasRestTest restTest = new AtlasRestTest(atlasUrl, atlasUsername, atlasPass);

    private AtlasEntity.AtlasEntityWithExtInfo cluster;
    private AtlasEntity.AtlasEntityWithExtInfo dataSet;
    private AtlasEntity.AtlasEntityWithExtInfo schema;
    Set<String> atlas_tables = new HashSet<>();
    Set<String> atlas_process = new HashSet<>();
    List<AtlasEntityHeader> tableHelpers = new ArrayList<>();

    long sumCreateColumns = 0L;
    long createColumnTimes = 0L;
    long sumGetColumns = 0L;
    long getColumnTimes = 0L;
    long createTable = 0L;


    public static void main(String[] args) throws Exception {
        DremioBridgeTest test = new DremioBridgeTest();
        test.testBatch(60, false);
//        test.testSingle(60, true);
    }

    public void testSingle(int batchSize, boolean delete) throws AtlasServiceException {
        try {
            initData(false);
            testBatchCreate(batchSize, false);
            testCreateLineage(batchSize, false);
        } catch (Exception e){
            e.printStackTrace();
        }finally {
            if (delete) deleteData(false);
        }
    }

    public void testBatch(int batchSize, boolean delete) throws AtlasServiceException {
        try {
            initData(true);
            testBatchCreate(batchSize, true);
            testCreateLineage(batchSize, true);
        } catch (Exception e){
            e.printStackTrace();
        }finally {
            if (delete) deleteData(true);
        }
    }

    private void testCreateLineage(int batchSize, boolean isBatch) throws AtlasServiceException {
        if (batchSize <= 1) {
            return;
        }
        AtlasEntity.AtlasEntitiesWithExtInfo entities = new AtlasEntity.AtlasEntitiesWithExtInfo();
        final Iterator<AtlasEntityHeader> iterator = tableHelpers.iterator();

        int id = 0;
        boolean convert = false;
        List<AtlasObjectId> outputs = new ArrayList<>();
        while (iterator.hasNext()) {
            if(outputs.isEmpty()){
                outputs.add(AtlasTypeUtil.getAtlasObjectId(iterator.next()));
            }else{
                AtlasEntityHeader current = iterator.next();
                List<AtlasObjectId> inputs = new ArrayList<>();
                inputs.addAll(outputs);
                outputs = new ArrayList<>();
                outputs.add(AtlasTypeUtil.getAtlasObjectId(current));
                if(!convert){
                    convert = true;
                }else{
                    if(iterator.hasNext()){
                        AtlasEntityHeader current2 = iterator.next();
                        outputs.add(AtlasTypeUtil.getAtlasObjectId(current2));
                    }
                    convert = false;
                }
                AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity(TEST_PROCESS));
                ret.getEntity().setAttribute(ATTRIBUTE_NAME, id + ".process");
                ret.getEntity().setAttribute(ATTRIBUTE_QUALIFIED_NAME, id+"."+clusterName+".process");
                ret.getEntity().setAttribute(ATTRIBUTE_OWNER, "");
                ret.getEntity().setAttribute(ATTRIBUTE_TABLE_SQL, "select 1 from tempSql");
                ret.getEntity().setRelationshipAttribute(ATTRIBUTE_INPUTS, inputs);
                ret.getEntity().setRelationshipAttribute(ATTRIBUTE_OUTPUTS, outputs);
                entities.addEntity(ret.getEntity());
                id++;
            }
        }

        long start, end;
        start = System.currentTimeMillis();
        if(isBatch){
            EntityMutationResponse response = restTest.batchCreateOrUpdate(entities);

            checkNull(response.getCreatedEntities()).stream()
                    .filter(entity -> StringUtils.equalsIgnoreCase(entity.getTypeName(), TEST_PROCESS))
                    .forEach(entity -> atlas_process.add(entity.getGuid()));
            checkNull(response.getUpdatedEntities()).stream()
                    .filter(entity -> StringUtils.equalsIgnoreCase(entity.getTypeName(), TEST_PROCESS))
                    .forEach(entity -> atlas_process.add(entity.getGuid()));
            end = System.currentTimeMillis();
            System.out.println(String.format("Finished to batch create %s atlas process entity, cost %s ms.", entities.getEntities().size(), end - start));
        }else{
            for (AtlasEntity atlasEntity : entities.getEntities()) {
                EntityMutationResponse response = restTest.createOrUpdate(new AtlasEntity.AtlasEntityWithExtInfo(atlasEntity));
                checkNull(response.getCreatedEntities()).stream()
                        .filter(entity -> StringUtils.equalsIgnoreCase(entity.getTypeName(), TEST_PROCESS))
                        .forEach(entity -> atlas_process.add(entity.getGuid()));
                checkNull(response.getUpdatedEntities()).stream()
                        .filter(entity -> StringUtils.equalsIgnoreCase(entity.getTypeName(), TEST_PROCESS))
                        .forEach(entity -> atlas_process.add(entity.getGuid()));
            }
            end = System.currentTimeMillis();
            System.out.println(String.format("Finished to create %s atlas process entity, cost %s ms.", entities.getEntities().size(), end - start));
        }

    }

    private void deleteData(boolean isBatch) throws AtlasServiceException {
        List<String> list = new ArrayList<>();
        list.addAll(atlas_tables);
        list.addAll(atlas_process);
        list.add(dataSet.getEntity().getGuid());
        list.add(cluster.getEntity().getGuid());
        list.add(schema.getEntity().getGuid());

        System.out.println(String.format("Starting to delete %s atlas table & process entity.", list.size()));

        long start = System.currentTimeMillis();
        if (isBatch) {
            restTest.delete(list);

            long end = System.currentTimeMillis();
            System.out.println(String.format("Finished to batch delete %s atlas table & process entity, cost %s ms.", list.size(), end - start));

        } else {
            for (String s : list) {
                restTest.delete(s);
            }

            long end = System.currentTimeMillis();
            System.out.println(String.format("Finished to delete %s atlas table & process entity, cost %s ms.", list.size(), end - start));

        }

//        restTest.delete(TEST_CATALOG, dataSetQualified);

//        System.out.println(String.format("Finished to delete catalog."));

//        restTest.delete(TEST_CLUSTER, clusterName);

//        System.out.println(String.format("Finished to delete cluster."));

//        restTest.delete(TEST_SCHEMA, schemaQualified);

//        System.out.println(String.format("Finished to delete schema."));


        cluster = null;
        dataSet = null;
        schema = null;
        atlas_tables.clear();
    }

    private void initData(boolean isBatch) throws AtlasServiceException {
        sumCreateColumns = 0L;
        createColumnTimes = 0L;
        sumGetColumns = 0L;
        getColumnTimes = 0L;
        createTable = 0L;
        atlas_tables.clear();
        tableHelpers.clear();
        atlas_process.clear();

        testInsertCluster();

        cluster = findEntity(TEST_CLUSTER, clusterName);

        testInsertDataset(cluster);

        dataSet = findEntity(TEST_CATALOG, dataSetQualified);

        testInsertSchema(dataSet, cluster);

        schema = findEntity(TEST_SCHEMA, schemaQualified);
    }

//    private void testInsertCols(boolean isBatch) throws AtlasServiceException {
//        AtlasEntity.AtlasEntitiesWithExtInfo cols = new AtlasEntity.AtlasEntitiesWithExtInfo();
//
//        long start, end;
//        start = System.currentTimeMillis();
//        if (isBatch) {
//            restTest.batchCreateOrUpdate(cols);
//        } else {
//            for (AtlasEntity.AtlasEntityWithExtInfo atlasEntityWithExtInfo : columnSet) {
//                restTest.createOrUpdate(atlasEntityWithExtInfo);
//            }
//        }
//        end = System.currentTimeMillis();
//        System.out.println(String.format("Finished to create %s column entity, cost %s ms.", columnSet.size(), end - start));
//    }

    public void testBatchCreate(int batchSize, boolean isBatch) throws AtlasServiceException {
        atlas_tables.clear();

        long start, end;
        start = System.currentTimeMillis();

        AtlasEntity.AtlasEntitiesWithExtInfo entities = new AtlasEntity.AtlasEntitiesWithExtInfo();
        List<AtlasEntity.AtlasEntityWithExtInfo> tableList = new ArrayList<>();
        for (int i = 0; i < batchSize; i++) {
            List<String> paths = new ArrayList<>();
            String realTableName = tableName + "" + i;
            paths.add(dataSetName);
            paths.add(schemaName);
            paths.add(realTableName);
            AtlasEntity.AtlasEntityWithExtInfo tableEntity = createTable(schema.getEntity(), paths, realTableName, "user", isBatch);
            entities.addEntity(tableEntity.getEntity());
            tableList.add(tableEntity);
        }

        end = System.currentTimeMillis();
//        System.out.println(String.format("Finished to create %s table entity, cost %s ms.", batchSize, end - start));

        System.out.println(String.format("Create 15 columns cost %s ms.", sumCreateColumns / createColumnTimes));
        System.out.println(String.format("Get 15 columns cost %s ms.", sumGetColumns / getColumnTimes));

        if (isBatch) {
            start = System.currentTimeMillis();
            final EntityMutationResponse response = restTest.batchCreateOrUpdate(entities);
            end = System.currentTimeMillis();
            System.out.println(String.format("Finished to batch create %s atlas table entity, cost %s ms.", batchSize, end - start));

            checkNull(response.getCreatedEntities()).forEach(entity -> {
                if (StringUtils.equalsIgnoreCase(entity.getTypeName(), TEST_TABLE)) {
                    if (!atlas_tables.contains(entity.getGuid())) {
                        atlas_tables.add(entity.getGuid());
                        tableHelpers.add(entity);
                    }
                }
            });
            checkNull(response.getUpdatedEntities()).forEach(entity -> {
                if (StringUtils.equalsIgnoreCase(entity.getTypeName(), TEST_TABLE)) {
                    if (!atlas_tables.contains(entity.getGuid())) {
                        atlas_tables.add(entity.getGuid());
                        tableHelpers.add(entity);
                    }
                }
            });
        } else {
            List<EntityMutationResponse> responses = new ArrayList<>();
            start = System.currentTimeMillis();
            for (AtlasEntity.AtlasEntityWithExtInfo entity : tableList) {
                responses.add(restTest.createOrUpdate(entity));
            }
            end = System.currentTimeMillis();
            System.out.println(String.format("Finished to create %s atlas table entity, cost %s ms.", batchSize, end - start));

            for (EntityMutationResponse response : responses) {
                checkNull(response.getCreatedEntities()).forEach(entity -> {
                    if (StringUtils.equalsIgnoreCase(entity.getTypeName(), TEST_TABLE)) {
                        if (!atlas_tables.contains(entity.getGuid())) {
                            atlas_tables.add(entity.getGuid());
                            tableHelpers.add(entity);
                        }
                    }
                });
                checkNull(response.getUpdatedEntities()).forEach(entity -> {
                    if (StringUtils.equalsIgnoreCase(entity.getTypeName(), TEST_TABLE)) {
                        if (!atlas_tables.contains(entity.getGuid())) {
                            atlas_tables.add(entity.getGuid());
                            tableHelpers.add(entity);
                        }
                    }
                });
            }
        }
    }

    private void testInsertSchema(AtlasEntity.AtlasEntityWithExtInfo dataSet, AtlasEntity.AtlasEntityWithExtInfo cluster) throws AtlasServiceException {
        long start, end;
        start = System.currentTimeMillis();

        List<String> schemaList = new ArrayList<>();
        schemaList.add(dataSetName);
        schemaList.add(schemaName);
        AtlasEntity.AtlasEntityWithExtInfo schema = createSchema(dataSet, cluster, schemaList, "table");
        end = System.currentTimeMillis();
//        System.out.println(String.format("Finished to create schema entity, cost %s ms.", end - start));

        start = System.currentTimeMillis();
        restTest.createOrUpdate(schema);
        end = System.currentTimeMillis();
//        System.out.println(String.format("Finished to create atlas schema entity, cost %s ms.", end - start));
    }


    private void testInsertDataset(AtlasEntity.AtlasEntityWithExtInfo cluster) throws AtlasServiceException {
        long start, end;
        start = System.currentTimeMillis();
        AtlasEntity.AtlasEntityWithExtInfo dataSet = createCatalog(cluster, dataSetName, "DataSet");
        end = System.currentTimeMillis();
//        System.out.println(String.format("Finished to create dataSet entity, cost %s ms.", end - start));

        start = System.currentTimeMillis();
        restTest.createOrUpdate(dataSet);
        end = System.currentTimeMillis();
//        System.out.println(String.format("Finished to create atlas dataSet entity, cost %s ms.", end - start));
    }

    public void createAllTypes() throws AtlasServiceException, IOException {
        restTest.createTypes(typesDef);
    }

    private AtlasEntity.AtlasEntityWithExtInfo findEntity(String typeName, String qualified) throws AtlasServiceException {
        long start, end;
        start = System.currentTimeMillis();

        AtlasEntity.AtlasEntityWithExtInfo ret = restTest.findByQualified(typeName, qualified);

        end = System.currentTimeMillis();
//        System.out.println(String.format("Finished to find entity, cost %s ms.", end - start));

        return ret;
    }

    private void testInsertCluster() throws AtlasServiceException {
        long start, end;
        start = System.currentTimeMillis();

        restTest.createOrUpdate(createCluster());

        end = System.currentTimeMillis();
//        System.out.println(String.format("Finished to insert cluster entity, cost %s ms.", end - start));

    }

    private AtlasEntity.AtlasEntityWithExtInfo createCluster() {
        AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity(TEST_CLUSTER));
        ret.getEntity().setAttribute(ATTRIBUTE_NAME, clusterName);
        ret.getEntity().setAttribute(ATTRIBUTE_QUALIFIED_NAME, clusterName);
        ret.getEntity().setAttribute(ATTRIBUTE_CLUSTER_TYPE, "dremio");
        ret.getEntity().setAttribute(CLUSTER_URL, "");
        return ret;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createCatalog(AtlasEntity.AtlasEntityWithExtInfo cluster, String sourceName, String sourceType) {
        AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity(TEST_CATALOG));
        ret.getEntity().setAttribute(ATTRIBUTE_NAME, sourceName);
        ret.getEntity().setAttribute(ATTRIBUTE_QUALIFIED_NAME, dataSetQualified);
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(ATTRIBUTE_SOURCE_TYPE, sourceType);
        ret.getEntity().setAttribute(ATTRIBUTE_PARAMETERS, parameters);
        ret.getEntity().setAttribute(ATTRIBUTE_SOURCE_TYPE, sourceType);
        ret.getEntity().setAttribute(ATTRIBUTE_ISSOURCE, true);
        ret.getEntity().setAttribute(ATTRIBUTE_CREATE_TIME, System.currentTimeMillis());
        ret.getEntity().setAttribute(CLUSTER_NAME, AtlasTypeUtil.getAtlasObjectId(cluster.getEntity()));
        return ret;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createProcess(String outputName, String sql, List<AtlasEntity> inputs, AtlasEntity output) {
        String qualifiedName = outputName + ".process@" + clusterName;

        AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity(TEST_PROCESS));

        ret.getEntity().setAttribute(ATTRIBUTE_NAME, output.getAttribute(ATTRIBUTE_QUALIFIED_NAME) + ".process");
        ret.getEntity().setAttribute(ATTRIBUTE_QUALIFIED_NAME, qualifiedName);
        ret.getEntity().setAttribute(ATTRIBUTE_OWNER, "");
        ret.getEntity().setAttribute(ATTRIBUTE_TABLE_SQL, sql);

        ret.getEntity().setRelationshipAttribute(ATTRIBUTE_INPUTS, AtlasTypeUtil.getAtlasObjectIds(inputs));
        ret.getEntity().setRelationshipAttribute(ATTRIBUTE_OUTPUTS, AtlasTypeUtil.getAtlasObjectIds(Collections.singletonList(output)));
        return ret;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createSchema(AtlasEntity.AtlasEntityWithExtInfo dataset, AtlasEntity.AtlasEntityWithExtInfo cluster, List<String> schemaList, String schemaType) {
        AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity(TEST_SCHEMA));
        if (schemaType.equals("table")) {
            ret.getEntity().setAttribute(ATTRIBUTE_CATALOG, AtlasTypeUtil.getAtlasObjectId(dataset.getEntity()));
        }
        ret.getEntity().setAttribute(ATTRIBUTE_NAME, dataSetName + "." + schemaName);
        ret.getEntity().setAttribute(ATTRIBUTE_QUALIFIED_NAME, schemaQualified);
        ret.getEntity().setAttribute(ATTRIBUTE_CREATE_TIME, System.currentTimeMillis());
        ret.getEntity().setAttribute(ATTRIBUTE_FULL_PATH, schemaList);
        ret.getEntity().setAttribute(CLUSTER_NAME, AtlasTypeUtil.getAtlasObjectId(cluster.getEntity()));
        return ret;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createTable(AtlasEntity schema, List<String> tablePath, String tableName, String owner, boolean isBatch) throws AtlasServiceException {
        String tableFullName = PathUtils.constructFullPath(tablePath);
        String qualifiedName = tableFullName + "@" + clusterName;
        AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity(TEST_TABLE));

        ret.getEntity().setAttribute(ATTRIBUTE_NAME, tableName);
        ret.getEntity().setAttribute(ATTRIBUTE_QUALIFIED_NAME, qualifiedName);
        ret.getEntity().setAttribute(ATTRIBUTE_OWNER, owner);
        ret.getEntity().setAttribute(ATTRIBUTE_CREATE_TIME, System.currentTimeMillis());
        ret.getEntity().setAttribute(ATTRIBUTE_TABLE_TYPE, "table");
        ret.getEntity().setAttribute(ATTRIBUTE_TABLE_ISACCELERATED, false);

        ret.getEntity().setAttribute(ATTRIBUTE_FULL_PATH, tablePath);
        ret.getEntity().setAttribute(ATTRIBUTE_MODIFY_TIME, System.currentTimeMillis());

        ret.getEntity().setAttribute(ATTRIBUTE_TABLE_SCHEMA, AtlasTypeUtil.getAtlasObjectId(schema));
//        ret.addReferredEntity(schema);

        List<AtlasEntity> cols = createColumns(tableFullName, 15, isBatch);
        ret.getEntity().setAttribute(ATTRIBUTE_COLUMNS, AtlasTypeUtil.getAtlasObjectIds(cols));
        return ret;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createView(AtlasEntity schema, String viewName, List<String> viewPath, String owner, boolean isBatch) throws AtlasServiceException {
        String qualifiedName = PathUtils.constructFullPath(viewPath) + "@" + clusterName;
        AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity(TEST_TABLE));

        ret.getEntity().setAttribute(ATTRIBUTE_NAME, viewName);
        ret.getEntity().setAttribute(ATTRIBUTE_QUALIFIED_NAME, qualifiedName);
        ret.getEntity().setAttribute(ATTRIBUTE_OWNER, owner);
        ret.getEntity().setAttribute(ATTRIBUTE_CREATE_TIME, System.currentTimeMillis());
        ret.getEntity().setAttribute(ATTRIBUTE_TABLE_TYPE, "view");
        ret.getEntity().setAttribute(ATTRIBUTE_FULL_PATH, viewPath);
        ret.getEntity().setAttribute(ATTRIBUTE_MODIFY_TIME, System.currentTimeMillis());
        ret.getEntity().setAttribute(ATTRIBUTE_TABLE_ISACCELERATED, false);
        ret.getEntity().setAttribute(ATTRIBUTE_TABLE_SCHEMA, AtlasTypeUtil.getAtlasObjectId(schema));
//        ret.addReferredEntity(schema);

        List<AtlasEntity> columns = createColumns(PathUtils.constructFullPath(viewPath), 15, isBatch);
        ret.getEntity().setAttribute(ATTRIBUTE_COLUMNS, AtlasTypeUtil.getAtlasObjectIds(columns));
        return ret;
    }

    private List<AtlasEntity> createColumns(String tableFullName, int size, boolean isBatch) throws AtlasServiceException {
        AtlasEntity.AtlasEntitiesWithExtInfo entitiesWithExtInfo = new AtlasEntity.AtlasEntitiesWithExtInfo();
        for (int i = 0; i < size; i++) {
            String qualifiedName = tableFullName + ".COLUMN_" + i + "@" + clusterName;
            AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity(TEST_COLUMN));
            ret.getEntity().setAttribute(ATTRIBUTE_TYPE, "String");
            ret.getEntity().setAttribute(ATTRIBUTE_NAME, "COLUMN_" + i);
            ret.getEntity().setAttribute(ATTRIBUTE_QUALIFIED_NAME, qualifiedName);
            entitiesWithExtInfo.addEntity(ret.getEntity());
        }

        long start, end;
        start = System.currentTimeMillis();
        if (isBatch) {
            restTest.batchCreateOrUpdate(entitiesWithExtInfo);
            end = System.currentTimeMillis();
            sumCreateColumns += (end - start);
            createColumnTimes++;
//            System.out.println(String.format("Finished to batch create %s atlas column entity, cost %s ms.", size,end - start));

        } else {
            for (AtlasEntity entity : entitiesWithExtInfo.getEntities()) {
                restTest.createOrUpdate(new AtlasEntity.AtlasEntityWithExtInfo(entity));
            }
            end = System.currentTimeMillis();
//            System.out.println(String.format("Finished to create %s atlas column entity, cost %s ms.", size,end - start));
            sumCreateColumns += (end - start);
            createColumnTimes++;
        }

        start = System.currentTimeMillis();
        List<AtlasEntity> entities = new ArrayList<>();
        if (isBatch) {
            List<Map<String, String>> qualified = new ArrayList<>();
            for (int i = 0; i < size; i++) {
                qualified.add(Collections.singletonMap("qualifiedName", tableFullName + ".COLUMN_" + i + "@" + clusterName));
            }
            AtlasEntity.AtlasEntitiesWithExtInfo byQualified = restTest.findByQualified(TEST_COLUMN, qualified);
            entities.addAll(byQualified.getEntities());

            end = System.currentTimeMillis();
//            System.out.println(String.format("Finished to batch find %s atlas column entity, cost %s ms.", size,end - start));
            sumGetColumns += (end - start);
            getColumnTimes++;
        } else {
            for (int i = 0; i < size; i++) {
                entities.add(restTest.findByQualified(TEST_COLUMN, tableFullName + ".COLUMN_" + i + "@" + clusterName).getEntity());
            }
            end = System.currentTimeMillis();
//            System.out.println(String.format("Finished to batch find %s atlas column entity, cost %s ms.", size,end - start));
            sumGetColumns += (end - start);
            getColumnTimes++;
        }
        return entities;
    }

    private AtlasEntity.AtlasEntityWithExtInfo createColumn(String colName, String type) {
        String qualifiedName = "COL" + "." + colName + "@" + clusterName;
        AtlasEntity.AtlasEntityWithExtInfo ret = new AtlasEntity.AtlasEntityWithExtInfo(new AtlasEntity(TEST_COLUMN));
        ret.getEntity().setAttribute(ATTRIBUTE_TYPE, type);
        ret.getEntity().setAttribute(ATTRIBUTE_NAME, colName);
        ret.getEntity().setAttribute(ATTRIBUTE_QUALIFIED_NAME, qualifiedName);
        return ret;
    }

    private List<AtlasEntityHeader> checkNull(List<AtlasEntityHeader> createdEntities) {
        return createdEntities == null ? new ArrayList<>() : createdEntities;
    }
}
