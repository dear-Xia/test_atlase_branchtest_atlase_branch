/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.atlas.dremio.hook;

import java.util.*;

import com.beust.jcommander.internal.Lists;
import com.dremio.config.DremioConfig;
import com.dremio.service.namespace.NamespaceException;
import com.dremio.service.namespace.NamespaceService;
import com.dremio.service.namespace.dataset.proto.*;
import com.dremio.service.namespace.source.proto.SourceConfig;
import com.dremio.service.namespace.space.proto.FolderConfig;
import com.dremio.service.namespace.space.proto.HomeConfig;
import com.dremio.service.namespace.space.proto.SpaceConfig;
import org.apache.atlas.AtlasServiceException;
import org.apache.atlas.hook.AtlasHook;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasEntity.AtlasEntitiesWithExtInfo;
import org.apache.atlas.model.instance.AtlasEntity.AtlasEntityWithExtInfo;
import org.apache.atlas.model.instance.AtlasObjectId;
import org.apache.atlas.model.notification.HookNotification;
import org.apache.atlas.model.notification.HookNotification.EntityUpdateRequestV2;
import org.apache.atlas.model.notification.HookNotification.EntityDeleteRequestV2;

import org.apache.atlas.type.AtlasTypeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.dremio.common.utils.PathUtils;
import com.dremio.dac.model.common.Field;
import com.dremio.dac.util.DatasetsUtil;
import com.dremio.service.SingletonRegistry;
import com.dremio.service.namespace.NameSpaceChangeListener;
import com.dremio.service.namespace.NamespaceKey;
import com.dremio.service.namespace.proto.NameSpaceContainer;

/**
 * Dremio hook used for atlas entity registration.
 */
public class DremioHook extends AtlasHook implements NameSpaceChangeListener {
  private static final Logger LOG = LoggerFactory.getLogger(DremioHook.class);

  private SingletonRegistry registry;
  private NamespaceService namespaceService;
  private DremioConfig dremioConfig;
 private String clusterId;
 private AtlasEntityWithExtInfo cluster;
  public DremioHook() {
  }

  @Override
  public void init(SingletonRegistry registry) {
    this.registry =registry;

  }

  private void initialize(){
    if (this.namespaceService == null) {
      this.namespaceService = registry.lookup(NamespaceService.class);
    }
    if (this.dremioConfig == null) {
      this.dremioConfig = registry.lookup(DremioConfig.class);
      this.clusterId = this.dremioConfig.getString("cluster.id");
      this.cluster = createCluster();
    }
  }
  private AtlasEntityWithExtInfo createCluster() {
    AtlasEntityWithExtInfo ret = new AtlasEntityWithExtInfo(new AtlasEntity("rf_cluster"));
    ret.getEntity().setAttribute("name", clusterId);
    ret.getEntity().setAttribute("qualifiedName", clusterId);
    ret.getEntity().setAttribute("clusterType", "dremio");
    ret.getEntity().setAttribute("url", "");
      List<HookNotification> messages = new ArrayList<>();
      messages.add(new EntityUpdateRequestV2("admin", new AtlasEntitiesWithExtInfo(ret)));

      super.notifyEntities(messages, null);
    return ret;
  }

  private AtlasEntityWithExtInfo createCatalog(SourceConfig source) {
    AtlasEntityWithExtInfo ret = new AtlasEntityWithExtInfo(new AtlasEntity("rf_catalog"));
    String qualifiedName = source.getName() + "@" + clusterId;

    ret.getEntity().setAttribute("name", source.getName());
    ret.getEntity().setAttribute("qualifiedName", qualifiedName);
    ret.getEntity().setAttribute("sourceType", source.getType());
    ret.getEntity().setAttribute("isSource", true);
    ret.getEntity().setAttribute("createdAt", source.getCtime());
      Map<String, Object> parameters = new HashMap<>();
      parameters.put("sourceType", source.getType());
      ret.getEntity().setAttribute("parameters", parameters);

      ret.getEntity().setAttribute("cluster", AtlasTypeUtil.getAtlasObjectId(cluster.getEntity()));
    ret.addReferredEntity(cluster.getEntity());
    return ret;
  }

    private AtlasEntityWithExtInfo createSchema(List<String> schemaList, String schemaType) {
        String schema = PathUtils.constructFullPath(schemaList) + "@" + clusterId;
        AtlasEntityWithExtInfo ret = new AtlasEntityWithExtInfo(new AtlasEntity("rf_schema"));
        if (schemaType.equals("table")) {
            SourceConfig source = null;
            try {
                source = namespaceService.getSource(new NamespaceKey(schemaList.get(0)));
            } catch (NamespaceException e) {
                e.printStackTrace();
            }
            AtlasEntityWithExtInfo catalog = createCatalog(source);
            ret.addReferredEntity(catalog.getEntity());
            for(AtlasEntity entity : catalog.getReferredEntities().values()){
                ret.addReferredEntity(entity);
            }
            ret.getEntity().setAttribute("catalog", AtlasTypeUtil.getAtlasObjectId(catalog.getEntity()));
        }

        ret.getEntity().setAttribute("name", schema);
        ret.getEntity().setAttribute("qualifiedName", schema);
        ret.getEntity().setAttribute("createdAt", System.currentTimeMillis());
        ret.getEntity().setAttribute("fullPath", schemaList);
        ret.getEntity().setAttribute("cluster", AtlasTypeUtil.getAtlasObjectId(cluster.getEntity()));
        ret.addReferredEntity(cluster.getEntity());
        return ret;
    }

    @Override
  public void beforeUpdate(NamespaceKey key, NameSpaceContainer v) {
    List<HookNotification> messages = new ArrayList<>();
    super.notifyEntities(messages, null);

  }

  private AtlasEntityWithExtInfo createColumn(String prefix, AtlasEntity table, String colName, String type) {
    String qualifiedName = prefix + "." + colName + "@" + this.clusterId;
    AtlasEntityWithExtInfo ret = new AtlasEntityWithExtInfo(new AtlasEntity("rf_column"));

    ret.getEntity().setAttribute("dataType", type);
    ret.getEntity().setAttribute("name", colName);
    ret.getEntity().setAttribute("qualifiedName", qualifiedName);
    ret.getEntity().setAttribute("table", AtlasTypeUtil.getAtlasObjectId(table));

    return ret;
  }

  private AtlasEntityWithExtInfo createProcess(String outputName, String sql, List<AtlasEntity> inputs, AtlasEntity output) {
    String qualifiedName = outputName + ".process@" + clusterId;

    AtlasEntityWithExtInfo ret = new AtlasEntityWithExtInfo(new AtlasEntity("rf_process"));

    ret.getEntity().setAttribute("name", output.getAttribute("qualifiedName") + ".process");
    ret.getEntity().setAttribute("qualifiedName", qualifiedName);
    ret.getEntity().setAttribute("owner", "");
    ret.getEntity().setAttribute("sql", sql);

    ret.getEntity().setRelationshipAttribute("inputs", AtlasTypeUtil.getAtlasObjectIds(inputs));
    ret.getEntity().setRelationshipAttribute("outputs", AtlasTypeUtil.getAtlasObjectIds(Collections.singletonList(output)));

    return ret;
  }
    private AtlasEntityWithExtInfo createDataSet(DatasetConfig datasetConfig) {
        AtlasEntityWithExtInfo ret = new AtlasEntityWithExtInfo(new AtlasEntity("rf_table"));
        String prefix = PathUtils.constructFullPath(datasetConfig.getFullPathList());
        String qualifiedName = prefix + "@" + this.clusterId;
        List<String> schemas = new ArrayList<>();
        if (datasetConfig.getFullPathList().size() > 1){
            schemas = datasetConfig.getFullPathList().subList(0, datasetConfig.getFullPathList().size()-1);
        }
        ret.getEntity().setAttribute("name", datasetConfig.getName());
        ret.getEntity().setAttribute("qualifiedName", qualifiedName);
        ret.getEntity().setAttribute("owner", datasetConfig.getOwner());
        ret.getEntity().setAttribute("createdAt", datasetConfig.getCreatedAt());
        ret.getEntity().setAttribute("fullPath", datasetConfig.getFullPathList());
        ret.getEntity().setAttribute("modifiedAt", datasetConfig.getLastModified());
        if (DatasetType.VIRTUAL_DATASET == datasetConfig.getType()) {
            ret.getEntity().setAttribute("tableType", "view");
            if(schemas.size() > 0){
                AtlasEntityWithExtInfo schemaRet = createSchema(schemas, "view");
                ret.getEntity().setAttribute("tableSchema", AtlasTypeUtil.getAtlasObjectId(schemaRet.getEntity()));
                ret.addReferredEntity(schemaRet.getEntity());
                addReferredEntity2NewEntity(ret, schemaRet);
            }
        } else {
            ret.getEntity().setAttribute("tableType", "table");
            AtlasEntityWithExtInfo schemaRet = createSchema(schemas, "table");
            ret.getEntity().setAttribute("tableSchema", AtlasTypeUtil.getAtlasObjectId(schemaRet.getEntity()));
            ret.addReferredEntity(schemaRet.getEntity());
            addReferredEntity2NewEntity(ret, schemaRet);
        }
        // create entities for columns
        List<AtlasEntity> columns = new ArrayList<>();
        List<Field> fields = DatasetsUtil.getFieldsFromDatasetConfig(datasetConfig);
        if(fields != null){
            for(Field field: fields){
                AtlasEntityWithExtInfo column = createColumn(prefix, ret.getEntity(), field.getName(), field.getType().name());
                ret.addReferredEntity(column.getEntity());
                columns.add(column.getEntity());
            }
            ret.getEntity().setAttribute("columns", AtlasTypeUtil.getAtlasObjectIds(columns));
        }
        return ret;
    }

    private void addReferredEntity2NewEntity(AtlasEntityWithExtInfo newRet, AtlasEntityWithExtInfo oldRet){
      for(AtlasEntity entity : oldRet.getReferredEntities().values()){
          newRet.addReferredEntity(entity);
      }
    }
  @Override
  public void afterUpdate(NamespaceKey key, NameSpaceContainer v) {
    this.initialize();
    List<HookNotification> messages = new ArrayList<>();
    DatasetConfig datasetConfig = v.getDataset();
    FolderConfig folderConfig = v.getFolder();
    SpaceConfig spaceConfig = v.getSpace();
    HomeConfig homeConfig = v.getHome();
    SourceConfig sourceConfig = v.getSource();
    if (datasetConfig != null) {
        AtlasEntityWithExtInfo ret = createDataSet(datasetConfig);
      if (DatasetType.VIRTUAL_DATASET == datasetConfig.getType()) {
        List<ParentDataset> parents = datasetConfig.getVirtualDataset().getParentsList();
        List<AtlasEntity> inputs = new ArrayList<>();
          List<AtlasEntityWithExtInfo> inputRets = new ArrayList<>();
        for(ParentDataset pd : parents){
            try {
                DatasetConfig pdConfig = this.namespaceService.getDataset(new NamespaceKey(pd.getDatasetPathList()));
                AtlasEntityWithExtInfo refRet = createDataSet(pdConfig);

                inputs.add(refRet.getEntity());
                inputRets.add(refRet);
            } catch (NamespaceException e) {
                e.printStackTrace();
            }
        }
        // create process
        AtlasEntityWithExtInfo processRet = createProcess(PathUtils.constructFullPath(datasetConfig.getFullPathList()),datasetConfig.getVirtualDataset().getSql(),inputs, ret.getEntity());
        processRet.addReferredEntity(ret.getEntity());
        for(AtlasEntity entity : inputs){
            processRet.addReferredEntity(entity);
        }
        for(AtlasEntity entity : ret.getReferredEntities().values()){
            processRet.addReferredEntity(entity);
        }

        for(AtlasEntityWithExtInfo inputRet: inputRets){
            for(AtlasEntity entity : inputRet.getReferredEntities().values()){
                processRet.addReferredEntity(entity);
            }
        }

        messages.add(new EntityUpdateRequestV2("admin", new AtlasEntitiesWithExtInfo(processRet)));
      } else {
        messages.add(new EntityUpdateRequestV2("admin", new AtlasEntitiesWithExtInfo(ret)));
      }
    } else if (folderConfig != null){
        AtlasEntityWithExtInfo ret = createSchema(folderConfig.getFullPathList(), "table");
        messages.add(new EntityUpdateRequestV2("admin", new AtlasEntitiesWithExtInfo(ret)));
    } else if(spaceConfig != null){
        List<String> fullPaths = new ArrayList<>();
        fullPaths.add(spaceConfig.getName());
        AtlasEntityWithExtInfo ret = createSchema(fullPaths, "view");
        messages.add(new EntityUpdateRequestV2("admin", new AtlasEntitiesWithExtInfo(ret)));

    } else if(homeConfig != null){
    } else if (sourceConfig != null){
        AtlasEntityWithExtInfo ret = createCatalog(sourceConfig);
        messages.add(new EntityUpdateRequestV2("admin", new AtlasEntitiesWithExtInfo(ret)));
    }
    super.notifyEntities(messages, null);
  }

  @Override
  public void beforeDelete(NamespaceKey key, String previousVersion) {
    List<HookNotification> messages = new ArrayList<>();
      this.initialize();
      List<AtlasObjectId> deleterets = new ArrayList<>();
      try {
          DatasetConfig datasetConfig = this.namespaceService.getDataset(key);
          AtlasEntityWithExtInfo ret = createDataSet(datasetConfig);

          for(AtlasEntity entity : ret.getReferredEntities().values()){
              deleterets.add(new AtlasObjectId(entity.getTypeName(), "qualifiedName", entity.getAttribute("qualifiedName")));
          }
          deleterets.add(new AtlasObjectId("rf_table", "qualifiedName", ret.getEntity().getAttribute("qualifiedName")));
          if(datasetConfig.getVirtualDataset() !=null){
              String qualifiedName = PathUtils.constructFullPath(datasetConfig.getFullPathList()) + ".process@" + clusterId;
              deleterets.add(new AtlasObjectId("rf_process", "qualifiedName", qualifiedName));
          }
      } catch (NamespaceException e) {
          e.printStackTrace();
      }
      try {
          FolderConfig folderConfig = this.namespaceService.getFolder(key);
          AtlasEntityWithExtInfo ret = createSchema(folderConfig.getFullPathList(), "table");
          deleterets.add(new AtlasObjectId("rf_schema", "qualifiedName", ret.getEntity().getAttribute("qualifiedName")));

      } catch (NamespaceException e) {
          e.printStackTrace();
      }
      try {
          SpaceConfig spaceConfig = this.namespaceService.getSpace(key);
          List<String> fullPaths = new ArrayList<>();
          fullPaths.add(spaceConfig.getName());
          AtlasEntityWithExtInfo ret = createSchema(fullPaths, "view");
          deleterets.add(new AtlasObjectId("rf_schema", "qualifiedName", ret.getEntity().getAttribute("qualifiedName")));

      } catch (NamespaceException e) {
          e.printStackTrace();
      }
//      try {
//          HomeConfig homeConfig =  this.namespaceService.getHome(key);
//      } catch (NamespaceException e) {
//          e.printStackTrace();
//      }
      try {
          SourceConfig sourceConfig =  this.namespaceService.getSource(key);
          AtlasEntityWithExtInfo ret = createCatalog(sourceConfig);
          deleterets.add(new AtlasObjectId("rf_catalog", "qualifiedName", ret.getEntity().getAttribute("qualifiedName")));

      } catch (NamespaceException e) {
          e.printStackTrace();
      }
      messages.add(new EntityDeleteRequestV2("admin", deleterets));
      super.notifyEntities(messages, null);
  }

  @Override
  public void afterDelete(NamespaceKey key, String previousVersion) {
    List<HookNotification> messages = new ArrayList<>();
    super.notifyEntities(messages, null);

  }

}
