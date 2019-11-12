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

import java.util.ArrayList;
import java.util.List;

import org.apache.atlas.hook.AtlasHook;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasEntity.AtlasEntitiesWithExtInfo;
import org.apache.atlas.model.instance.AtlasEntity.AtlasEntityWithExtInfo;
import org.apache.atlas.model.notification.HookNotification;
import org.apache.atlas.model.notification.HookNotification.EntityUpdateRequestV2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.dremio.common.utils.PathUtils;
import com.dremio.dac.model.common.Field;
import com.dremio.dac.util.DatasetsUtil;
import com.dremio.service.SingletonRegistry;
import com.dremio.service.namespace.NameSpaceChangeListener;
import com.dremio.service.namespace.NamespaceKey;
import com.dremio.service.namespace.dataset.proto.DatasetConfig;
import com.dremio.service.namespace.dataset.proto.DatasetType;
import com.dremio.service.namespace.dataset.proto.PhysicalDataset;
import com.dremio.service.namespace.dataset.proto.VirtualDataset;
import com.dremio.service.namespace.proto.NameSpaceContainer;

/**
 * Dremio hook used for atlas entity registration.
 */
public class DremioHook extends AtlasHook implements NameSpaceChangeListener {
  private static final Logger LOG = LoggerFactory.getLogger(DremioHook.class);

  public DremioHook() {
  }

  @Override
  public void init(SingletonRegistry registry) {
  }

  @Override
  public void beforeUpdate(NamespaceKey key, NameSpaceContainer v) {
    List<HookNotification> messages = new ArrayList<>();
    DatasetConfig datasetConfig = v.getDataset();
    if (datasetConfig != null) {
      List<Field> fields = DatasetsUtil.getFieldsFromDatasetConfig(datasetConfig);
      AtlasEntityWithExtInfo ret = new AtlasEntityWithExtInfo(new AtlasEntity("rf_table"));
      String prefix = PathUtils.constructFullPath(datasetConfig.getFullPathList());
      String qualifiedName = prefix + "@dremioTest";
      if (DatasetType.VIRTUAL_DATASET == datasetConfig.getType()) {
        VirtualDataset vds = datasetConfig.getVirtualDataset();
        ret.getEntity().setAttribute("name", datasetConfig.getName());
        ret.getEntity().setAttribute("qualifiedName", qualifiedName);
        ret.getEntity().setAttribute("owner", datasetConfig.getOwner());
        ret.getEntity().setAttribute("createdAt", datasetConfig.getCreatedAt());
        ret.getEntity().setAttribute("tableType", "view");
        ret.getEntity().setAttribute("fullPath", datasetConfig.getFullPathList());
        ret.getEntity().setAttribute("modifiedAt", datasetConfig.getLastModified());
        messages.add(new EntityUpdateRequestV2("admin", new AtlasEntitiesWithExtInfo(ret)));
      } else {
        PhysicalDataset pds = datasetConfig.getPhysicalDataset();
        ret.getEntity().setAttribute("name", datasetConfig.getName());
        ret.getEntity().setAttribute("qualifiedName", qualifiedName);
        ret.getEntity().setAttribute("owner", datasetConfig.getOwner());
        ret.getEntity().setAttribute("createdAt", datasetConfig.getCreatedAt());
        ret.getEntity().setAttribute("tableType", "table");
        ret.getEntity().setAttribute("fullPath", datasetConfig.getFullPathList());
        ret.getEntity().setAttribute("modifiedAt", datasetConfig.getLastModified());
        messages.add(new EntityUpdateRequestV2("admin", new AtlasEntitiesWithExtInfo(ret)));

      }
      // create entities for columns
      // for (Field field : fields) {
      // }
      super.notifyEntities(messages, null);
    }

  }

  @Override
  public void afterUpdate(NamespaceKey key, NameSpaceContainer v) {
    List<HookNotification> messages = new ArrayList<>();
    super.notifyEntities(messages, null);
  }

  @Override
  public void beforeDelete(NamespaceKey key, String previousVersion) {
    List<HookNotification> messages = new ArrayList<>();
    super.notifyEntities(messages, null);
  }

  @Override
  public void afterDelete(NamespaceKey key, String previousVersion) {
    List<HookNotification> messages = new ArrayList<>();
    super.notifyEntities(messages, null);

  }

}
