package org.apache.atlas.dremio.bridge;

import com.sun.jersey.api.client.ClientResponse;
import org.apache.atlas.AtlasClientV2;
import org.apache.atlas.AtlasServiceException;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasEntity.AtlasEntitiesWithExtInfo;
import org.apache.atlas.model.instance.AtlasEntity.AtlasEntityWithExtInfo;
import org.apache.atlas.model.instance.AtlasEntityHeader;
import org.apache.atlas.model.instance.EntityMutationResponse;
import org.apache.atlas.model.instance.EntityMutations;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class AtlasEntityBuilder {

  protected final AtlasClientV2 atlasClientV2;

  private static final Logger LOG = LoggerFactory.getLogger(AtlasEntityBuilder.class);

  public AtlasEntityBuilder(AtlasClientV2 atlasClientV2) {
    this.atlasClientV2 = atlasClientV2;
  }

  public AtlasEntity getEntityByName(String type, String attrName, String attrValue) throws AtlasServiceException {
    AtlasEntityWithExtInfo entityWithExtInfo = atlasClientV2.getEntityByAttribute(type, Collections.singletonMap(attrName, attrValue));
    if (entityWithExtInfo != null)
      return entityWithExtInfo.getEntity();
    return null;
  }

  /***
   * find eneity using 'qualifiedName'
   * 
   * @param typeName
   * @param qualifiedName
   * @return
   * @throws AtlasServiceException
   */
  public AtlasEntityWithExtInfo findEntity(final String typeName, final String qualifiedName) throws AtlasServiceException {
    AtlasEntityWithExtInfo ret = null;

    try {
      ret = atlasClientV2.getEntityByAttribute(typeName, Collections.singletonMap("qualifiedName", qualifiedName));
    } catch (AtlasServiceException e) {
      if (e.getStatus() == ClientResponse.Status.NOT_FOUND) {
        return new AtlasEntityWithExtInfo(new AtlasEntity(typeName));
      }

      throw e;
    }

    clearRelationshipAttributes(ret);

    return ret;
  }

  /**
   * Registers an entity in atlas
   * 
   * @param entity
   * @return
   * @throws Exception
   */
  protected AtlasEntityWithExtInfo registerInstance(AtlasEntityWithExtInfo entity) throws Exception {
    AtlasEntityWithExtInfo ret = null;
    EntityMutationResponse response = atlasClientV2.createEntity(entity);
    List<AtlasEntityHeader> createdEntities = response.getEntitiesByOperation(EntityMutations.EntityOperation.CREATE);

    if (CollectionUtils.isNotEmpty(createdEntities)) {
      for (AtlasEntityHeader createdEntity : createdEntities) {
        if (ret == null) {
          ret = atlasClientV2.getEntityByGuid(createdEntity.getGuid());

        } else if (ret.getEntity(createdEntity.getGuid()) == null) {
          AtlasEntityWithExtInfo newEntity = atlasClientV2.getEntityByGuid(createdEntity.getGuid());

          ret.addReferredEntity(newEntity.getEntity());

          if (MapUtils.isNotEmpty(newEntity.getReferredEntities())) {
            for (Map.Entry<String, AtlasEntity> entry : newEntity.getReferredEntities().entrySet()) {
              ret.addReferredEntity(entry.getKey(), entry.getValue());
            }
          }

        }
      }
    }

    clearRelationshipAttributes(ret);

    return ret;
  }

  /**
   * Registers an entity in atlas
   * 
   * @param entities
   * @return
   * @throws Exception
   */
  protected AtlasEntitiesWithExtInfo registerInstances(AtlasEntitiesWithExtInfo entities) throws Exception {

    EntityMutationResponse response = atlasClientV2.createEntities(entities);
    List<AtlasEntityHeader> createdEntities = response.getEntitiesByOperation(EntityMutations.EntityOperation.CREATE);
    return clearAfterCreate(createdEntities);
    // if (CollectionUtils.isNotEmpty(createdEntities)) {
    // ret = new AtlasEntitiesWithExtInfo();
    //
    // for (AtlasEntityHeader createdEntity : createdEntities) {
    // AtlasEntityWithExtInfo entity = atlasClientV2.getEntityByGuid(createdEntity.getGuid());
    //
    // ret.addEntity(entity.getEntity());
    //
    // if (MapUtils.isNotEmpty(entity.getReferredEntities())) {
    // for (Map.Entry<String, AtlasEntity> entry : entity.getReferredEntities().entrySet()) {
    // ret.addReferredEntity(entry.getKey(), entry.getValue());
    // }
    // }
    //
    // }
    // }
    //
    // clearRelationshipAttributes(ret);

    // return ret;
  }

  protected AtlasEntitiesWithExtInfo clearAfterCreate(List<AtlasEntityHeader> createdEntities) throws AtlasServiceException {
    AtlasEntitiesWithExtInfo ret = null;
    if (CollectionUtils.isNotEmpty(createdEntities)) {
      ret = new AtlasEntitiesWithExtInfo();

      for (AtlasEntityHeader createdEntity : createdEntities) {
        AtlasEntityWithExtInfo entity = atlasClientV2.getEntityByGuid(createdEntity.getGuid());

        ret.addEntity(entity.getEntity());

        if (MapUtils.isNotEmpty(entity.getReferredEntities())) {
          for (Map.Entry<String, AtlasEntity> entry : entity.getReferredEntities().entrySet()) {
            ret.addReferredEntity(entry.getKey(), entry.getValue());
          }
        }

      }
    }

    clearRelationshipAttributes(ret);
    return ret;
  }

  public void updateInstance(AtlasEntityWithExtInfo entity) throws AtlasServiceException {

    atlasClientV2.updateEntity(entity);

  }

  public void clearRelationshipAttributes(AtlasEntitiesWithExtInfo entities) {
    if (entities != null) {
      if (entities.getEntities() != null) {
        for (AtlasEntity entity : entities.getEntities()) {
          clearRelationshipAttributes(entity);
          ;
        }
      }

      if (entities.getReferredEntities() != null) {
        clearRelationshipAttributes(entities.getReferredEntities().values());
      }
    }
  }

  public void clearRelationshipAttributes(AtlasEntityWithExtInfo entity) {
    if (entity != null) {
      clearRelationshipAttributes(entity.getEntity());

      if (entity.getReferredEntities() != null) {
        clearRelationshipAttributes(entity.getReferredEntities().values());
      }
    }
  }

  public void clearRelationshipAttributes(Collection<AtlasEntity> entities) {
    if (entities != null) {
      for (AtlasEntity entity : entities) {
        clearRelationshipAttributes(entity);
      }
    }
  }

  public void clearRelationshipAttributes(AtlasEntity entity) {
    if (entity != null && entity.getRelationshipAttributes() != null) {
      entity.getRelationshipAttributes().clear();
    }
  }

  /***
   * TODO: batch , table with columns should cache column
   * 
   * @param entity
   * @return
   * @throws AtlasServiceException
   */
  public AtlasEntity createInstance(AtlasEntity entity) throws AtlasServiceException {
    AtlasEntityWithExtInfo entityWithExtInfo = new AtlasEntityWithExtInfo(entity);
    return createInstance(entityWithExtInfo).getEntity();
  }

  public List<AtlasEntityHeader> deleteInstance(final String typeName, final String qualifiedName) throws AtlasServiceException {
    EntityMutationResponse ret = null;

    try {
      ret = atlasClientV2.deleteEntityByAttribute(typeName, Collections.singletonMap("qualifiedName", qualifiedName));
    } catch (AtlasServiceException e) {
      if (e.getStatus() == ClientResponse.Status.NOT_FOUND) {
        return null;
      }

      throw e;
    }

    return ret.getDeletedEntities();

  }

  public AtlasEntityWithExtInfo createInstance(AtlasEntityWithExtInfo entity) throws AtlasServiceException {
    AtlasEntityWithExtInfo entityWithExtInfo = null;
    EntityMutationResponse response = atlasClientV2.createEntity(entity);
    List<AtlasEntityHeader> entities = response.getCreatedEntities();
    List<AtlasEntityHeader> updatedEntities = response.getUpdatedEntities();
    String guid = "";
    String opName = "";
    if (CollectionUtils.isNotEmpty(entities)) {
      guid = entities.get(0).getGuid();
      opName = "Create";
      // clearAfterCreate(entities);
    } else if (CollectionUtils.isNotEmpty(updatedEntities)) {
      guid = updatedEntities.get(0).getGuid();
      opName = "Update";
      // clearAfterCreate(updatedEntities);
    }
    if (!StringUtils.isEmpty(guid)) {
      entityWithExtInfo = atlasClientV2.getEntityByGuid(guid);
      System.out.println(opName + " entity of type [" + entityWithExtInfo.getEntity().getTypeName() + "], guid: " + entityWithExtInfo.getEntity().getGuid() + " name: "
          + entityWithExtInfo.getEntity().getAttribute("qualifiedName"));
    } else {
      return entity;
    }
    clearRelationshipAttributes(entityWithExtInfo);
    return entityWithExtInfo;
  }

}
