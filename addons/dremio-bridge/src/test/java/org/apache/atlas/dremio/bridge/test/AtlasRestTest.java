package org.apache.atlas.dremio.bridge.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jersey.api.client.ClientResponse;
import org.apache.atlas.AtlasClientV2;
import org.apache.atlas.AtlasServiceException;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasEntityHeader;
import org.apache.atlas.model.instance.EntityMutationResponse;
import org.apache.atlas.model.typedef.AtlasTypesDef;
import org.apache.atlas.utils.AuthenticationUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.security.UserGroupInformation;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class AtlasRestTest {

    private AtlasClientV2 atlasClientV2;

    public AtlasRestTest(AtlasClientV2 atlasClientV2) {
        this.atlasClientV2 = atlasClientV2;
    }

    public AtlasRestTest(String url, String userName, String password) {
        try {
            if (!AuthenticationUtil.isKerberosAuthenticationEnabled()) {
                String[] basicAuthUsernamePassword = new String[2];
                basicAuthUsernamePassword[0] = userName;
                basicAuthUsernamePassword[1] = password;

                atlasClientV2 = new AtlasClientV2(url.split(","), basicAuthUsernamePassword);
            } else {
                UserGroupInformation ugi = UserGroupInformation.getCurrentUser();

                atlasClientV2 = new AtlasClientV2(ugi, ugi.getShortUserName(), url.split(","));
            }
            this.atlasClientV2 = atlasClientV2;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public AtlasEntity.AtlasEntitiesWithExtInfo findByQualified(String type, List<Map<String,String>> qualified) throws AtlasServiceException {
        return atlasClientV2.getEntitiesByAttribute(type,qualified);
    }

    public AtlasEntity.AtlasEntityWithExtInfo findByQualified(String type, String qualified) throws AtlasServiceException {
        return atlasClientV2.getEntityByAttribute(type, Collections.singletonMap("qualifiedName", qualified));
    }

    public AtlasTypesDef createTypes(String jsonStr) throws AtlasServiceException, IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        AtlasTypesDef atlasTypesDef = objectMapper.readValue(jsonStr, AtlasTypesDef.class);
        return atlasClientV2.createAtlasTypeDefs(atlasTypesDef);
    }

    public EntityMutationResponse batchCreateOrUpdate(AtlasEntity.AtlasEntityWithExtInfo... entities) throws AtlasServiceException {
        AtlasEntity.AtlasEntitiesWithExtInfo entitiesWithExtInfo = new AtlasEntity.AtlasEntitiesWithExtInfo();
        for (AtlasEntity.AtlasEntityWithExtInfo entity : entities) {
            entitiesWithExtInfo.addEntity(entity.getEntity());
        }
        EntityMutationResponse response = atlasClientV2.createEntities(entitiesWithExtInfo);
//        List<AtlasEntityHeader> createdEntities = checkNull(response.getCreatedEntities());
//        List<AtlasEntityHeader> updatedEntities = checkNull(response.getUpdatedEntities());
//        System.out.println(String.format("Create %s entities, updated %s entities.", createdEntities.size(), updatedEntities.size()));
        return response;
    }


    public EntityMutationResponse batchCreateOrUpdate(AtlasEntity.AtlasEntitiesWithExtInfo entities) throws AtlasServiceException {
        EntityMutationResponse response = atlasClientV2.createEntities(entities);
//        List<AtlasEntityHeader> createdEntities = checkNull(response.getCreatedEntities());
//        List<AtlasEntityHeader> updatedEntities = checkNull(response.getUpdatedEntities());
//        System.out.println(String.format("Create %s entities, updated %s entities.", createdEntities.size(), updatedEntities.size()));
        return response;
    }

    public EntityMutationResponse batchDelete(AtlasEntity.AtlasEntitiesWithExtInfo entities) throws AtlasServiceException {
        List<String> guids = new ArrayList<>();
        List<QualifiedVo> qualifiedVos = new ArrayList<>();
        entities.getEntities().forEach(entity -> {
            if (entity != null && StringUtils.isNotBlank(entity.getGuid())) {
                guids.add(entity.getGuid());
            } else {
                qualifiedVos.add(new QualifiedVo(entity.getTypeName(), String.valueOf(entity.getAttribute("qualifiedName"))));
            }
        });
        EntityMutationResponse response = batchDelete(guids);
        for (QualifiedVo qualifiedVo : qualifiedVos) {
            delete(qualifiedVo);
        }
        return response;
    }

    public EntityMutationResponse batchDelete(List<String> guids) throws AtlasServiceException {
        EntityMutationResponse response = atlasClientV2.deleteEntitiesByGuids(guids);
//        List<AtlasEntityHeader> deletedEntities = checkNull(response.getDeletedEntities());
//        System.out.println(String.format("Delete %s entities.", deletedEntities.size()));
        return response;
    }

    public EntityMutationResponse createOrUpdate(AtlasEntity.AtlasEntityWithExtInfo entity) throws AtlasServiceException {
        EntityMutationResponse response = atlasClientV2.createEntity(entity);
//        List<AtlasEntityHeader> createdEntities = checkNull(response.getCreatedEntities());
//        List<AtlasEntityHeader> updatedEntities = checkNull(response.getUpdatedEntities());
//        System.out.println(String.format("Create %s entities, updated %s entities.", createdEntities.size(), updatedEntities.size()));
        return response;
    }

    private List<AtlasEntityHeader> checkNull(List<AtlasEntityHeader> createdEntities) {
        return createdEntities == null ? new ArrayList<>() : createdEntities;
    }

    public EntityMutationResponse delete(String  guid) throws AtlasServiceException {
        return atlasClientV2.deleteEntityByGuid(guid);
    }

    public EntityMutationResponse delete(QualifiedVo qualifiedVo) throws AtlasServiceException {
        return delete(qualifiedVo.getTypeName(), qualifiedVo.getQualified());
    }

    public EntityMutationResponse delete(List<String> guids) throws AtlasServiceException {
        try {
            final EntityMutationResponse response = atlasClientV2.deleteEntitiesByGuids(guids);
//            System.out.println(String.format("Delete %s entities.", checkNull(response.getDeletedEntities()).size()));
            return response;
        }catch (AtlasServiceException e) {
            if (e.getStatus() == ClientResponse.Status.NOT_FOUND) {
                return null;
            }
            throw e;
        }
    }

    public EntityMutationResponse delete(final String typeName, final String qualifiedName) throws AtlasServiceException {
        EntityMutationResponse ret = null;
        int size = 0;
        try {
            ret = atlasClientV2.deleteEntityByAttribute(typeName, Collections.singletonMap("qualifiedName", qualifiedName));
            size = checkNull(ret.getDeletedEntities()).size();
        } catch (AtlasServiceException e) {
            if (e.getStatus() == ClientResponse.Status.NOT_FOUND) {
                size = 0;
            }
            throw e;
        }
//        System.out.println(String.format("Delete %s entities.", size));
        return ret;
    }

    public static class QualifiedVo {
        private String typeName;
        private String qualified;

        public QualifiedVo(String typeName, String qualified) {
            this.typeName = typeName;
            this.qualified = qualified;
        }

        public String getTypeName() {
            return typeName;
        }

        public void setTypeName(String typeName) {
            this.typeName = typeName;
        }

        public String getQualified() {
            return qualified;
        }

        public void setQualified(String qualified) {
            this.qualified = qualified;
        }
    }

}
