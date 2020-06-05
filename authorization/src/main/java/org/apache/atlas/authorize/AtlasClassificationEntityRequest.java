package org.apache.atlas.authorize;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class AtlasClassificationEntityRequest extends AtlasAccessRequest {

    private Set<String> classificationEntities;
    private Set<String> classificationEntityTypes;
    private Set<String> classificationEntityIds;

    public AtlasClassificationEntityRequest(AtlasPrivilege action) {
        super(action);
    }

    public AtlasClassificationEntityRequest(AtlasPrivilege action, String classificationEntity, String classificationEntityType, String classificationEntityId) {
        super(action);
        this.classificationEntityIds = new HashSet<>();
        this.classificationEntityTypes = new HashSet<>();
        this.classificationEntities = new HashSet<>();
        this.classificationEntities.add(classificationEntity);
        this.classificationEntityTypes.add(classificationEntityType);
        this.classificationEntityIds.add(classificationEntityId);
    }

    public AtlasClassificationEntityRequest(AtlasPrivilege action, Set<String> classificationEntity, Set<String> classificationEntityTypes, Set<String> classificationEntityIds) {
        super(action);
        this.classificationEntityIds = classificationEntityIds;
        this.classificationEntityTypes =  classificationEntityTypes;
        this.classificationEntities = classificationEntity;
    }

    public AtlasClassificationEntityRequest(AtlasPrivilege action, String user, Set<String> userGroups) {
        super(action, user, userGroups);
    }

    public AtlasClassificationEntityRequest(AtlasPrivilege action, String user, Set<String> userGroups, String classificationEntity, String classificationEntityType, String classificationEntityId) {
        super(action, user, userGroups);
        this.classificationEntityIds = new HashSet<>();
        this.classificationEntityTypes = new HashSet<>();
        this.classificationEntities = new HashSet<>();
        this.classificationEntities.add(classificationEntity);
        this.classificationEntityTypes.add(classificationEntityType);
        this.classificationEntityIds.add(classificationEntityId);
    }

    public AtlasClassificationEntityRequest(AtlasPrivilege action, String user, Set<String> userGroups, Set<String> classificationEntity, Set<String> classificationEntityTypes, Set<String> classificationEntityIds) {
        super(action, user, userGroups);
        this.classificationEntityIds = classificationEntityIds;
        this.classificationEntityTypes =  classificationEntityTypes;
        this.classificationEntities = classificationEntity;
    }

    public AtlasClassificationEntityRequest(AtlasPrivilege action, String user, Set<String> userGroups, Date accessTime, String clientIPAddress) {
        super(action, user, userGroups, accessTime, clientIPAddress);
    }

    public void addClassificationEntity(String classification) {
        if(classificationEntities == null){
            classificationEntities = new HashSet<>();
        }
        classificationEntities.add(classification);
    }

    public Set<String> getClassificationEntities() {
        return classificationEntities;
    }

    public void setClassificationEntities(Set<String> classificationEntities) {
        this.classificationEntities = classificationEntities;
    }

    public void addClassificationEntityType(String entityType) {
        if(classificationEntityTypes == null){
            classificationEntityTypes = new HashSet<>();
        }
        classificationEntityTypes.add(entityType);
    }

    public Set<String> getClassificationEntityTypes() {
        return classificationEntityTypes;
    }

    public void setClassificationEntityTypes(Set<String> classificationEntityTypes) {
        this.classificationEntityTypes = classificationEntityTypes;
    }

    public void addClassificationEntityId(String classificationEntityId) {
        if(classificationEntityIds == null){
            classificationEntityIds = new HashSet<>();
        }
        classificationEntityIds.add(classificationEntityId);
    }

    public Set<String> getClassificationEntityIds() {
        return classificationEntityIds;
    }

    public void setClassificationEntityIds(Set<String> classificationEntityIds) {
        this.classificationEntityIds = classificationEntityIds;
    }
}
