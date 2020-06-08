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
package org.apache.atlas.authorize;

public enum AtlasPrivilege {
     TYPE_CREATE("type-create"),
     TYPE_UPDATE("type-update"),
     TYPE_DELETE("type-delete"),
     TYPE_READ("type-read"),
     ADD_CHILD_CLASSIFICATION("add-child-classification"),
     UPDATE_CHILD_CLASSIFICATION("update-child-classification"),
     REMOVE_CHILD_CLASSIFICATION("remove-child-classification"),
     AUTHORIZE_CHILD_CLASSIFICATION("authorize-child-classification"),


     ADD_CLASSIFICATION_TABLES("add-classification-tables"),
     UPDATE_CLASSIFICATION_TABLES("update-classification-tables"),
     REMOVE_CLASSIFICATION_TABLES("remove-classification-tables"),

     ENTITY_READ("entity-read"),
     ENTITY_CREATE("entity-create"),
     ENTITY_UPDATE("entity-update"),
     ENTITY_DELETE("entity-delete"),
     ENTITY_READ_CLASSIFICATION("entity-read-classification"),
     ENTITY_ADD_CLASSIFICATION("entity-add-classification"),
     ENTITY_UPDATE_CLASSIFICATION("entity-update-classification"),
     ENTITY_REMOVE_CLASSIFICATION("entity-remove-classification"),

     ADMIN_EXPORT("admin-export"),
     ADMIN_IMPORT("admin-import"),

     RELATIONSHIP_ADD("add-relationship"),
     RELATIONSHIP_UPDATE("update-relationship"),
     RELATIONSHIP_REMOVE("remove-relationship");

     private final String type;

     AtlasPrivilege(String actionType){
           this.type = actionType;
     }

     public String getType() {
          return type;
     }
}
