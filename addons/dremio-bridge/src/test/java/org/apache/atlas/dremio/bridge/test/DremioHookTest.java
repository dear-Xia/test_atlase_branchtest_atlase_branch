package org.apache.atlas.dremio.bridge.test;

import org.apache.atlas.hook.AtlasHook;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.notification.HookNotification;

import java.util.ArrayList;
import java.util.List;

public class DremioHookTest extends AtlasHook {

    public void sendMessage(AtlasEntity.AtlasEntityWithExtInfo ret){
        List<HookNotification> messages = new ArrayList<>();
        messages.add(new HookNotification.EntityUpdateRequestV2("admin", new AtlasEntity.AtlasEntitiesWithExtInfo(ret)));
        super.notifyEntities(messages, null);
    }
}
