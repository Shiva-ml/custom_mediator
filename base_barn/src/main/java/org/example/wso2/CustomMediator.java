package org.example.wso2;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.ParseException;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Map;

public class CustomMediator extends AbstractMediator {
    private static final Log log = LogFactory.getLog(CustomMediator.class);

    @Override
    public boolean mediate(MessageContext synCtx) {

        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) synCtx)
                .getAxis2MessageContext();

        try {
            JSONObject jsonObject = new JSONObject(JsonUtil.jsonPayloadToString(axis2MessageContext));
            synCtx.setProperty("JWT_AUD", jsonObject.getJSONObject("dev").getString("name"));

            if (jsonObject.has("dev") && jsonObject.getJSONObject("dev").has("name")
                    && "medium".equals((String) jsonObject.getJSONObject("dev").get("name"))) {
                jsonObject.getJSONObject("dev").put("name", "Athiththan");

            }
            synCtx.setProperty("JWT_SUB", jsonObject.getJSONObject("dev").getString("name"));


            JsonUtil.newJsonPayload(axis2MessageContext, jsonObject.toString(), true, true);

        } catch (JSONException e) {
            log.error("approach failed");
            e.printStackTrace();
        }

        return true;
    }
}









