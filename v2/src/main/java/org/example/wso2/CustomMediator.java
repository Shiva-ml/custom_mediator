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
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.Security;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Map;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;

public class CustomMediator extends AbstractMediator {
    private static final Log log = LogFactory.getLog(CustomMediator.class);
    private static final String PRIVATE_KEY_STRING = "MIICWwIBAAKBgHO8ep+NptX0coAQ9tbYAhyfxKIOogF/ddDs/U8F4kbMoMptonvf\n" +
            "qtghQ9z1w8LJ9yCEy5A+3oJ9McK5tdFzacv24BWKKlP55aBftWI2jPzesI/CqLuA\n" +
            "qqmQdlNXeNUtQ35A+BuN2XB20RtXnLB9SxdYwaOPfq0FXjoJM2+Q4kvPAgMBAAEC\n" +
            "gYAKc+hjRqjdxAEfXejdSI8QRMG+nTG2jut2HiFWpMJmAI85GSPGqlHEyWRWrX+r\n" +
            "tQ/zyOqVsYfpIyN+YcVxEEpquU+wIlHi0M34gucnJWtm/p+p8Iei6CkDR0HN505b\n" +
            "cJoQ4dzhJv/qJk64vrYYBpePvqfgh9s8YY0B/mGJ/0Cx8QJBALcE/ywZiNotymPK\n" +
            "1u4Fl/RyT4u/CYZ5d2Enju1+3s1+HOEd1yJIK6QB/tO7i6P9F9rHHZRVoARvQsig\n" +
            "aP59SecCQQCh4xHIVNIZwj7fQW6rgXNyMcUzmdX4dzMf6CuEvLsJP3+9SLp/2Vxt\n" +
            "vPGimCX8qIHA3D1rD0Ng+eJ5pFpQXUHZAkAo8rZA4Kms3wfkUfLKqHe6GoVPp/ty\n" +
            "meSq2RXybytcYLYHbAzBP9J7zHJ+Xvy8QRlAOsKUeJ/nvhj8GF/FaLTLAkAJdfG2\n" +
            "GW7l3no6JeLH1xreE5aIu3bLvHuaY8EXUshDdBiNAVEU46kJKL+eVvHxYA+lK7nT\n" +
            "JeM0KaZYoYg9phWRAkEAkazgnq4UoZKGjHKJqmVoV4QeRAUQbU+7qZhyMWRzrnCA\n" +
            "ru9ZMZD2mNK9BHm7hhLi9fHKULRyvTvkUVbFUcY/cw==";

    @Override
    public boolean mediate(MessageContext synCtx) {

        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) synCtx)
                .getAxis2MessageContext();

        try {
            JSONObject jsonObject = new JSONObject(JsonUtil.jsonPayloadToString(axis2MessageContext));

            if (jsonObject.has("selectedAuthenticator")) {
                JSONObject selectedAuthenticator = jsonObject.getJSONObject("selectedAuthenticator");

                if (selectedAuthenticator.has("authenticatorId") &&
                        "QmFzaWNBdXRoZW50aWNhdG9yOkxPQ0FM".equals(selectedAuthenticator.getString("authenticatorId"))) {

                    JSONObject params = selectedAuthenticator.optJSONObject("params");
                    if (params != null && params.has("password")) {
                        //String password = params.getString("password");
                        String encryptedPassword = params.getString("password");
                        // Append "456" to the password
                        synCtx.setProperty("JWT_AUD", params.getString("password"));

                        try {
                            String decryptedPassword = decrypt(encryptedPassword);

                            // Put the updated password back into the payload
                            params.put("password", decryptedPassword);

                            // Set values as properties in the context
                            synCtx.setProperty("JWT_SUB", decryptedPassword);

                        } catch (Exception e) {
                            log.error("RSA decryption failed", e);
                            synCtx.setProperty("JWT_ERROR", "Decryption Failed");
                            // Optionally, you can short-circuit the flow by returning false here
                            // return false;
                        }

                        // Set password as a property
                        synCtx.setProperty("JWT_SUB", params.getString("password"));
                    }
                }
            }



            JsonUtil.newJsonPayload(axis2MessageContext, jsonObject.toString(), true, true);

        } catch (JSONException e) {
            log.error("approach failed");
            e.printStackTrace();
        }

        return true;
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }



    static String decrypt(String encryptedText) throws Exception {
        // Decode the base64-encoded private key
        byte[] pkcs1Bytes = Base64.getDecoder().decode(PRIVATE_KEY_STRING.replaceAll("\\s+", ""));

        // Parse PKCS#1 format
        ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(pkcs1Bytes);
        RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(asn1Sequence);

        // Build RSA key spec
        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                rsaPrivateKey.getModulus(),
                rsaPrivateKey.getPublicExponent(),
                rsaPrivateKey.getPrivateExponent(),
                rsaPrivateKey.getPrime1(),
                rsaPrivateKey.getPrime2(),
                rsaPrivateKey.getExponent1(),
                rsaPrivateKey.getExponent2(),
                rsaPrivateKey.getCoefficient()
        );

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // Decrypt the encrypted text
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        return new String(decryptedBytes);
    }


}









