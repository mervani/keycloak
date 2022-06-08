package org.keycloak.examples.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

public class CustomOTPProvider implements Authenticator {
    private static Map<String, String> otpMap;
    static {
        otpMap = new HashMap<>();
        otpMap.put("testuser", "hello");
    }
    @Override public void authenticate(AuthenticationFlowContext context) {
        Response challenge = context.form().createForm("otp-input.ftl");
        context.challenge(challenge);

    }

    @Override public void action(AuthenticationFlowContext context) {

        boolean validated = validateAnswer(context);
        if (!validated) {
            Response challenge = context.form().setError("badOtp").createForm("otp-input.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }
        context.success();

    }

    private boolean validateAnswer(AuthenticationFlowContext context) {
        String username = context.getUser().getUsername();

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        String conf = config.getConfig().get("otp.endpoint");
        String ep = String.valueOf(conf == null ? "" : conf);

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String secret = formData.getFirst("secret_answer");

        System.out.format("This is the username: %s; endpoint: %s; secret: %s, res: %s\n", username, ep, secret, secret.trim().equals(otpMap.get(username).trim()));

        return secret == null ? false : secret.trim().equals(otpMap.get(username).trim());
    }

    @Override public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override public void close() {

    }
}
