package de.fimmonline.keycloak.events.logging;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;


public class LastEmailVerificationEventListenerProviderFactory implements EventListenerProviderFactory {

    @Override
    public LastEmailVerificationEventListenerProvider create(KeycloakSession keycloakSession) {
        return new LastEmailVerificationEventListenerProvider(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {
        //
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        //
    }

    @Override
    public void close() {
        //
    }

    @Override
    public String getId() {
        return "last_email_verification";
    }

}
