package de.fimmonline.keycloak.events.logging;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmProvider;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class LastEmailVerificationEventListenerProvider implements EventListenerProvider {

    private static final Logger log = Logger.getLogger(LastEmailVerificationEventListenerProvider.class);

    private final KeycloakSession session;
    private final RealmProvider model;

    public LastEmailVerificationEventListenerProvider(KeycloakSession session) {
        this.session = session;
        this.model = session.realms();
    }

    @Override
    public void onEvent(Event event) {
        if (!EventType.VERIFY_EMAIL.equals(event.getType())) {
            return;
        }
        var realm = model.getRealm(event.getRealmId());
        var user = session.users().getUserById(realm, event.getUserId());

        if (user == null) {
            return;
        }
        log.info("Updating last email verification status for user: " + user.getUsername());

        // Use current server time for login event
        var verificationTime = ZonedDateTime.now(ZoneOffset.UTC);
        var verificationTimeS = DateTimeFormatter.ISO_DATE_TIME.format(verificationTime);
        user.setSingleAttribute("last-email-verification", verificationTimeS);
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean b) {
    }

    @Override
    public void close() {
        // Nothing to close
    }

}
