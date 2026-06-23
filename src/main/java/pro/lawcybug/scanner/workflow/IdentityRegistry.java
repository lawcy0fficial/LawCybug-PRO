package pro.lawcybug.scanner.workflow;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Central registry of {@link SessionIdentity} objects configured by the user
 * in the Settings/Identities UI tab. Detectors pull "Victim"/"Attacker"
 * identities from here by role rather than each detector inventing its own
 * "secondarySessionHeaderValue"-style setting -- this is what lets every
 * BOLA/ATO/privilege-escalation check share one consistent multi-user setup.
 */
public final class IdentityRegistry {

    private final Map<String, SessionIdentity> identities = new LinkedHashMap<>();

    public void register(SessionIdentity identity) {
        identities.put(identity.name(), identity);
    }

    public Optional<SessionIdentity> byName(String name) {
        return Optional.ofNullable(identities.get(name));
    }

    public Optional<SessionIdentity> byRole(SessionIdentity.Role role) {
        return identities.values().stream()
                .filter(i -> i.role() == role)
                .findFirst();
    }

    public Map<String, SessionIdentity> all() {
        return identities;
    }

    public boolean hasMultiUserSetup() {
        return byRole(SessionIdentity.Role.VICTIM).isPresent()
                && byRole(SessionIdentity.Role.ATTACKER).isPresent();
    }
}
