package org.joget.marketplace;

import java.util.ArrayList;
import java.util.Collection;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;

public class Activator implements BundleActivator {

    protected Collection<ServiceRegistration> registrationList;

    public static final String MESSAGE_PATH = "messages/MandatoryMfaSecurityEnhancedDirectoryManager";

    public void start(BundleContext context) {
        registrationList = new ArrayList<ServiceRegistration>();

        //Register plugin here
        registrationList.add(context.registerService(MandatoryMfaSecurityEnhancedDirectoryManager.class.getName(), new MandatoryMfaSecurityEnhancedDirectoryManager(), null));
        registrationList.add(context.registerService(MandatoryMfaUserSecurityImpl.class.getName(), new MandatoryMfaUserSecurityImpl(), null));
        registrationList.add(context.registerService(MandatoryTotpMfaAuthenticator.class.getName(), new MandatoryTotpMfaAuthenticator(), null));
    }

    public void stop(BundleContext context) {
        for (ServiceRegistration registration : registrationList) {
            registration.unregister();
        }
    }
}