package com.axway.security;

import java.security.Provider;
import java.util.List;
import java.util.Map;

import com.vordel.security.openssl.Key;

/**
 * This security provider makes the internal keystore of the API gateway available as a standard PKCS11 
 * keystore and can therefore be used in other Java libraries.  
 * To enable, please modify the security providers in:
 * <pre>system/conf/jvm.xml</pre>
 * Add the following provider. It's recommended to add it after the OSSLProvider
 * <pre>{@code
 * <SecurityProvider index="3" name="com.axway.security.APIGatewayHSMPKCS11Provider" />
 * }</pre>
 * With the current version only private keys can be loaded from the HSM, because the returned keystore is fixed to HSM.
 * Example code:
 * <pre>{@code
 * Keystore keystore = KeyStore.getInstance("PKCS11", "AxwayAPIGWPCKS11");
 * keyStore.load(zero, zero);
 * keyStore.getKey("changeforprod", zero);
 * }</pre>
 * This loads the Keystore with type: PKCS11 from the Security-Provider: AxwayAPIGWPCKS11, 
 * initialized it and requests a private key which is then loaded from the HSM.
 * The KeyId is a previously configured CertificateRealm. 
 * 
 * @author cwiechmann (Axway)
 *
 */
public class APIGatewayHSMPKCS11Provider extends Provider {

	private static final long serialVersionUID = 1L;

	public APIGatewayHSMPKCS11Provider() {
		super("AxwayAPIGWPKCS11", 1.0, "Security provider to internal HSM-Keystore.");
		putService(new OSSLKeyService("KeyStore", "PKCS11", PKCS11KeystoreSpi.class, null, null));
	}

	private class OSSLKeyService extends OSSLService {

		public boolean supportsParameter(Object param) {
			return param instanceof Key;
		}

		public OSSLKeyService(String type, String algorythm, Class<?> classType, List<String> aliases,
				Map<String, String> attributes) {
			super(type, algorythm, classType, aliases, attributes);
		}
	}

	private class OSSLService extends Provider.Service {

		public OSSLService(String type, String algorithm, Class<?> classType, List<String> aliases,
				Map<String, String> attributes) {
			super(APIGatewayHSMPKCS11Provider.this, type, algorithm, classType.getName(), aliases, attributes);
		}

		public Object newInstance(Object param) {
			return new PKCS11KeystoreSpi();
		}
	}
}
