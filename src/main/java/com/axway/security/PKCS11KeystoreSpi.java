package com.axway.security;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

import com.vordel.store.cert.CertStore;

/**
 * This class implements the java.lang.Keystore and forwards requests to the internal API gateway CertStore, which is already initialized.
 * 
 * @author cwiechmann (Axway)
 *
 */
public class PKCS11KeystoreSpi extends KeyStoreSpi {

	public PKCS11KeystoreSpi() {
	}

	/**
	 * Returns a key from the internal API gateway CertStore (HSM only)
	 */
	@Override
	public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
		// Map given parameters into the expected format by the CertStore
		CertEntity certEntity = new CertEntity();
		certEntity.setStoreType("HSM");
		certEntity.setCertificateRealm(alias);
		System.out.println("Requesting key from API-Gateway certificate store: " + certEntity);
		Key key = CertStore.getPrivateKey(certEntity, null);
		return key;
	}
	
	@Override
	public void engineLoad(InputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		// Do nothing, as the internal CertStore is already initialized
		return;
	}
	
	@Override
	public boolean engineContainsAlias(String alias) {
		if(CertStore.getInstance().getPersonalInfoByAlias(alias)==null) {
			System.out.println("engineContainsAlias - alias: '"+alias+"' is unknown");
			return false;
		} else {
			System.out.println("engineContainsAlias - alias: '"+alias+"' found");
			return true;
		}
	}
	
	@Override
	public Certificate engineGetCertificate(String alias) {
		System.out.println("engineGetCertificate - return certificate for alias: '"+alias+"'");
		//return CertStore.getInstance().getPersonalInfoByAlias(alias).certificate;
		try {
			return CertStore.getInstance().getKeyStore().getCertificate(alias);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error getting certificate for alias: '"+alias+"' from underlying CertStore.keystore", e);
		}
	}

	@Override
	public Certificate[] engineGetCertificateChain(String alias) {
		System.out.println("engineGetCertificate - return certificate chain for alias: '"+alias+"'");
		//return CertStore.getInstance().getPersonalInfoByAlias(alias).chain;
		try {
			return CertStore.getInstance().getKeyStore().getCertificateChain(alias);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error getting certificate chain for alias: '"+alias+"'  from underlying CertStore.keystore", e);
		}
	}
	
	@Override
	public Enumeration<String> engineAliases() {
		try {
			return CertStore.getInstance().getKeyStore().aliases();
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error getting aliases from underlying CertStore.keystore", e);
		}
	}

	@Override
	public Date engineGetCreationDate(String alias) {
		try {
			return CertStore.getInstance().getKeyStore().getCreationDate(alias);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error getting creation date for alias: '"+alias+"' from underlying CertStore.keystore", e);
		}
	}

	@Override
	public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
			throws KeyStoreException {
		throw new UnsupportedOperationException("Method 'engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)' is not supported by the PKCS#11 keystore.");
	}

	@Override
	public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
		throw new UnsupportedOperationException("Method 'engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)' is not supported by the PKCS#11 keystore.");
	}

	@Override
	public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
		throw new UnsupportedOperationException("Method 'engineSetCertificateEntry(String alias, Certificate cert)' is not supported by the PKCS#11 keystore.");
	}

	@Override
	public void engineDeleteEntry(String alias) throws KeyStoreException {
		throw new UnsupportedOperationException("Method 'engineDeleteEntry(String alias)' is not supported by the PKCS#11 keystore.");
	}

	@Override
	public int engineSize() {
		try {
			return CertStore.getInstance().getKeyStore().size();
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error getting size from underlying CertStore.keystore", e);
		}
	}

	@Override
	public boolean engineIsKeyEntry(String alias) {
		try {
			return CertStore.getInstance().getKeyStore().isKeyEntry(alias);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error when calling IsKeyEntry for alias: '"+alias+"' on underlying CertStore.keystore", e);
		}
	}

	@Override
	public boolean engineIsCertificateEntry(String alias) {
		try {
			return CertStore.getInstance().getKeyStore().isCertificateEntry(alias);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error when calling IsCertificateEntry for alias: '"+alias+"' on underlying CertStore.keystore", e);
		}
	}

	@Override
	public String engineGetCertificateAlias(Certificate cert) {
		try {
			return CertStore.getInstance().getKeyStore().getCertificateAlias(cert);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error when calling getCertificateAlias for certificate: '"+cert+"' on underlying CertStore.keystore", e);
		}
	}

	@Override
	public void engineStore(OutputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		throw new UnsupportedOperationException("Method 'engineStore(OutputStream stream, char[] password)' is not supported by the PKCS#11 keystore.");
	}
}
