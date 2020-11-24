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
	public Certificate[] engineGetCertificateChain(String alias) {
		throw new UnsupportedOperationException("Method 'engineGetCertificateChain(String alias)' is not supported by the PKCS#11 keystore. Alias: " + alias);
	}

	@Override
	public Certificate engineGetCertificate(String alias) {
		throw new UnsupportedOperationException("Method 'engineGetCertificate(String alias)' is not supported by the PKCS#11 keystore. Alias: " + alias);
	}

	@Override
	public Date engineGetCreationDate(String alias) {
		throw new UnsupportedOperationException("Method 'engineGetCreationDate(String alias)' is not supported by the PKCS#11 keystore. Alias: " + alias);
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
	public Enumeration<String> engineAliases() {
		throw new UnsupportedOperationException("Method 'engineAliases()' is not supported by the PKCS#11 keystore.");
	}

	@Override
	public boolean engineContainsAlias(String alias) {
		throw new UnsupportedOperationException("Method 'engineContainsAlias(String alias)' is not supported by the PKCS#11 keystore.");
	}

	@Override
	public int engineSize() {
		throw new UnsupportedOperationException("Method 'engineSize()' is not supported by the PKCS#11 keystore.");
	}

	@Override
	public boolean engineIsKeyEntry(String alias) {
		throw new UnsupportedOperationException("Method 'engineIsKeyEntry(String alias)' is not supported by the PKCS#11 keystore.");
	}

	@Override
	public boolean engineIsCertificateEntry(String alias) {
		throw new UnsupportedOperationException("Method 'engineIsKeyEntry(String alias)' is not supported by the PKCS#11 keystore.");
	}

	@Override
	public String engineGetCertificateAlias(Certificate cert) {
		throw new UnsupportedOperationException("Method 'engineGetCertificateAlias(Certificate cert)' is not supported by the PKCS#11 keystore.");
	}

	@Override
	public void engineStore(OutputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		throw new UnsupportedOperationException("Method 'engineStore(OutputStream stream, char[] password)' is not supported by the PKCS#11 keystore.");
	}

	@Override
	public void engineLoad(InputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		throw new UnsupportedOperationException("Method 'engineLoad(InputStream stream, char[] password)' is not supported by the PKCS#11 keystore.");
	}

}
