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
		return null;
	}

	@Override
	public Certificate engineGetCertificate(String alias) {
		return null;
	}

	@Override
	public Date engineGetCreationDate(String alias) {
		return null;
	}

	@Override
	public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
			throws KeyStoreException {

	}

	@Override
	public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {

	}

	@Override
	public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
	}

	@Override
	public void engineDeleteEntry(String alias) throws KeyStoreException {
	}

	@Override
	public Enumeration<String> engineAliases() {
		return null;
	}

	@Override
	public boolean engineContainsAlias(String alias) {
		return false;
	}

	@Override
	public int engineSize() {
		return 0;
	}

	@Override
	public boolean engineIsKeyEntry(String alias) {
		return false;
	}

	@Override
	public boolean engineIsCertificateEntry(String alias) {
		return false;
	}

	@Override
	public String engineGetCertificateAlias(Certificate cert) {
		return null;
	}

	@Override
	public void engineStore(OutputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {

	}

	@Override
	public void engineLoad(InputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {

	}

}
