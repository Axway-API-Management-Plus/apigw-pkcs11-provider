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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import com.vordel.common.util.DigestUtil;
import com.vordel.security.cert.PersonalInfo;
import com.vordel.store.cert.CertStore;
import com.vordel.trace.Trace;

/**
 * This class implements the java.lang.Keystore and forwards requests to the internal API gateway CertStore, which is already initialized.
 * 
 * @author cwiechmann (Axway)
 *
 */
public class PKCS11KeystoreSpi extends KeyStoreSpi {
	
	String intend = "                ";

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
		Trace.debug("engineGetKey: Trying get key from API-Gateway certificate store (HSM): " + certEntity);
		Key key = CertStore.getPrivateKey(certEntity, null);
		if(key!=null) {
			Trace.debug(intend+"engineGetKey: Got key from HSM for alias: " + alias);
		} else {
			Trace.error(intend+"engineGetKey: No private key found for alias: " + alias);
		}
		return key;
	}
	
	@Override
	public void engineLoad(InputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		Trace.trace("PKCS11KeystoreSpi: engineLoad is doing nothing, as the underlying engine is already initialized by the API-Gateway internally.", Trace.TRACE_DATA);
		// Do nothing, as the internal CertStore is already initialized
		return;
	}
	
	@Override
	public boolean engineContainsAlias(String alias) {
		if(CertStore.getInstance().getPersonalInfoByAlias(alias)==null) {
			Trace.debug("engineContainsAlias - alias: '"+alias+"' is unknown");
			return false;
		} else {
			Trace.trace("engineContainsAlias - alias: '"+alias+"' found", Trace.TRACE_DATA);
			return true;
		}
	}
	
	@Override
	public Certificate engineGetCertificate(String alias) {
		return engineGetCertificate(alias, true);
	}
	
	public Certificate engineGetCertificate(String alias, boolean traceCertificate) {
		Certificate cert = null;
		Trace.trace("engineGetCertificate - Trying to get certificate for alias: '"+alias+"'", Trace.TRACE_DATA);
		PersonalInfo persInfo = CertStore.getInstance().getPersonalInfoByAlias(alias);
		if(persInfo!=null) {
			Trace.debug("engineGetCertificate - Got personalInfo by alias: '"+alias+"'");
			if(persInfo.certificate!=null) {
				Trace.trace("engineGetCertificate - Got certificate from personalInfo by alias: '"+alias+"'", Trace.TRACE_DATA);
				cert = persInfo.certificate;
			}
		} else {
			try {
				Trace.debug("engineGetCertificate - No personalInfo found for: '"+alias+"'. Trying to use keystore: ....getKeyStore().getCertificate(alias).");
				cert = CertStore.getInstance().getKeyStore().getCertificate(alias);
			} catch (KeyStoreException e) {
				Trace.error("Exception on getKeyStore().getCertificate(alias). " + e.getMessage(), e);
			}
		}
		if(cert!=null) {
			Trace.debug(intend+"engineGetCertificate - Got certificate for alias: '"+alias+"'");
			if(traceCertificate) traceCertificate(cert);
		} else {
			Trace.error(intend+"engineGetCertificate - no certificate found for alias: "+alias);
		}
		return cert;
	}
	
	@Override
	public Certificate[] engineGetCertificateChain(String alias) {
		Trace.trace("engineGetCertificateChain - Trying to get certificate chain for alias: '"+alias+"'", Trace.TRACE_DATA);
		Certificate certificate = engineGetCertificate(alias, false);
		if(certificate==null) {
			Trace.debug(intend+"engineGetCertificateChain - No certificate found with alias: '"+alias+"'");
			return null;
		}
		Certificate[] chain = CertStore.getInstance().getX509CertificateChainAsArray((X509Certificate)certificate);
		if(chain!=null) {
			Trace.debug(intend+"engineGetCertificateChain - Got certificate chain for alias: '"+alias+"'. Got: " + chain.length + " certificate(s)");
			for(Certificate cert : chain) {
				Trace.debug("------");
				traceCertificate(cert);
			}
			return chain;
		} else {
			Trace.debug(intend+"engineGetCertificateChain - No certificate chain found for alias: '"+alias+"'");
			return null;
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
	
	private byte[] getCertEncoded(Certificate cert) {
	      try {
	        return cert.getEncoded();
	      } catch (CertificateEncodingException e) {
	    	  Trace.error("Error byte encodedo", e);
	      }
	      return null;
	}

	private void traceCertificate(Certificate cert) {
		if(cert!=null && cert instanceof X509Certificate) {
			X509Certificate x509Cert = (X509Certificate)cert;
			Trace.debug(intend+"Cert issued to:   " + x509Cert.getSubjectDN().getName());
			Trace.debug(intend+"Cert issued by:   " + x509Cert.getIssuerDN().getName());
			Trace.debug(intend+"SHA1-Fingerprint: " + DigestUtil.getSHA1MessageDigest(getCertEncoded(cert)) );
			Trace.debug(intend+"MD5-Fingerprint:  " + DigestUtil.getMD5MessageDigest(getCertEncoded(cert)) );
		}
	}
}
