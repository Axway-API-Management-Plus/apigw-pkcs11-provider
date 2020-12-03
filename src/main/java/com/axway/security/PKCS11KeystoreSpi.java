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

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

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
		Trace.info("engineGetKey: Requesting key from API-Gateway certificate store (HSM): " + certEntity);
		Key key = CertStore.getPrivateKey(certEntity, null);
		if(key!=null) {
			Trace.info(intend+"engineGetKey: Got key from HSM for alias: " + alias);	
		} else {
			Trace.error(intend+"engineGetKey: No private key found for alias: " + alias);
		}
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
			Trace.info("engineContainsAlias - alias: '"+alias+"' is unknown");
			return false;
		} else {
			Trace.info("engineContainsAlias - alias: '"+alias+"' found");
			return true;
		}
	}
	
	@Override
	public Certificate engineGetCertificate(String alias) {
		return engineGetCertificate(alias, true);
	}
	
	public Certificate engineGetCertificate(String alias, boolean traceCertificate) {
		Trace.trace("engineGetCertificate - return certificate for alias: '"+alias+"'", Trace.TRACE_DATA);
		try {
			Certificate cert = CertStore.getInstance().getKeyStore().getCertificate(alias);
			if(cert!=null) {
				Trace.info(intend+"engineGetCertificate - return certificate for alias: '"+alias+"'");
				if(traceCertificate) traceCertificate(cert);
			} else {
				Trace.error(intend+"engineGetCertificate - no certificate found for alias: "+alias);
			}
			return cert;
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error getting certificate for alias: '"+alias+"' from underlying CertStore.keystore", e);
		}
	}
	
	@Override
	public Certificate[] engineGetCertificateChain(String alias) {
		Trace.info("engineGetCertificateChain - return certificate chain for alias: '"+alias+"'");
		Certificate certificate = engineGetCertificate(alias, false);
		if(certificate==null) {
			Trace.info(intend+"engineGetCertificateChain - No certificate found with alias: '"+alias+"'");
			return null;
		}
		Certificate[] chain = CertStore.getInstance().getX509CertificateChainAsArray((X509Certificate)certificate);
		if(chain!=null) {
			Trace.info(intend+"engineGetCertificateChain - return certificate chain for alias: '"+alias+"'. Got: " + chain.length + " certificate(s)");
			for(Certificate cert : chain) {
				Trace.info("------");
				traceCertificate(cert);
			}
			return chain;
		} else {
			Trace.info(intend+"engineGetCertificateChain - No certificate chain found for alias: '"+alias+"'");
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

	private String getHexString(byte[] bytes) {
		char[] hex = Hex.encodeHex(bytes);
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < hex.length; i++) {
			if (i % 2 == 0 && i > 0)
				sb.append(':'); 
			sb.append(Character.toUpperCase(hex[i]));
		} 
		return sb.toString();
	}

	private void traceCertificate(Certificate cert) {
		if(cert!=null && cert instanceof X509Certificate) {
			X509Certificate x509Cert = (X509Certificate)cert;
			Trace.info(intend+"Cert issued to:   " + x509Cert.getSubjectDN().getName());
			Trace.info(intend+"Cert issued by:   " + x509Cert.getIssuerDN().getName());
			Trace.info(intend+"SHA1-Fingerprint: " + getHexString(DigestUtils.sha1(getCertEncoded(cert)) ) );
			Trace.info(intend+"MD5-Fingerprint:  " + getHexString(DigestUtils.md5(getCertEncoded(cert)) ) );
		}
	}
}
