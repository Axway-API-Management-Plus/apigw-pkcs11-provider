package com.axway.security;

import java.util.HashMap;
import java.util.Map;

import com.vordel.es.Entity;
import com.vordel.es.EntityStoreException;

/**
 * Utility class that simulates an entity store to pass the necessary 
 * parameters to the API gateway CertStore. Standalone class to simplify the usage.
 * 
 * @author cwiechmann
 *
 */
public class CertEntity extends Entity {
	
	private Map<String, String> values = new HashMap<String, String>();
	
	private Map<String, byte[]> binaryValues = new HashMap<String, byte[]>();

	public CertEntity() {
		super(null);
	}

	@Override
	public String getStringValue(String fieldName) {
		if(values.containsKey(fieldName)) {
			return values.get(fieldName);
		} else {
			System.out.println("fieldName: " + fieldName + " not supported by CertEntity");
		}
		return super.getStringValue(fieldName);
	}

	@Override
	public byte[] getBinaryValue(String fieldName) throws EntityStoreException {
		if(binaryValues.containsKey(fieldName)) {
			return binaryValues.get(fieldName);
		} else {
			System.out.println("fieldName: " + fieldName + " not supported by CertEntity");
		}
		return super.getBinaryValue(fieldName);
	}

	public void setStoreType(String storeType) {
		this.values.put("storeType", storeType);
	}

	public void setCertificateRealm(String certificateRealm) {
		this.values.put("certificateRealm", certificateRealm);
	}
	
	public void setKey(byte[] key) {
		binaryValues.put("key", key);
	}
	
	public void setKeyId(String key) {
		values.put("keyId", key);
	}

	@Override
	public String toString() {
		return "CertEntity [values=" + values + "]";
	}
}
