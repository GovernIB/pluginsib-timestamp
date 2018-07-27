package org.fundaciobit.plugins.timestamp.catcertrfc;

import java.util.Calendar;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TimeStampToken;
import org.fundaciobit.plugins.timestamp.api.ITimeStampPlugin;
import org.fundaciobit.plugins.timestamp.api.utils.RFC3161Connection;
import org.fundaciobit.plugins.timestamp.api.utils.RFC3161Params;
import org.fundaciobit.plugins.utils.AbstractPluginProperties;


/**
 * CatCert
 * 
 * @author anadal
 *
 */
public class CatCertRfcTimeStampPlugin extends AbstractPluginProperties implements
    ITimeStampPlugin {

  protected final Logger log = Logger.getLogger(getClass());

  public static final String CATCERTRFC_BASE_PROPERTIES = TIMESTAMP_BASE_PROPERTY
      + "catcertrfc.";

  
  public static final String OID_RFC3161 = CATCERTRFC_BASE_PROPERTIES + "oid_rfc3161";
  
  public static final String URL = CATCERTRFC_BASE_PROPERTIES + "url_rfc";
  
  public static final String HASH_ALGORITHM = CATCERTRFC_BASE_PROPERTIES + "hashalgorithm";
  
  

  /**
   * @param propertyKeyBase
   * @param properties
   */
  public CatCertRfcTimeStampPlugin(String propertyKeyBase, Properties properties) {
    super(propertyKeyBase, properties);
  }

  /**
   * @param propertyKeyBase
   */
  public CatCertRfcTimeStampPlugin(String propertyKeyBase) {
    super(propertyKeyBase);
  }



  @Override
  public TimeStampToken getTimeStamp(byte[] inputdata, Calendar time) throws Exception {
    byte[] ts = getTimeStampDirect(inputdata, time);
    return RFC3161Connection.getTimeStampTokenFromTimeStampResponse(ts);
  }


  @Override
  public String getTimeStampPolicyOID() {
    return getProperty(OID_RFC3161);
  }

  @Override
  public String getTimeStampHashAlgorithm() {    
    return getProperty(HASH_ALGORITHM);
  }

  @Override
  public byte[] getTimeStampDirect(byte[] inputData, Calendar time) throws Exception {
    RFC3161Params rfcParams = new RFC3161Params(getProperties());
    RFC3161Connection connection = new RFC3161Connection(rfcParams);

    return connection.getTimeStampResponse(inputData, rfcParams.getTsaHashAlgorithm(), time);
  }

  protected Properties getProperties() {
    String tsaURL = getProperty(URL);

    Properties properties = new Properties();

    properties.setProperty("tsaURL", tsaURL);
    
    properties.setProperty("tsaPolicy",getTimeStampPolicyOID());

    properties.setProperty("tsaHashAlgorithm", getTimeStampHashAlgorithm());

    // TODO Passar com parametre
    properties.setProperty("tsaRequireCert", "true");

    return properties;
  }




}
