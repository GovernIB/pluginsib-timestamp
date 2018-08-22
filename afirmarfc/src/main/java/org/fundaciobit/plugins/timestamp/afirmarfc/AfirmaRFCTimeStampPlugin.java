package org.fundaciobit.plugins.timestamp.afirmarfc;

import java.io.File;
import java.util.Calendar;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TimeStampToken;
import org.fundaciobit.plugins.timestamp.api.ITimeStampPlugin;
import org.fundaciobit.pluginsib.core.utils.AbstractPluginProperties;


import org.fundaciobit.plugins.timestamp.afirmarfc.utils.RFC3161Connection;
import org.fundaciobit.plugins.timestamp.afirmarfc.utils.RFC3161Params;
import org.fundaciobit.pluginsib.core.utils.Base64;
import org.fundaciobit.pluginsib.core.utils.FileUtils;


/**
 *
 * @author anadal
 *
 */
public class AfirmaRFCTimeStampPlugin extends AbstractPluginProperties implements
    ITimeStampPlugin {

  protected final Logger log = Logger.getLogger(getClass());

  public static final String AFIRMARFC_BASE_PROPERTIES = TIMESTAMP_BASE_PROPERTY
      + "afirmarfc.";

  public static final String OID_RFC3161 = AFIRMARFC_BASE_PROPERTIES + "oid_rfc3161";
  public static final String APPLICATION_ID = AFIRMARFC_BASE_PROPERTIES + "applicationid";

  public static final String URL_RFC = AFIRMARFC_BASE_PROPERTIES + "url_rfc";

  public static final String HASH_ALGORITHM = AFIRMARFC_BASE_PROPERTIES + "hashalgorithm";

  // String locCert = rs.getString("https.autenticacion.location.cert");
  public static final String AUTH_CERT_PATH = AFIRMARFC_BASE_PROPERTIES + "auth.cert.p12.path";

  // String passCert = rs.getString("https.autenticacion.password.cert");
  public static final String AUTH_CERT_PASSWORD = AFIRMARFC_BASE_PROPERTIES
      + "auth.cert.p12.password";

  // Opcional
  // String locTrust = rs.getString("location.trustkeystore");
  public static final String SERVER_TRUSTKEYSTORE_PATH = AFIRMARFC_BASE_PROPERTIES
      + "server.trustkeystore.path";

  // String passTrust = rs.getString("password.trustkeystore");
  public static final String SERVER_TRUSTKEYSTORE_PASSWORD = AFIRMARFC_BASE_PROPERTIES
      + "server.trustkeystore.password";

  /**
   * 
   */
  public AfirmaRFCTimeStampPlugin() {
    super();
  }

  /**
   * @param propertyKeyBase
   * @param properties
   */
  public AfirmaRFCTimeStampPlugin(String propertyKeyBase, Properties properties) {
    super(propertyKeyBase, properties);
  }

  /**
   * @param propertyKeyBase
   */
  public AfirmaRFCTimeStampPlugin(String propertyKeyBase) {
    super(propertyKeyBase);
  }

  @Override
  public String getTimeStampPolicyOID() {
    return getProperty(OID_RFC3161);
  }

  @Override
  public String getTimeStampHashAlgorithm() {
    return getProperty(HASH_ALGORITHM);
  }

  
  
  /*
  @Override
  public TimeStampToken getTimeStamp(byte[] inputdata, Calendar time) throws Exception {

    return TimeStampService.componerSalida(getTimeStampDirect(inputdata, time));

  }

  @Override
  public byte[] getTimeStampDirect(byte[] inputdata, Calendar time) throws Exception {

    String appID = getProperty(APPLICATION_ID);
    String tsaURL = getProperty(URL_RFC);
    String tsaOIDPolicy = getTimeStampPolicyOID();

    String locCert = getProperty(AUTH_CERT_PATH);
    String passCert = getProperty(AUTH_CERT_PASSWORD);

    String locTrust = getProperty(SERVER_TRUSTKEYSTORE_PATH);
    String passTrust = getProperty(SERVER_TRUSTKEYSTORE_PASSWORD);

    String hashAlgorithm = getTimeStampHashAlgorithm();

    byte[] rawReturn = TimeStampService.requestTimeStampHTTPS(appID, tsaURL, tsaOIDPolicy,
        locCert, passCert, locTrust, passTrust, hashAlgorithm, inputdata, time);

    return rawReturn;

  }
  */
  
  @Override
  public TimeStampToken getTimeStamp(byte[] inputdata, Calendar time) throws Exception {

    byte[] ts = getTimeStampDirect(inputdata, time);

    return RFC3161Connection.getTimeStampTokenFromTimeStampResponse(ts);

  }

  @Override
  public byte[] getTimeStampDirect(byte[] inputdata, Calendar time) throws Exception {

    RFC3161Params tsaparams = new RFC3161Params(getProperties());
    String hashAlgorithm = tsaparams.getTsaHashAlgorithm();
    RFC3161Connection ts = new RFC3161Connection(tsaparams);

    return ts.getTimeStampResponse(inputdata, hashAlgorithm, time);
  }

  public Properties getProperties() throws Exception {

    Properties miniAppletProperties = new Properties();

    String tsaURL = getProperty(URL_RFC);
    miniAppletProperties.setProperty("tsaURL", tsaURL);

    miniAppletProperties.setProperty("tsaPolicy", getTimeStampPolicyOID());

    miniAppletProperties.setProperty("tsaHashAlgorithm", getTimeStampHashAlgorithm());

    // TODO Passar com parametre
    miniAppletProperties.setProperty("tsaRequireCert", "true");

    String locCert = getProperty(AUTH_CERT_PATH);
    String passCert = getProperty(AUTH_CERT_PASSWORD);
    // Almacen para el SSL cliente
    miniAppletProperties.setProperty("tsaSslKeyStore", toB64(locCert));

    miniAppletProperties.setProperty("tsaSslKeyStorePassword", passCert);

    // TODO Passar com parametre
    miniAppletProperties.setProperty("tsaSslKeyStoreType", "PKCS12");

    // TrustStore con los certificados de confianza para el SSL ==> BASE 64
    
    String locTrust = getProperty(SERVER_TRUSTKEYSTORE_PATH);
    String passTrust = getProperty(SERVER_TRUSTKEYSTORE_PASSWORD);
    
    if (locTrust != null && passTrust != null) {
      miniAppletProperties.setProperty("tsaSslTrustStore", toB64(locTrust));
      miniAppletProperties.setProperty("tsaSslTrustStorePassword", passTrust);
      // TODO Passar com parametre
      miniAppletProperties.setProperty("tsaSslTrustStoreType", "JKS");
    }

    miniAppletProperties.setProperty("verifyHostname", "false");

    String appID = getProperty(APPLICATION_ID);
    miniAppletProperties.setProperty("tsaExtensionOid", "1.3.4.6.1.3.4.6");
    miniAppletProperties.setProperty("tsaExtensionCritical", "false");
    miniAppletProperties.setProperty("tsaExtensionValueBase64", Base64.encode(appID));

    return miniAppletProperties;
  }

  public static String toB64(String filePath) throws Exception {
    byte[] dataTS = FileUtils.readFromFile(new File(filePath));

    return Base64.encode(dataTS);

}

}
