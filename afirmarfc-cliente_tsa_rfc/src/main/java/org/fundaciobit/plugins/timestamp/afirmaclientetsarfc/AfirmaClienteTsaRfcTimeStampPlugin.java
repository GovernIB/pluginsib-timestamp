package org.fundaciobit.plugins.timestamp.afirmaclientetsarfc;

import java.util.Calendar;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TimeStampToken;
import org.fundaciobit.plugins.timestamp.api.ITimeStampPlugin;
import org.fundaciobit.pluginsib.core.utils.AbstractPluginProperties;
import org.fundaciobit.tsa.client.TimeStampService;

/**
 * 
 * @author anadal(u80067)
 *
 */
public class AfirmaClienteTsaRfcTimeStampPlugin extends AbstractPluginProperties implements
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
  public AfirmaClienteTsaRfcTimeStampPlugin() {
    super();
  }

  /**
   * @param propertyKeyBase
   * @param properties
   */
  public AfirmaClienteTsaRfcTimeStampPlugin(String propertyKeyBase, Properties properties) {
    super(propertyKeyBase, properties);
  }

  /**
   * @param propertyKeyBase
   */
  public AfirmaClienteTsaRfcTimeStampPlugin(String propertyKeyBase) {
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

  @Override
  public TimeStampToken getTimeStamp(byte[] inputdata, Calendar time) throws Exception {

    TimeStampService tss = instantiateTimeStampService();

    return tss.generarTS(inputdata, time);

  }

  @Override
  public byte[] getTimeStampDirect(byte[] inputdata, Calendar time) throws Exception {

    TimeStampService tss = instantiateTimeStampService();

    return tss.generarTSDirect(inputdata, time);
  }

  protected TimeStampService instantiateTimeStampService() {
    String m_sPolicyOID = getTimeStampPolicyOID();

    String url = getProperty(URL_RFC);

    String appID = getProperty(APPLICATION_ID);

    String hashAlgo = getTimeStampHashAlgorithm();

    final boolean autenticacionCliente = true;

    String locCert = getProperty(AUTH_CERT_PATH);
    String passCert = getProperty(AUTH_CERT_PASSWORD);

    String locTrust = getProperty(SERVER_TRUSTKEYSTORE_PATH);
    String passTrust = getProperty(SERVER_TRUSTKEYSTORE_PASSWORD);

    TimeStampService tss = new TimeStampService(m_sPolicyOID, url, appID, hashAlgo,
        autenticacionCliente, locCert, passCert, locTrust, passTrust);
    return tss;
  }

}
