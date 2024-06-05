package org.fundaciobit.tsa.client;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Calendar;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.fundaciobit.tsa.client.excepciones.AutenticacionException;
import org.fundaciobit.tsa.client.excepciones.ConexionException;
import org.fundaciobit.tsa.client.excepciones.PeticionException;

/**
 * 
 * @author anadal(u80067)
 *
 */
public class TimeStampService {

  private final String m_sPolicyOID;
  private final String url;
  private final String appID;
  private final String hashAlgo;
  private final boolean autenticacionCliente;
  private final String locCert;
  private final String passCert;
  private final String locTrust;
  private final String passTrust;

  public TimeStampService(String m_sPolicyOID, String url, String appID, String hashAlgo,
      boolean autenticacionCliente, String locCert, String passCert, String locTrust,
      String passTrust) {

    this.m_sPolicyOID = m_sPolicyOID;
    this.appID = appID;
    this.url = url;
    this.hashAlgo = hashAlgo;
    this.autenticacionCliente = autenticacionCliente;

    this.locCert = locCert;
    this.passCert = passCert;

    this.locTrust = locTrust;
    this.passTrust = passTrust;
  }

  public TimeStampToken generarTS(byte[] fichero, Calendar nonce) throws ConexionException,
      AutenticacionException, PeticionException {
    try {
      if (fichero == null) {
        return null;
      }

      final String oidHashAlgo = getOID(this.hashAlgo);
      System.out.println(" ALGO OID = " + oidHashAlgo);

      Digest digest;
      if (OID_SHA512.equals(oidHashAlgo)) {
        digest = new SHA512Digest();
      } else if (OID_SHA384.equals(oidHashAlgo)) {
        digest = new SHA384Digest();
      } else if (OID_SHA256.equals(oidHashAlgo)) {
        digest = new SHA256Digest();
      } else if (OID_SHA1.equals(oidHashAlgo)) {
        digest = new SHA1Digest();
      } else {
        throw new IOException("Not found Hash Algorithm: ]" + this.hashAlgo + "[");
      }

      digest.update(fichero, 0, fichero.length);
      byte[] digestValue = new byte[digest.getDigestSize()];
      digest.doFinal(digestValue, 0);

      ASN1ObjectIdentifier asn1 = new ASN1ObjectIdentifier(oidHashAlgo);

      byte[] respBytes = this.requestTimeStampHTTPS(digestValue, asn1, nonce);

      return this.componerSalida(respBytes);

    } catch (ConnectException cExc) {

      throw new ConexionException(
          "Error de conexion. Compruebe el Host establecido o que el servicio este habilitado");

    } catch (TSPException tspException) {
      throw new PeticionException(tspException.getMessage());
    } catch (AutenticacionException autExc) {
      throw autExc;
    } catch (IOException ioExc) {
      AutenticacionException autExc = null;
      if (ioExc.getMessage().contains("402")) {
        autExc = new AutenticacionException("Error en el proceso de autenticaci�n");
        throw autExc;
      }
      if ((ioExc.getMessage().contains("401"))
          || (ioExc.getMessage().contains("handshake_failure"))) {
        autExc = new AutenticacionException("Certificado no v�lido");
        throw autExc;
      }
      if (ioExc.getMessage().contains("400")) {
        throw new PeticionException("Petición Incorrecta");
      }
      ioExc.printStackTrace();
      return null;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }

  }

  public byte[] generarTSDirect(byte[] imprint, Calendar nonce) throws ConexionException,
      AutenticacionException, PeticionException {
    try {
      if (imprint == null) {
        return null;
      }

      final String oidHashAlgo = getOID(this.hashAlgo);

      ASN1ObjectIdentifier asn1 = new ASN1ObjectIdentifier(oidHashAlgo);

      return this.requestTimeStampHTTPS(imprint, asn1, nonce);

    } catch (ConnectException cExc) {

      throw new ConexionException(
          "Error de conexion. Compruebe el Host establecido o que el servicio este habilitado");

    } catch (TSPException tspException) {
      throw new PeticionException(tspException.getMessage());
    } catch (AutenticacionException autExc) {
      throw autExc;
    } catch (IOException ioExc) {
      AutenticacionException autExc = null;
      if (ioExc.getMessage().contains("402")) {
        autExc = new AutenticacionException("Error en el proceso de autenticaci�n");
        throw autExc;
      }
      if ((ioExc.getMessage().contains("401"))
          || (ioExc.getMessage().contains("handshake_failure"))) {
        autExc = new AutenticacionException("Certificado no v�lido");
        throw autExc;
      }
      if (ioExc.getMessage().contains("400")) {
        throw new PeticionException("Petición Incorrecta");
      }
      return null;
    } catch (Exception e) {
      return null;
    }

  }

  @SuppressWarnings("deprecation")
  private byte[] requestTimeStampHTTPS(byte[] imprint, ASN1ObjectIdentifier asn1,
      final Calendar time) throws TSPException, IOException, AutenticacionException {
    TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
    reqgen.setCertReq(true);

    if (appID != null && !"".equals(appID)) {
      final String oid = "1.3.4.6.1.3.4.6";
      reqgen.addExtension(new ASN1ObjectIdentifier(oid), false, new DEROctetString(appID.getBytes()));
    }
    if (this.m_sPolicyOID != null && !this.m_sPolicyOID.equals("")) {
      reqgen.setReqPolicy(this.m_sPolicyOID);
    }

    TimeStampRequest req = reqgen
        .generate(asn1, imprint, BigInteger.valueOf(time != null ? time.getTimeInMillis()
            : System.currentTimeMillis()));
    byte[] request = req.getEncoded();
    URL urlTSA = new URL(url);
    HttpsURLConnection tsaConnection = (HttpsURLConnection) urlTSA.openConnection();
    tsaConnection.setHostnameVerifier(new NameVerifier());
    try {
      SSLContext ctx = SSLContext.getInstance("SSL");
      KeyStore ks = KeyStore.getInstance("PKCS12");
      KeyStore cer = KeyStore.getInstance("JKS");
      cer.load(new FileInputStream(locTrust), passTrust.toCharArray());
      TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
      tmf.init(cer);
      if (autenticacionCliente) {
        FileInputStream inKS = new FileInputStream(locCert);
        char[] passphrase = passCert.toCharArray();
        ks.load(inKS, passCert.toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, passphrase);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
      } else {
        ctx.init(null, tmf.getTrustManagers(), null);
      }
      SSLSocketFactory factory = ctx.getSocketFactory();
      tsaConnection.setSSLSocketFactory(factory);
    } catch (Exception e) {
      e.printStackTrace();
    }
    tsaConnection.setDoInput(true);
    tsaConnection.setDoOutput(true);
    tsaConnection.setUseCaches(false);
    tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
    tsaConnection.setAllowUserInteraction(false);
    tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");
    OutputStream out = tsaConnection.getOutputStream();
    out.write(request);
    out.close();
    InputStream inp = tsaConnection.getInputStream();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buffer = new byte[1024];
    int bytesRead = 0;
    while ((bytesRead = inp.read(buffer, 0, buffer.length)) >= 0) {
      baos.write(buffer, 0, bytesRead);
    }
    byte[] respBytes = baos.toByteArray();
    String encoding = tsaConnection.getContentEncoding();
    if (encoding != null && encoding.equalsIgnoreCase("base64")) {
      respBytes = Base64.getDecoder().decode(respBytes);
    }

    TimeStampResponse tsr = new TimeStampResponse(respBytes);
    System.out.println("XYZ ZZZ Validant RESPOSTA XYZ ZZZ");
    tsr.validate(req);

    return respBytes;
  }

  public TimeStampToken componerSalida(byte[] res) {
    try {
      ASN1InputStream in = new ASN1InputStream(res);

      DLSequence asn = (DLSequence) in.readObject();
      DLSequence info = (DLSequence) asn.getObjectAt(0);
      ASN1Integer status = (ASN1Integer) info.getObjectAt(0);

      if (status.getValue().intValue() != 0 && status.getValue().intValue() != 1) {
        String tspExMsg = "Timestamp server error. ";
        if (info.getObjectAt(1) != null) {
          tspExMsg = tspExMsg + new String(((DLSequence) info.getObjectAt(1)).getEncoded());
        }
        in.close();
        throw new TSPException(tspExMsg);
      }
      in.close();
      try {
        byte[] d = asn.getObjectAt(1).toASN1Primitive().getEncoded(ASN1Encoding.DER);
        return new TimeStampToken(new CMSSignedData(d));
      } catch (TSPException e) {
        throw e;
      } catch (Exception e) {
        throw new TSPException(e.getMessage(), e);
      }
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  class NameVerifier implements HostnameVerifier {
    NameVerifier() {
    }

    /*
     * Enabled aggressive block sorting Enabled unnecessary exception pruning Enabled
     * aggressive exception aggregation
     */
    public boolean verify(String hostname, SSLSession session) {
      try {
        FileInputStream inKS = new FileInputStream(locTrust);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(inKS, passTrust.toCharArray());
        Enumeration<String> aliases = keyStore.aliases();
        Certificate[] certs = session.getPeerCertificates();
        int i = 0;
        do {
          if (i >= certs.length) {
            return false;
          }
          if (certs[i] instanceof X509Certificate) {
            while (aliases.hasMoreElements()) {

              String a = aliases.nextElement();
              Certificate certificadoConfianza = keyStore.getCertificate(a);
              X509Certificate c = (X509Certificate) certs[i];
              if (!certificadoConfianza.equals(c))
                continue;
              return true;
            }
          }
          ++i;
        } while (true);
      } catch (Exception e) {
        return false;
      }
    }
  }

  private static final String OID_SHA1 = "1.3.14.3.2.26"; //$NON-NLS-1$
  private static final String OID_SHA512 = "2.16.840.1.101.3.4.2.3"; //$NON-NLS-1$
  private static final String OID_SHA256 = "2.16.840.1.101.3.4.2.1"; //$NON-NLS-1$
  private static final String OID_SHA384 = "2.16.840.1.101.3.4.2.2"; //$NON-NLS-1$
  private static final String OID_RSA = "1.2.840.113549.1.1.1"; //$NON-NLS-1$

  private static final Dictionary<String, String> OIDS = new Hashtable<String, String>();
  static {
    OIDS.put("SHA1", OID_SHA1); //$NON-NLS-1$
    OIDS.put("SHA-1", OID_SHA1); //$NON-NLS-1$
    OIDS.put("SHA", OID_SHA1); //$NON-NLS-1$
    OIDS.put(OID_SHA1, OID_SHA1);

    OIDS.put("SHA-512", OID_SHA512); //$NON-NLS-1$
    OIDS.put("SHA512", OID_SHA512); //$NON-NLS-1$
    OIDS.put(OID_SHA512, OID_SHA512);

    OIDS.put("SHA-256", OID_SHA256); //$NON-NLS-1$
    OIDS.put("SHA256", OID_SHA256); //$NON-NLS-1$
    OIDS.put(OID_SHA256, OID_SHA256);

    OIDS.put("SHA-384", OID_SHA384); //$NON-NLS-1$
    OIDS.put("SHA384", OID_SHA384); //$NON-NLS-1$
    OIDS.put(OID_SHA384, OID_SHA384);

    OIDS.put("RSA", OID_RSA); //$NON-NLS-1$
    OIDS.put(OID_RSA, OID_RSA);
  }

  /**
   * Obtiene el OID del algoritmo indicado.
   * 
   * @param name
   *          Nombre del algoritmo
   * @return OID del algoritmo
   */
  public static String getOID(final String name) {
    if (name == null) {
      return null;
    }
    final String res = OIDS.get(name.toUpperCase(Locale.US));
    if (res == null) {
      throw new IllegalArgumentException("Se deconoce el algoritmo '" + name + "'"); //$NON-NLS-1$ //$NON-NLS-2$
    }
    return res;
  }

}