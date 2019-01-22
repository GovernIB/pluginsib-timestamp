package org.fundaciobit.tsa.client.test;

import java.io.FileInputStream;
import java.util.Calendar;
import java.util.Properties;

import org.bouncycastle.tsp.TimeStampToken;
import org.fundaciobit.tsa.client.TimeStampService;
import org.fundaciobit.tsa.client.excepciones.AutenticacionException;
import org.fundaciobit.tsa.client.excepciones.ConexionException;
import org.fundaciobit.tsa.client.excepciones.PeticionException;

/**
 * 
 * @author anadal(u80067)
 *
 */
public class TesterTimeStamp {

  public static void main(String[] args) {
    byte[] datos = { 'h', 'o', 'l', 'a' };
    try {

     Properties prop = new Properties();
     prop.load(new FileInputStream("configuracionCliente.properties"));

      String m_sPolicyOID = prop.getProperty("oid.rfc3161");

      String appID = prop.getProperty("ident.aplicacion");
      String tsaURL = prop.getProperty("url.https");
      
      System.out.println("prop.getProperty(https.autenticacion.cliente) => |" + prop.getProperty("https.autenticacion.cliente") + "|");
      
      
      boolean autenticacionCliente = "true"
          .equals(prop.getProperty("https.autenticacion.cliente"));

      String locCert = prop.getProperty("https.autenticacion.location.cert");
      String passCert = prop.getProperty("https.autenticacion.password.cert");

      String locTrust = prop.getProperty("location.trustkeystore");
      String passTrust = prop.getProperty("password.trustkeystore");

      String hashAlgo = "SHA-512";
      
      
      System.out.println("locCert: " + locCert);
      
      System.out.println("passCert: " + passCert);
      
      System.out.println("locTrust: " + locTrust);
      System.out.println("passTrust: " + passTrust);
      
      System.out.println("autenticacionCliente: " + autenticacionCliente);
      

      Calendar nonce = Calendar.getInstance();
      nonce.setTimeInMillis(System.currentTimeMillis() + 2000);
      
      System.out.println("NONCE ENVIAT: " + nonce.getTimeInMillis());

      TimeStampService rfcGenerator = new TimeStampService(m_sPolicyOID, tsaURL, appID,
          hashAlgo, autenticacionCliente, locCert, passCert, locTrust, passTrust);
      TimeStampToken token = rfcGenerator.generarTS(datos, nonce);
      
      
      if (token != null) {

        System.out.println("|" + token.toString() + "|");
        System.out.println("HASH: " + token.getTimeStampInfo().getHashAlgorithm());
        System.out.println("NONCE REBUT: " + token.getTimeStampInfo().getNonce());
        System.out.println("ImprintDigest: " + token.getTimeStampInfo().getMessageImprintDigest().length);
        
        System.out.println("Imprint-Algo: "+ token.getTimeStampInfo().getMessageImprintAlgOID());

        
        
        //tstInfo.getMessageImprintAlgOID().equals(request.getMessageImprintAlgOID()
        

      } else {
        System.out.println("Respuesta vacía.");
      }
      // TimeStampToken token2 =

      // rfcGenerator.generarTS(TiposRFC.RFC3151, datos);
      // if (token2 != null) {
      // System.out.println(token2.toString());
      // } else {
      // System.out.println("Respuesta vacía.");
      // }
    } catch (ConexionException conEx) {
      conEx.printStackTrace();
    } catch (PeticionException petEx) {
      petEx.printStackTrace();
    } catch (AutenticacionException autEx) {
      autEx.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }
  
  
  

}