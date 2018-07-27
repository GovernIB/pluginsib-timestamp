package org.fundaciobit.tsatest;

import java.io.FileInputStream;
import java.util.Calendar;
import java.util.Properties;

import org.fundaciobit.plugins.timestamp.afirmarfc.AfirmaRFCTimeStampPlugin;
import org.fundaciobit.plugins.timestamp.api.ITimeStampPlugin;
import org.fundaciobit.plugins.utils.Base64;
import org.fundaciobit.plugins.utils.PluginsManager;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * 
 * @author anadal
 *
 */
public class AfirmaRFCTimeStampTest extends TestCase {
  /**
   * Create the test case
   *
   * @param testName
   *          name of the test case
   */
  public AfirmaRFCTimeStampTest(String testName) {
    super(testName);
  }

  /**
   * @return the suite of tests being tested
   */
  public static Test suite() {
    return new TestSuite(AfirmaRFCTimeStampTest.class);
  }

  /**
   * Rigourous Test :-)
   */
  public void testApp() {
    assertTrue(true);
    //main(null);
  }

  public static void main(String[] args) {

    
    StringBuffer results = new StringBuffer();
    final int j = 0;
    
    try {
      
      System.out.println(AfirmaRFCTimeStampPlugin.class.getCanonicalName());

      final String packageBase = "es.caib.example.";

      Properties afirmaRfcProperties = new Properties();

      afirmaRfcProperties.load(new FileInputStream("test.properties"));
      
      System.out.println("Properties: " + afirmaRfcProperties.toString());

      ITimeStampPlugin afirmaRFCTimeStampPlugin;
      afirmaRFCTimeStampPlugin = (ITimeStampPlugin) PluginsManager.instancePluginByClass(
          AfirmaRFCTimeStampPlugin.class, packageBase, afirmaRfcProperties);
      
      StringBuffer str = new StringBuffer();
//      for (int i = 0; i < 1000; i++) {
//        str.append("a");
//      }
      str.append("HOLA");
 
      
      System.out.println(" LEN: " + str.length());

      byte[] fichero = str.toString().getBytes();

      
      System.out.println("\n\n*** INICIO RFC3161+HTTPS (Port 8443) == DIRECT ***");

      byte[] direct = afirmaRFCTimeStampPlugin.getTimeStampDirect(fichero, Calendar.getInstance());
      if (direct != null) {
        System.out.println("DIRECT Sello obtenido:");
        System.out.println(new String(direct));
        
        System.out.println();
        System.out.println();
        System.out.println();
        
        
        System.out.println(new String(Base64.encode(direct)));

      } else {
        System.out.println("DIRECT Error desconocido. Respuesta NULL.");
      }

      System.out.println("\n============================================\n");
      
      /*
      System.out.println("\n\n*** INICIO RFC3161+HTTPS (Port 8443) == TIMESTAMP BC ***");
      long start = System.currentTimeMillis();
      TimeStampToken tst3 = afirmaRFCTimeStampPlugin.getTimeStamp(fichero, Calendar.getInstance());
      System.out.println("Elapsed MS: " + (System.currentTimeMillis() - start));
      
      if (tst3 != null) {
        System.out.println("TIMESTAMP BC Sello obtenido:");
        System.out.println(new String(tst3.getEncoded()));
        System.out.println("TIMESTAMP BC  Sello obtenido (B64):");
        System.out.println(new String(Base64.encode(tst3.getEncoded())));
        
        
        
        
        

      } else {
        System.out.println("TIMESTAMP BC  Error desconocido. Respuesta vacia.");
      }
      
*/
      System.out.println("*** FIN RFC3161+HTTPS (Port 8443) ***");
      
      Thread.sleep(2000);
      
      results.append( j + "Kb\tOK\n");
      

    } catch (Exception e) {
      
      results.append( j + "Kb\t" + e.getMessage() + "\n");      
    
      e.printStackTrace();
    }
    
    
    System.out.println();
    System.out.println();
    System.out.println();        
    System.out.println(results.toString());

  }

}
