package org.fundaciobit.plugins.timestamp.catcertrfc;

import java.io.FileInputStream;
import java.util.Calendar;
import java.util.Properties;

import org.bouncycastle.tsp.TimeStampToken;
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
public class CatCertRFCTimeStampTest  extends TestCase {
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public CatCertRFCTimeStampTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( CatCertRFCTimeStampTest.class );
    }

    /**
     * Rigourous Test :-)
     */
    public void testApp()
    {
        assertTrue( true );
        // main(null);
    }
    
    public static void main(String[] args) {

      try {
        System.out.println(CatCertRfcTimeStampPlugin.class.getCanonicalName());

        final String packageBase = "es.caib.example.";

        Properties catcertRfcProperties = new Properties();

        catcertRfcProperties.load(new FileInputStream("test.properties"));

        System.out.println("Properties: " + catcertRfcProperties.toString());

        ITimeStampPlugin catCertRFCTimeStampPlugin;
        catCertRFCTimeStampPlugin = (ITimeStampPlugin) PluginsManager.instancePluginByClass(
            CatCertRfcTimeStampPlugin.class, packageBase, catcertRfcProperties);

        byte[] fichero = new String("hola").getBytes();

        System.out.println("*** INICIO RFC3161  ***");
        TimeStampToken tst3 = catCertRFCTimeStampPlugin.getTimeStamp(fichero, Calendar.getInstance());
        if (tst3 != null) {
          System.out.println("Sello obtenido:");
          System.out.println(new String(tst3.getEncoded()));
          System.out.println("\n\n-------------------------------------------------------------");
          System.out.println(new String(Base64.encode(tst3.getEncoded())));
        } else {
          System.out.println("Error desconocido. Respuesta vacia.");
        }
        System.out.println("*** FIN RFC3161 ***");

      } catch (Exception e) {
        e.printStackTrace();
      }
    }
}
