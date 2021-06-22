package org.fundaciobit.plugins.timestamp.catcertrfc;

import java.io.FileInputStream;
import java.util.Calendar;
import java.util.Properties;

import org.bouncycastle.tsp.TimeStampToken;
import org.fundaciobit.plugins.timestamp.api.ITimeStampPlugin;
import org.fundaciobit.pluginsib.core.utils.Base64;
import org.fundaciobit.pluginsib.core.utils.PluginsManager;

import org.junit.Test;

/**
 * 
 * @author anadal
 *
 */
public class CatCertRFCTimeStampTest {

    @Test
    public void test() {

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
          System.out.println(Base64.encode(tst3.getEncoded()));
        } else {
          System.out.println("Error desconocido. Respuesta vacia.");
        }
        System.out.println("*** FIN RFC3161 ***");

      } catch (Exception e) {
        e.printStackTrace();
      }
    }
}
