package org.fundaciobit.pluginsib.timestamp.catcertrfc;

import java.io.FileInputStream;
import java.util.Calendar;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.fundaciobit.pluginsib.core.v3.utils.Base64;
import org.fundaciobit.pluginsib.core.v3.utils.PluginsManager;
import org.fundaciobit.pluginsib.timestamp.api.ITimeStampPlugin;
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
            catCertRFCTimeStampPlugin = (ITimeStampPlugin) PluginsManager
                    .instancePluginByClass(CatCertRfcTimeStampPlugin.class, packageBase, catcertRfcProperties);

            byte[] fichero = new String("hola").getBytes();

            System.out.println("*** INICIO RFC3161  ***");
            TimeStampToken tst3 = catCertRFCTimeStampPlugin.getTimeStamp(fichero, Calendar.getInstance());
            if (tst3 != null) {
                System.out.println("Sello obtenido:");

                System.out.println("\n\n-------------------------------------------------------------");
                System.out.println(new String(tst3.getEncoded()));
                System.out.println("\n\n-------------------------------------------------------------");
                System.out.println(Base64.encode(tst3.getEncoded()));
                System.out.println("\n\n-------------------------------------------------------------");

                TimeStampTokenInfo info = tst3.getTimeStampInfo();
                System.out.println(" - getAccuracy: " + info.getAccuracy().getMillis());
                System.out.println(" - getGenTime: " + info.getGenTime());
                System.out.println(" - getExtensions: " + info.getExtensions());
                System.out.println(" - getSerialNumber: " + info.getSerialNumber());
                System.out.println(" - getMessageImprintAlgOID: " + info.getMessageImprintAlgOID());
                if (tst3.getUnsignedAttributes() != null) {
                    System.out.println(" - getUnsignedAttributes: " + tst3.getUnsignedAttributes().toHashtable());
                }
                if (tst3.getSignedAttributes() != null) {
                    System.out.println(" - getSignedAttributes: " + tst3.getSignedAttributes().toHashtable());
                    Hashtable<Object, Object> map = tst3.getSignedAttributes().toHashtable();
                    for (Map.Entry<Object, Object> entry : map.entrySet()) {
                        Object key = entry.getKey();
                        Attribute val = (Attribute) entry.getValue();
                        System.out.println(key + " => " + val.toASN1Primitive().toString());
                    }
                }
            } else {
                System.out.println("Error desconocido. Respuesta vacia.");
            }
            System.out.println("*** FIN RFC3161 ***");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
