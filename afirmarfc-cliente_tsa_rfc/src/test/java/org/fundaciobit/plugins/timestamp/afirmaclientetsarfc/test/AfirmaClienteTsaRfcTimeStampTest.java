package org.fundaciobit.plugins.timestamp.afirmaclientetsarfc.test;

import java.io.FileInputStream;
import java.util.Calendar;
import java.util.Properties;

import org.fundaciobit.plugins.timestamp.afirmaclientetsarfc.AfirmaClienteTsaRfcTimeStampPlugin;
import org.fundaciobit.plugins.timestamp.api.ITimeStampPlugin;
import org.fundaciobit.pluginsib.core.utils.Base64;
import org.fundaciobit.pluginsib.core.utils.PluginsManager;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.junit.Test;

/**
 * @author anadal
 */
public class AfirmaClienteTsaRfcTimeStampTest {

    @Test
    public void test() throws Exception {

        System.out.println(AfirmaClienteTsaRfcTimeStampPlugin.class.getCanonicalName());

        final String packageBase = "es.caib.example.";

        Properties properties = new Properties();
        properties.load(new FileInputStream("test.properties"));
        System.out.println("Properties: " + properties);

        ITimeStampPlugin plugin = (ITimeStampPlugin) PluginsManager.instancePluginByClass(
                AfirmaClienteTsaRfcTimeStampPlugin.class, packageBase, properties);

        byte[] fichero = "HOLA".getBytes();

        System.out.println("\n\n*** INICIO RFC3161+HTTPS (Port 8443) == DIRECT ***");

        byte[] direct = plugin.getTimeStampDirect(fichero, Calendar.getInstance());
        if (direct != null) {
            System.out.println("DIRECT Sello obtenido:");
            System.out.println(new String(direct));

            System.out.println();
            System.out.println();
            System.out.println();

            System.out.println(Base64.encode(direct));

        } else {
            System.out.println("DIRECT Error desconocido. Respuesta NULL.");
        }

        System.out.println("\n============================================\n");

    }

}
