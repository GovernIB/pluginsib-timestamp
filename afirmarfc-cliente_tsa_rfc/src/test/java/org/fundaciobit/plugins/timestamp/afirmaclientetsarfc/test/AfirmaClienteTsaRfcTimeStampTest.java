package org.fundaciobit.plugins.timestamp.afirmaclientetsarfc.test;

import org.bouncycastle.tsp.TimeStampToken;
import org.fundaciobit.plugins.timestamp.afirmaclientetsarfc.AfirmaClienteTsaRfcTimeStampPlugin;
import org.fundaciobit.plugins.timestamp.api.ITimeStampPlugin;
import org.fundaciobit.pluginsib.core.utils.Base64;
import org.fundaciobit.pluginsib.core.utils.PluginsManager;
import org.junit.Assert;
import org.junit.Test;

import java.io.FileInputStream;
import java.util.Calendar;
import java.util.Properties;

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

        Calendar calendar = Calendar.getInstance();

        TimeStampToken token = plugin.getTimeStamp(fichero, calendar);
        Assert.assertNotNull(token);

        System.out.println("Token obtenido:");
        byte[] encoded = token.getEncoded();
        System.out.println(new String(encoded));
        System.out.println();
        System.out.println(Base64.encode(encoded));
    }

}
