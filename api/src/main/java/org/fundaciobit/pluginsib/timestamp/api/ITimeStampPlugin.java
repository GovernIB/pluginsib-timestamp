package org.fundaciobit.pluginsib.timestamp.api;

import java.util.Calendar;

import org.fundaciobit.pluginsib.core.v3.IPluginIB;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * Interficie per Segellat de Temps 
 *
 * @author anadal
 *
 */
public interface ITimeStampPlugin extends IPluginIB {

    public static final String TIMESTAMP_BASE_PROPERTY = IPLUGINSIB_BASE_PROPERTIES + "timestamp.";

    public String getTimeStampPolicyOID();

    public String getTimeStampHashAlgorithm();

    public TimeStampToken getTimeStamp(byte[] inputData, final Calendar time) throws Exception;

    public byte[] getTimeStampDirect(byte[] inputData, final Calendar time) throws Exception;

}