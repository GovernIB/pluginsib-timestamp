package org.fundaciobit.plugins.timestamp.api;

import java.util.Calendar;

import org.fundaciobit.plugins.IPlugin;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * Interficie per Segellat de Temps 
 *
 * @author anadal
 *
 */
public interface ITimeStampPlugin extends IPlugin {

  public static final String TIMESTAMP_BASE_PROPERTY = IPLUGIN_BASE_PROPERTIES  + "timestamp.";
  
  public String getTimeStampPolicyOID();
  
  public String getTimeStampHashAlgorithm();
  
  public TimeStampToken getTimeStamp(byte[] inputData, final Calendar time) throws Exception;
  
  public byte[] getTimeStampDirect(byte[] inputData, final Calendar time) throws Exception;

} 