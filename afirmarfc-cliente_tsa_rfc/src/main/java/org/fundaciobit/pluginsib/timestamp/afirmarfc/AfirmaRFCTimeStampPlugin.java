package org.fundaciobit.pluginsib.timestamp.afirmarfc;

import java.util.Properties;

import org.fundaciobit.pluginsib.timestamp.afirmaclientetsarfc.AfirmaClienteTsaRfcTimeStampPlugin;

/**
 * Només es per retrocompatibilitat amb AfirmaRFCTimeStampPlugin
 * @author anadal
 *
 */
public class AfirmaRFCTimeStampPlugin extends AfirmaClienteTsaRfcTimeStampPlugin {

  /**
   * 
   */
  public AfirmaRFCTimeStampPlugin() {
    super();
  }

  /**
   * @param propertyKeyBase
   * @param properties
   */
  public AfirmaRFCTimeStampPlugin(String propertyKeyBase, Properties properties) {
    super(propertyKeyBase, properties);
  }

  /**
   * @param propertyKeyBase
   */
  public AfirmaRFCTimeStampPlugin(String propertyKeyBase) {
    super(propertyKeyBase);
  }

}
