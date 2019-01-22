package org.fundaciobit.tsa.client.excepciones;

import java.io.Serializable;

public class AutenticacionException extends Exception implements Serializable {
  private static final long serialVersionUID = 1L;

  public AutenticacionException() {
  }

  public AutenticacionException(Throwable cause) {
    super(cause);
  }

  public AutenticacionException(String mensaje) {
    super(mensaje);
  }
}
