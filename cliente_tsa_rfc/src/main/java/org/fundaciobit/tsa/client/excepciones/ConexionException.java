package org.fundaciobit.tsa.client.excepciones;

import java.io.Serializable;

public class ConexionException extends Exception implements Serializable {
  private static final long serialVersionUID = 1L;

  public ConexionException() {
  }

  public ConexionException(Throwable cause) {
    super(cause);
  }

  public ConexionException(String mensaje) {
    super(mensaje);
  }
}
