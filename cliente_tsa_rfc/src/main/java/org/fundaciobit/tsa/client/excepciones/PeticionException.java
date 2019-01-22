package org.fundaciobit.tsa.client.excepciones;

import java.io.Serializable;

public class PeticionException extends Exception implements Serializable {
  private static final long serialVersionUID = 1L;

  public PeticionException() {
  }

  public PeticionException(Throwable cause) {
    super(cause);
  }

  public PeticionException(String mensaje) {
    super(mensaje);
  }
}

