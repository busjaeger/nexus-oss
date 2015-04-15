package org.sonatype.nexus.proxy;

/**
 * Exception indicates that a precondition was violated when storing an item. For example,
 * the digest of an item at the time of applying modified state did not match what the client expected.
 *
 */
@SuppressWarnings("deprecation")
public class PreconditionFailedException extends StorageException {

  private static final long serialVersionUID = 2519473778374642946L;

  public PreconditionFailedException(String msg) {
    super(msg);
  }

  public PreconditionFailedException(String msg, Throwable cause) {
    super(msg, cause);
  }

  public PreconditionFailedException(Throwable cause) {
    super(cause);
  }

}
