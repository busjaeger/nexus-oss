package org.sonatype.nexus.content.internal;

/**
 * Content-Range used for http range requests
 * 
 * @author bbusjaeger
 */
public class ContentRange {

  /**
   * Parses the given element of a byte-range-set range wrt the provided content length. Throws an
   * exception if the range is syntactically invalid. If a successfully parsed range is not
   * satisfiable, null is returned. Otherwise, the parsed range is returned. Therefore, if this
   * method returns a range, clients can assume the range is syntactically correct and satisfiable
   * wrt the given content length.
   * 
   * See: http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35.1
   * 
   * @param range raw range string from http header
   * @param contentLength entity body length
   * @return parsed range with lower and upper in [0, contentLength) and lower <= upper
   * @throws IllegalArgumentException if the given range is syntactically invalid
   */
  static ContentRange parseContentRange(String range, long contentLength) {
    final int index = range.indexOf('-');
    // invalid: must contain '-'
    if (index == -1)
      throw new IllegalArgumentException("missing '-' separator in " + range);

    final long first;
    final long last;
    // suffix-byte-range. Example: "bytes=-999" (from 0th byte to 999th or last byte)
    if (index == 0) {
      if (range.length() == 1)
        throw new IllegalArgumentException("suffix-length missing in " + range);
      final long suffixLength = parseUnsigned(range.substring(index + 1));
      if (suffixLength < 0)
        throw new IllegalArgumentException("suffix-length in " + range + " must be a positive integer");
      // unsatisfiable: range needs to be at least one byte long
      if (suffixLength == 0)
        return null;
      first = 0l;
      last = (suffixLength < contentLength ? suffixLength : contentLength) - 1;
    }
    // byte-range-spec without last-byte-pos. Example: "bytes=500-" (from 500th byte to the end)
    else if (index == range.length() - 1) {
      final long firstBytePos = parseUnsigned(range.substring(0, index));
      if (firstBytePos < 0)
        throw new IllegalArgumentException("first-byte-pos in " + range + "must be a positive integer");
      // unsatisfiable: first position needs to be within content body
      if (firstBytePos >= contentLength)
        return null;
      first = firstBytePos;
      last = contentLength - 1;
    }
    // byte-range-spec. Example: "bytes=500-999" (from 500th byte to 999th or last byte)
    else {
      final long firstBytePos = parseUnsigned(range.substring(0, index));
      if (firstBytePos < 0)
        throw new IllegalArgumentException("first-byte-pos in " + range + " must be a positive integer");
      final long lastBytePos = parseUnsigned(range.substring(index + 1));
      if (lastBytePos < 0)
        throw new IllegalArgumentException("last-byte-pos in " + range + " must be a positive integer");
      if (firstBytePos > lastBytePos)
        throw new IllegalArgumentException("first-byte-pos in " + range + " greater than last-byte-pos");
      // unsatisfiable: first position needs to be within content body
      if (firstBytePos >= contentLength)
        return null;
      first = firstBytePos;
      last = lastBytePos < contentLength ? lastBytePos : contentLength - 1;
    }
    return new ContentRange(first, last);
  }

  private static long parseUnsigned(String s) {
    try {
      return Long.parseLong(s);
    } catch (NumberFormatException e) {
      return -1;
    }
  }

  private final long first;
  private final long last;

  private String string;

  ContentRange(long first, long last) {
    if (first < 0 || last < 0 || first > last)
      throw new IllegalArgumentException("first and last must be positive with first coming before last");
    this.first = first;
    this.last = last;
  }

  /**
   * Returns the content offset, i.e. the index of the first byte of content to return.
   * 
   * @return
   */
  public long first() {
    return first;
  }

  /**
   * Returns the index of the last byte of content to return
   * 
   * @return
   */
  public long last() {
    return last;
  }

  /**
   * Returns how many bytes to return for this range
   * 
   * @return
   */
  public long size() {
    return last - first + 1;
  }

  /**
   * Returns the value of this range in a Content-Range header. See:
   * http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.16
   * 
   * @return
   */
  public String toHeaderValue() {
    if (string == null)
      string = "bytes " + first + "-" + last + "/" + size();
    return string;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (int) (first ^ (first >>> 32));
    result = prime * result + (int) (last ^ (last >>> 32));
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    ContentRange other = (ContentRange) obj;
    if (first != other.first)
      return false;
    if (last != other.last)
      return false;
    return true;
  }

  @Override
  public String toString() {
    return first + ":" + last;
  }

}
