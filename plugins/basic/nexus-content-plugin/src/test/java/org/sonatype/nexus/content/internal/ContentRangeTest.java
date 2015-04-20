package org.sonatype.nexus.content.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class ContentRangeTest {

  @Test(expected = IllegalArgumentException.class)
  public void testParseContentRangeNoSeparator() {
    ContentRange.parseContentRange("12345", 10);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseContentRangeEmtpy() {
    ContentRange.parseContentRange("", 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseContentRangeNoValues() {
    ContentRange.parseContentRange("-", 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseContentRangeNegative() {
    ContentRange.parseContentRange("--123", 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseContentRangeSuffixNoNumber() {
    ContentRange.parseContentRange("-a", 1);
  }

  @Test
  public void testParseSuffix() {
    assertEquals(new ContentRange(0, 0), ContentRange.parseContentRange("-1", 2));
  }

  @Test
  public void testParseUnsatisfiableSuffix() {
    assertNull(ContentRange.parseContentRange("-0", 2));
  }

  @Test
  public void testParseSuffixBeyondLength() {
    assertEquals(new ContentRange(0, 99), ContentRange.parseContentRange("-200", 100));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseContentRangeFirstNoNumber() {
    ContentRange.parseContentRange("a1234-", 1);
  }

  @Test
  public void testParseContentRangeEndOpen() {
    assertEquals(new ContentRange(2, 99), ContentRange.parseContentRange("2-", 100));
  }

  @Test
  public void testParseContentRangeFirstBeyondLength() {
    assertNull(ContentRange.parseContentRange("5-", 5));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseContentRangeFirstAfterLast() {
    ContentRange.parseContentRange("2-1", 10);
  }

  @Test
  public void testParseContentRangeFirstEqualLast() {
    assertEquals(new ContentRange(1, 1), ContentRange.parseContentRange("1-1", 10));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseContentRangeFirstNotANumber() {
    ContentRange.parseContentRange("a-1", 10);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseContentRangeLastNotANumber() {
    ContentRange.parseContentRange("1-n", 10);
  }

  @Test
  public void testParseContentRangeLastBeyondLength() {
    assertEquals(new ContentRange(20, 99), ContentRange.parseContentRange("20-300", 100));
  }

  @Test
  public void testParseContentRangeBothLastBeyondLength() {
    assertNull(ContentRange.parseContentRange("200-300", 100));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testConstructorFirstAfterLast() {
    new ContentRange(2, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testConstructorFirstNegative() {
    new ContentRange(-1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testConstructorSecondNegative() {
    new ContentRange(1, -1);
  }

  @Test
  public void testSize() {
    assertEquals(2, new ContentRange(1, 2).size());
  }

  @Test
  public void testSizeSingle() {
    assertEquals(1, new ContentRange(2, 2).size());
  }

  @Test
  public void testToHeaderValue() {
    final long first = 1;
    final long last = 3;
    final long size = 3; // [1,2,3].length
    final String expected = "bytes " + first + "-" + last + "/" + size;
    final String actual = new ContentRange(first, last).toHeaderValue();
    assertEquals(expected, actual);
  }

}
