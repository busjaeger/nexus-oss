package org.sonatype.nexus.content.internal;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.util.Arrays.asList;
import static javax.servlet.http.HttpServletResponse.SC_PARTIAL_CONTENT;
import static javax.servlet.http.HttpServletResponse.SC_REQUESTED_RANGE_NOT_SATISFIABLE;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.sonatype.nexus.configuration.application.NexusConfiguration;
import org.sonatype.nexus.proxy.ResourceStoreRequest;
import org.sonatype.nexus.proxy.attributes.Attributes;
import org.sonatype.nexus.proxy.item.StorageFileItem;
import org.sonatype.nexus.proxy.router.RepositoryRouter;
import org.sonatype.nexus.web.WebUtils;

public class ContentServletTest {

  @Test
  public void testDoGetFileUnsatisfiable() throws ServletException, IOException {
    final HttpServletRequest request = mockRequest("bytes=2-5");
    final StorageFileItem file = mockFile(new byte[] {1});
    final HttpServletResponse response = mock(HttpServletResponse.class);
    mockServlet().doGetFile(request, response, file);
    verify(response).setStatus(SC_REQUESTED_RANGE_NOT_SATISFIABLE);
    verify(response).setHeader("Content-Range", "bytes */1");
  }

  @Test
  public void testDoGetFileSingleRange() throws ServletException, IOException {
    final HttpServletRequest request = mockRequest("bytes=2-4");
    final StorageFileItem file = mockFile(new byte[] {0, 1, 2, 3, 4, 5});
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final HttpServletResponse response = mockResponse(out);
    mockServlet().doGetFile(request, response, file);
    verify(response).setStatus(SC_PARTIAL_CONTENT);
    verify(response).setContentType(file.getMimeType());
    verify(response).setContentLength(3);
    verify(response).setHeader("Content-Range", "bytes 2-4/3");
    assertArrayEquals(new byte[] {2, 3, 4}, out.toByteArray());
  }

  @Test
  public void testDoGetFileMultiRange() throws ServletException, IOException {
    final HttpServletRequest request = mockRequest("bytes=2-4,6-8");
    final StorageFileItem file = mockFile(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final HttpServletResponse response = mockResponse(out);

    mockServlet().doGetFile(request, response, file);

    // boundary changes across invocations, so need to figure it out here
    final ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(response).setContentType(captor.capture());
    final String contentType = captor.getValue();
    final String boundary = contentType.substring(contentType.lastIndexOf('=') + 1);

    verify(response).setStatus(SC_PARTIAL_CONTENT);
    assertEquals("multipart/byteranges; boundary=" + boundary, contentType);

    final byte[] boundary0 = ("\r\n--" + boundary + "\r\nContent-Type: " + file.getMimeType() + "\r\nContent-Range: bytes 2-4/3\r\n\r\n").getBytes(ISO_8859_1);
    final byte[] content0 = new byte[] {2, 3, 4};
    final byte[] boundary1 = ("\r\n--" + boundary + "\r\nContent-Type: " + file.getMimeType() + "\r\nContent-Range: bytes 6-8/3\r\n\r\n").getBytes(ISO_8859_1);
    final byte[] content1 = new byte[] {6, 7, 8};
    final byte[] boundaryEnd = ("\r\n--" + boundary + "--\r\n").getBytes(ISO_8859_1);
    final byte[] expected = concat(new byte[][] {boundary0, content0, boundary1, content1, boundaryEnd});
    verify(response).setContentLength(expected.length);
    assertArrayEquals(expected, out.toByteArray());
  }

  private static byte[] concat(byte[][] arrays) {
    int length = 0;
    for (int i = 0; i < arrays.length; i++)
      length += arrays[i].length;
    final byte[] array = new byte[length];
    int pos = 0;
    for (int i = 0; i < arrays.length; i++) {
      System.arraycopy(arrays[i], 0, array, pos, arrays[i].length);
      pos += arrays[i].length;
    }
    return array;
  }

  @Test
  public void testGetRanges() {
    final HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader("Range")).thenReturn("bytes=1-2,3-4, 5-7");
    assertEquals(asList(new ContentRange(1, 2), new ContentRange(3, 4), new ContentRange(5, 7)), //
        mockServlet().getRanges(request, 10));
  }

  @Test
  public void testGetRangesNull() {
    final HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader("Range")).thenReturn(null);
    assertNull(mockServlet().getRanges(request, 10));
  }

  @Test
  public void testGetRangesSyntacticallyIncorrect() {
    final HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader("Range")).thenReturn("1-3,4-2, 5-7");
    assertNull(mockServlet().getRanges(request, 10));
  }

  @Test
  public void testGetRangesNonAscending() {
    final HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader("Range")).thenReturn("bytes=1-3,2-4");
    assertEquals(asList(), mockServlet().getRanges(request, 10));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testGetSatisfiableRangesNoBytePrefix() {
    mockServlet().getSatisfiableRanges("1-3", 4);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testGetSatisfiableRangesSyntaxError() {
    mockServlet().getSatisfiableRanges("bytes=3-1", 4);
  }

  @Test
  public void testGetSatisfiableRanges() {
    assertEquals(asList(new ContentRange(2, 3)), mockServlet().getSatisfiableRanges("bytes=-0, ,2-3 , 6-8", 4));
  }

  @Test
  public void testAscendingSingle() {
    assertTrue(ContentServlet.ascending(asList(new ContentRange(1, 1))));
  }

  @Test
  public void testAscending() {
    assertTrue(ContentServlet.ascending(asList(new ContentRange(1, 2), new ContentRange(3, 5))));
  }

  @Test
  public void testAscendingOverlap() {
    assertFalse(ContentServlet.ascending(asList(new ContentRange(1, 2), new ContentRange(2, 5))));
  }

  @Test
  public void testAscendingInverted() {
    assertFalse(ContentServlet.ascending(asList(new ContentRange(2, 5), new ContentRange(1, 2))));
  }

  @Test
  public void testAscendingEmpty() {
    assertTrue(ContentServlet.ascending(Collections.<ContentRange>emptyList()));
  }

  private static ContentServlet mockServlet() {
    return new ContentServlet(mock(NexusConfiguration.class), mock(RepositoryRouter.class), mock(ContentRenderer.class), mock(WebUtils.class));
  }

  private static HttpServletRequest mockRequest(String rangeHeader) {
    final HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getMethod()).thenReturn("GET");
    when(request.getHeader("Range")).thenReturn(rangeHeader);
    return request;
  }

  private static StorageFileItem mockFile(byte[] content) {
    final StorageFileItem file = mock(StorageFileItem.class);
    when(file.isContentGenerated()).thenReturn(false);
    when(file.isVirtual()).thenReturn(false);
    when(file.getModified()).thenReturn(1l);
    final Attributes attributes = mock(Attributes.class);
    when(attributes.containsKey(StorageFileItem.DIGEST_SHA1_KEY)).thenReturn(false);
    when(file.getRepositoryItemAttributes()).thenReturn(attributes);
    when(file.getResourceStoreRequest()).thenReturn(new ResourceStoreRequest(""));
    when(file.getLength()).thenReturn((long) content.length);
    when(file.getMimeType()).thenReturn("application/java-archive");
    try {
      when(file.getInputStream()).thenReturn(new ByteArrayInputStream(content));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return file;
  }

  private static HttpServletResponse mockResponse(final OutputStream out) {
    final HttpServletResponse response = mock(HttpServletResponse.class);
    try {
      when(response.getOutputStream()).thenReturn(new ServletOutputStream() {
        @Override
        public void write(int b) throws IOException {
          out.write(b);
        }
      });
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return response;
  }
}
