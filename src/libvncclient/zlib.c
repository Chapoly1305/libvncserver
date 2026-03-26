/*
 *  Copyright (C) 2000 Tridia Corporation.  All Rights Reserved.
 *  Copyright (C) 1999 AT&T Laboratories Cambridge.  All Rights Reserved.
 *
 *  This is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This software is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this software; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 *  USA.
 */

#ifdef LIBVNCSERVER_HAVE_LIBZ

/*
 * zlib.c - handle zlib encoding.
 *
 * This file shouldn't be compiled directly.  It is included multiple times by
 * rfbproto.c, each time with a different definition of the macro BPP.  For
 * each value of BPP, this file defines a function which handles an zlib
 * encoded rectangle with BPP bits per pixel.
 */

#define HandleZlibBPP CONCAT2E(HandleZlib,BPP)
#define CARDBPP CONCAT3E(uint,BPP,_t)
#define EnsureRawBufferBPP CONCAT2E(EnsureRawBuffer,BPP)
#define CanDirectDecodeBPP CONCAT2E(CanDirectDecode,BPP)
#define CopyIntoFrameBufferBPP CONCAT2E(CopyIntoFrameBuffer,BPP)

static rfbBool
EnsureRawBufferBPP(rfbClient* client, size_t need)
{
  size_t cap;
  char *buf;

  if (client->raw_buffer != NULL &&
      client->raw_buffer_size > 0 &&
      (size_t)client->raw_buffer_size >= need) {
    return TRUE;
  }

  cap = (client->raw_buffer_size > 0) ? (size_t)client->raw_buffer_size : 0;
  if (cap < 65536) {
    cap = 65536;
  }
  while (cap < need) {
    size_t next = cap * 2;
    if (next <= cap) {
      cap = need;
      break;
    }
    cap = next;
  }

  buf = (char *)realloc(client->raw_buffer, cap);
  if (buf == NULL) {
    rfbClientLog("zlib raw buffer allocation failed for %lu bytes\n",
                 (unsigned long)cap);
    return FALSE;
  }

  client->raw_buffer = buf;
  client->raw_buffer_size = (int)cap;
  return TRUE;
}

static rfbBool
CanDirectDecodeBPP(rfbClient* client, int rx, int ry, int rw, int rh,
                   Bytef **dst_out, size_t *row_bytes_out, size_t *stride_bytes_out)
{
  size_t offset;

  if (client->GotBitmap != rfbClientDefaultGotBitmap ||
      client->frameBuffer == NULL ||
      rx != 0 ||
      rw != client->width ||
      ry < 0 ||
      rh <= 0 ||
      ry + rh > client->height) {
    return FALSE;
  }

  *stride_bytes_out = (size_t)client->width * (size_t)(BPP / 8);
  *row_bytes_out = (size_t)rw * (size_t)(BPP / 8);
  offset = (size_t)ry * (*stride_bytes_out) + (size_t)rx * (size_t)(BPP / 8);
  *dst_out = (Bytef *)(client->frameBuffer + offset);
  return TRUE;
}

static rfbBool
CopyIntoFrameBufferBPP(rfbClient* client, const Bytef *src,
                       int rx, int ry, int rw, int rh)
{
  size_t row_bytes;
  size_t stride_bytes;
  size_t offset;
  Bytef *dst;
  int row;

  if (client->frameBuffer == NULL ||
      rx < 0 || ry < 0 ||
      rw <= 0 || rh <= 0 ||
      rx + rw > client->width ||
      ry + rh > client->height) {
    return FALSE;
  }

  row_bytes = (size_t)rw * (size_t)(BPP / 8);
  stride_bytes = (size_t)client->width * (size_t)(BPP / 8);
  offset = (size_t)ry * stride_bytes + (size_t)rx * (size_t)(BPP / 8);
  dst = (Bytef *)(client->frameBuffer + offset);

  if (rx == 0 && rw == client->width) {
    memcpy(dst, src, row_bytes * (size_t)rh);
    return TRUE;
  }

  for (row = 0; row < rh; ++row) {
    memcpy(dst, src, row_bytes);
    dst += stride_bytes;
    src += row_bytes;
  }
  return TRUE;
}

static rfbBool
HandleZlibBPP (rfbClient* client, int rx, int ry, int rw, int rh)
{
  rfbZlibHeader hdr;
  int remaining;
  int inflateResult;
  int toRead;
  size_t raw_size;
  size_t direct_row_bytes;
  size_t direct_stride_bytes;
  Bytef *dst;
  rfbBool direct_decode;

  /* First make sure we have a large enough raw buffer to hold the
   * decompressed data.  In practice, with a fixed BPP, fixed frame
   * buffer size and the first update containing the entire frame
   * buffer, this buffer allocation should only happen once, on the
   * first update.
   */
  raw_size = (size_t)rw * (size_t)rh * (size_t)(BPP / 8);
  direct_decode = CanDirectDecodeBPP(client, rx, ry, rw, rh, &dst,
                                     &direct_row_bytes, &direct_stride_bytes);
  if (!direct_decode) {
    if (!EnsureRawBufferBPP(client, raw_size)) {
      return FALSE;
    }
    dst = (Bytef *)client->raw_buffer;
    direct_row_bytes = raw_size;
    direct_stride_bytes = raw_size;
  }

  if (!ReadFromRFBServer(client, (char *)&hdr, sz_rfbZlibHeader))
    return FALSE;

  remaining = rfbClientSwap32IfLE(hdr.nBytes);

  /* Need to initialize the decompressor state. */
  client->decompStream.next_in   = ( Bytef * )client->buffer;
  client->decompStream.avail_in  = 0;
  client->decompStream.next_out  = dst;
  client->decompStream.avail_out = direct_decode ? direct_row_bytes : client->raw_buffer_size;
  client->decompStream.data_type = Z_BINARY;

  /* Initialize the decompression stream structures on the first invocation. */
  if ( client->decompStreamInited == FALSE ) {

    inflateResult = inflateInit( &client->decompStream );

    if ( inflateResult != Z_OK ) {
      rfbClientLog(
              "inflateInit returned error: %d, msg: %s\n",
              inflateResult,
              client->decompStream.msg);
      return FALSE;
    }

    client->decompStreamInited = TRUE;

  }

  inflateResult = Z_OK;

  /* Process buffer full of data until no more to process, or
   * some type of inflater error, or Z_STREAM_END.
   */
  while (( remaining > 0 ) &&
         ( inflateResult == Z_OK )) {
  
    if ( remaining > RFB_BUFFER_SIZE ) {
      toRead = RFB_BUFFER_SIZE;
    }
    else {
      toRead = remaining;
    }

    /* Fill the buffer, obtaining data from the server. */
    if (!ReadFromRFBServer(client, client->buffer,toRead))
      return FALSE;

    client->decompStream.next_in  = ( Bytef * )client->buffer;
    client->decompStream.avail_in = toRead;

    /* Need to uncompress buffer full. */
    inflateResult = inflate( &client->decompStream, Z_SYNC_FLUSH );

    /* We never supply a dictionary for compression. */
    if ( inflateResult == Z_NEED_DICT ) {
      rfbClientLog("zlib inflate needs a dictionary!\n");
      return FALSE;
    }
    if ( inflateResult < 0 ) {
      rfbClientLog(
              "zlib inflate returned error: %d, msg: %s\n",
              inflateResult,
              client->decompStream.msg);
      return FALSE;
    }

    /* Result buffer allocated to be at least large enough.  We should
     * never run out of space!
     */
    if (( client->decompStream.avail_in > 0 ) &&
        ( client->decompStream.avail_out <= 0 )) {
      rfbClientLog("zlib inflate ran out of space!\n");
      return FALSE;
    }

    remaining -= toRead;

  } /* while ( remaining > 0 ) */

  if ( inflateResult == Z_OK ) {

    /* Put the uncompressed contents of the update on the screen. */
    if (!direct_decode && client->GotBitmap == rfbClientDefaultGotBitmap) {
      if (!CopyIntoFrameBufferBPP(client, (const Bytef *)client->raw_buffer,
                                  rx, ry, rw, rh)) {
        rfbClientLog("zlib framebuffer copy failed for rect %dx%d at (%d,%d)\n",
                     rw, rh, rx, ry);
        return FALSE;
      }
    } else if (!direct_decode) {
      client->GotBitmap(client, (uint8_t *)client->raw_buffer, rx, ry, rw, rh);
    }
  }
  else {

    rfbClientLog(
            "zlib inflate returned error: %d, msg: %s\n",
            inflateResult,
            client->decompStream.msg);
    return FALSE;

  }

  return TRUE;
}

#undef CARDBPP
#undef EnsureRawBufferBPP
#undef CanDirectDecodeBPP
#undef CopyIntoFrameBufferBPP

#endif
