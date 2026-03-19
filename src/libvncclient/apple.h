#ifndef LIBVNCSERVER_SRC_LIBVNCCLIENT_APPLE_H
#define LIBVNCSERVER_SRC_LIBVNCCLIENT_APPLE_H

#include <rfb/rfbclient.h>

rfbBool rfbClientHandleAppleAuth(rfbClient* client, uint32_t authScheme);
void rfbClientResetAppleAuth(rfbClient* client);

#endif
