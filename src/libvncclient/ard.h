#ifndef LIBVNCSERVER_SRC_LIBVNCCLIENT_ARD_H
#define LIBVNCSERVER_SRC_LIBVNCCLIENT_ARD_H

#include <rfb/rfbclient.h>

rfbBool rfbClientHandleARDAuth(rfbClient* client, uint32_t authScheme);
void rfbClientResetARDAuth(rfbClient* client);

#endif
