#include "ardhpdebug_hidpi.h"

#include <stdlib.h>
#include <string.h>

int ardhpdebug_hidpi_enabled_from_env(void) {
  const char *value = getenv("VNC_ARD_HIDPI");

  if (!value || !*value) return 1;
  return strcmp(value, "0") != 0 &&
         strcmp(value, "false") != 0 &&
         strcmp(value, "FALSE") != 0 &&
         strcmp(value, "no") != 0 &&
         strcmp(value, "NO") != 0;
}

void ardhpdebug_output_to_logical_size(int window_w,
                                       int window_h,
                                       int output_w,
                                       int output_h,
                                       int hidpi_enabled,
                                       int *logical_w,
                                       int *logical_h) {
  int w = output_w;
  int h = output_h;

  if (hidpi_enabled && output_w > 0 && output_h > 0) {
    int hidpi_scale = 1;

    if (window_w > 0) {
      int inferred = (output_w + (window_w / 2)) / window_w;
      if (inferred > hidpi_scale) hidpi_scale = inferred;
    }
    if (window_h > 0) {
      int inferred = (output_h + (window_h / 2)) / window_h;
      if (inferred > hidpi_scale) hidpi_scale = inferred;
    }
    if (hidpi_scale < 1) hidpi_scale = 1;
    w = output_w / hidpi_scale;
    h = output_h / hidpi_scale;
  }

  if (logical_w) *logical_w = w;
  if (logical_h) *logical_h = h;
}
