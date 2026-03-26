#ifndef ARDHPDEBUG_HIDPI_H
#define ARDHPDEBUG_HIDPI_H

int ardhpdebug_hidpi_enabled_from_env(void);
void ardhpdebug_output_to_logical_size(int window_w,
                                       int window_h,
                                       int output_w,
                                       int output_h,
                                       int hidpi_enabled,
                                       int *logical_w,
                                       int *logical_h);

#endif
