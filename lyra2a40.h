#ifndef LYRA2A40_H
#define  LYRA2A40_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void lyra2a40_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
