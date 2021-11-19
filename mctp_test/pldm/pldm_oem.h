#ifndef _PLDM_OEM_H
#define _PLDM_OEM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "pldm.h"

/* commands of pldm type 0x3F : PLDM_TYPE_OEM */
#define PLDM_OEM_CMD_ECHO 0x00

uint8_t pldm_oem_handler_query(uint8_t code, void **ret_fn);

#ifdef __cplusplus
}
#endif

#endif /* _PLDM_OEM_H */