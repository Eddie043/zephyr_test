#ifndef _PLDM_BASE_H
#define _PLDM_BASE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "pldm.h"

/* commands of pldm type 0x00 : PLDM_TYPE_CTRL_DISCOV */
#define PLDM_BASE_CMD_CODE_SETTID 0x01
#define PLDM_BASE_CMD_CODE_GETTID 0x02
#define PLDM_BASE_CMD_CODE_GET_PLDM_VER 0x03
#define PLDM_BASE_CMD_CODE_GET_PLDM_TYPE 0x04
#define PLDM_BASE_CMD_CODE_GET_PLDM_CMDS 0x05

uint8_t pldm_base_handler_found(uint8_t code, void **ret_fn);

#ifdef __cplusplus
}
#endif

#endif /* _PLDM_BASE_H */