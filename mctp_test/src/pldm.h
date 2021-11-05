#ifndef _PLDM_H
#define _PLDM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/printk.h>
#include <zephyr.h>
#include <cmsis_os2.h>
#include "mctp.h"

uint8_t pldm_cmd_handler(void *mctp_p, uint8_t src_ep, uint8_t *buf, uint32_t len, mctp_medium_ext_param medium_ext_params);

#ifdef __cplusplus
}
#endif

#endif /* _PLDM_H */