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
#include "pldm_base.h"
#include "pldm_oem.h"

#define PLDM_DEBUG 1

#define PLDM_SUCCESS 0
#define PLDM_ERROR 1

/* generic pldm completion codes  */
#define PLDM_BASE_CODES_SUCCESS 0x00
#define PLDM_BASE_CODES_ERROR 0x01
#define PLDM_BASE_CODES_ERROR_INVALID_DATA 0x02
#define PLDM_BASE_CODES_ERROR_INVALID_LENGTH 0x03
#define PLDM_BASE_CODES_ERROR_NOT_READY 0x04
#define PLDM_BASE_CODES_ERROR_UNSUPPORT_PLDM_CMD 0x05
#define PLDM_BASE_CODES_ERROR_UNSUPPORT_PLDM_TYPE 0x20

#define PLDM_MAX_DATA_SIZE 256

typedef uint8_t (*pldm_cmd_proc_fn)(uint8_t *, uint16_t, uint8_t *, uint16_t *);

typedef enum {
    PLDM_TYPE_BASE = 0x00,
    PLDM_TYPE_SMBIOS,
    PLDM_TYPE_PLAT_MON_CTRL,
    PLDM_TYPE_BIOS_CTRL_CONF,
    PLDM_TYPE_FW_UPDATE = 0x05,
    PLDM_TYPE_OEM = 0x3F
} PLDM_TYPE;

typedef struct _pldm_cmd_handler {
    uint8_t cmd_code;
    pldm_cmd_proc_fn fn;
} pldm_cmd_handler;

typedef struct __attribute__((packed)) {
    uint8_t msg_type : 7;
    uint8_t ic : 1;

    union {
        struct {
            uint8_t inst_id : 5;
            uint8_t rsvd : 1;
            uint8_t d : 1;
            uint8_t rq : 1;
        };
        uint8_t req_d_id;
    };
    
    uint8_t pldm_type : 6;
    uint8_t ver : 2;
    uint8_t cmd;
} pldm_hdr;

typedef struct __attribute__((packed)) {
    pldm_hdr common_hdr;
    uint8_t resp_comp_code;
} pldm_resp_hdr;

typedef struct _pldm_msg {
    pldm_hdr hdr; /* TODO: endian check */
    uint8_t buf[PLDM_MAX_DATA_SIZE];
    uint16_t len;
} pldm_msg;

/* the pldm command handler */
uint8_t mctp_pldm_cmd_handler(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_param ext_params);

/* send the pldm command message through mctp with timeout setting and timeout callback function */
uint8_t mctp_pldm_send_msg_with_timeout(void *mctp_p, pldm_msg *msg, mctp_ext_param ext_param, 
                        void (*resp_fn)(void *, uint8_t *, uint16_t), void *cb_args,
                        uint16_t timeout_ms, void (*to_fn)(void *), void *to_fn_args);

/* send the pldm command message through mctp */
uint8_t mctp_pldm_send_msg(void *mctp_p, pldm_msg *msg, mctp_ext_param ext_param, 
                        void (*resp_fn)(void *, uint8_t *, uint16_t), void *cb_args);

uint8_t pldm_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _PLDM_H */