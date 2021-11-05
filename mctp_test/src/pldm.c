#include <zephyr.h>
#include <sys/printk.h>
#include <cmsis_os2.h>
#include "mctp.h"
#include "pldm.h"

/* commands of pldm type 0x00 : PLDM_TYPE_CTRL_DISCOV */
#define PLDM_CTRL_DISCOV_CMD_CODE_SETTID 0x01
#define PLDM_CTRL_DISCOV_CMD_CODE_GETTID 0x02
#define PLDM_CTRL_DISCOV_CMD_CODE_GET_PLDM_VER 0x03
#define PLDM_CTRL_DISCOV_CMD_CODE_GET_PLDM_TYPE 0x04
#define PLDM_CTRL_DISCOV_CMD_CODE_GET_PLDM_CMDS 0x05

typedef enum {
    PLDM_TYPE_CTRL_DISCOV = 0x00,
    PLDM_TYPE_SMBIOS,
    PLDM_TYPE_PLAT_MON_CTRL,
    PLDM_TYPE_BIOS_CTRL_CONF,
    PLDM_TYPE_FW_UPDATE = 0x05
} PLDM_TYPE;

typedef struct __attribute__((packed)) {
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

uint8_t get_tid(void *mctp_p, uint8_t src_ep, uint8_t *buf, uint32_t len, mctp_medium_ext_param medium_ext_params)
{
    mctp_printf("\n");
    return MCTP_SUCCESS;
}

typedef struct _cmd_handler {
    uint8_t cmd_code;
    mctp_fn_cb fn;
} cmd_handler;

static cmd_handler pldm_ctrl_discov_table[] ={
    {PLDM_CTRL_DISCOV_CMD_CODE_GETTID, get_tid},
    {0xFF, NULL}
};

uint8_t pldm_cmd_handler(void *mctp_p, uint8_t src_ep, uint8_t *buf, uint32_t len, mctp_medium_ext_param medium_ext_params)
{
	mctp_printf("\n");
	if (!mctp_p || !buf || !len)
		return MCTP_ERROR;

    pldm_hdr *hdr = (pldm_hdr *)buf;
    mctp_printf("sizeof(pldm_hdr) = %x\n", sizeof(pldm_hdr));
    mctp_printf("req_d_id = 0x%x\n", hdr->req_d_id);
    mctp_printf("pldm_type = 0x%x\n", hdr->pldm_type);
    mctp_printf("ver = 0x%x\n", hdr->ver);
    mctp_printf("cmd = 0x%x\n", hdr->cmd);

    cmd_handler *cmd_p = NULL;
    switch (hdr->pldm_type) {
    case PLDM_TYPE_CTRL_DISCOV:
        cmd_p = pldm_ctrl_discov_table;
        break;
    default:
        break;
    }

    if (!cmd_p)
        return MCTP_ERROR;

    uint8_t i;
    for (i = 0; ; i++) {
        if ((cmd_p + i)->cmd_code == 0xFF)
            break;

        if ((cmd_p + i)->cmd_code != hdr->cmd)
            continue;

        if ((cmd_p + i)->fn)
            (cmd_p + i)->fn(mctp_p, src_ep, buf, len, medium_ext_params);
        break;
    }

	return MCTP_SUCCESS;
}