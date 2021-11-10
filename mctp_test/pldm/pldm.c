#include <zephyr.h>
#include <string.h>
#include <sys/printk.h>
#include <cmsis_os2.h>
#include "mctp.h"
#include "pldm.h"

#define PLDM_INST_MAX_NUM 8

typedef enum {
    PLDM_TYPE_BASE = 0x00,
    PLDM_TYPE_SMBIOS,
    PLDM_TYPE_PLAT_MON_CTRL,
    PLDM_TYPE_BIOS_CTRL_CONF,
    PLDM_TYPE_FW_UPDATE = 0x05
} PLDM_TYPE;

uint8_t mctp_pldm_cmd_handler(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_param ext_params)
{
	pldm_printf("\n");
	if (!mctp_p || !buf || !len)
		return PLDM_ERROR;

    pldm_hdr *hdr = (pldm_hdr *)buf;
    pldm_printf("sizeof(pldm_hdr) = %x\n", sizeof(pldm_hdr));
    pldm_printf("msg_type = %d\n", hdr->msg_type);
    pldm_printf("req_d_id = 0x%x\n", hdr->req_d_id);
    pldm_printf("pldm_type = 0x%x\n", hdr->pldm_type);
    pldm_printf("ver = 0x%x\n", hdr->ver);
    pldm_printf("cmd = 0x%x\n", hdr->cmd);

    /* the message is a response, check if any callback function should be invoked */
    if (!hdr->rq) {
        /* TODO: implement link list to store the callback function and mapping the inst_id/pldm_type/pldm_cmd */
        return PLDM_SUCCESS;
    }

    /* the message is a request, find the proper handler to handle it */
    /* initial response data */
    uint16_t resp_len = 0;
    pldm_msg resp;
    memset(&resp, 0, sizeof(resp));
    resp.hdr = *hdr;
    resp.hdr.rq = 0;
    resp.len = 1; /* at least 1 byte comp code */

    uint8_t *comp = resp.buf;

    /* the message is a request, check is there handler to process it */
    pldm_cmd_proc_fn handler = NULL;
    uint8_t (*handler_found)(uint8_t, void **);

    switch (hdr->pldm_type) {
    case PLDM_TYPE_BASE:
        handler_found = pldm_base_handler_found;
        break;
    default:
        handler_found = NULL;
        break;
    }

    if (!handler_found) {
        *comp = PLDM_BASE_CODES_ERROR_UNSUPPORT_PLDM_TYPE;
        goto send_msg;
    }
    
    uint8_t rc = PLDM_ERROR;
    /* found the proper cmd handler in the pldm_type_cmd table */
    rc = handler_found(hdr->cmd, (void **)&handler);
    if (rc == PLDM_ERROR || !handler) {
        *comp = PLDM_BASE_CODES_ERROR_UNSUPPORT_PLDM_CMD;
        goto send_msg;
    }
    
    /* invoke the cmd handler to process */
    handler(buf + sizeof(*hdr), len - sizeof(*hdr), resp.buf, &resp.len);

send_msg:
    /* send the pldm response data */
    resp_len = sizeof(resp.hdr) + resp.len;
    pldm_printf("resp_len = %d\n", resp_len);
	return mctp_send_msg(mctp_p, (uint8_t *)&resp, resp_len, ext_params);
}

uint8_t pldm_send_msg(void *mctp_p, uint8_t dest_ep, uint8_t type, uint8_t cmd, uint8_t *buf, uint16_t len, mctp_ext_param ext_params)
{
    if (!mctp_p)
        return PLDM_ERROR;
#if 0
    /* setup pldm header */
    pldm_msg req;
    memset(&req, 0, sizeof(req));

    req.hdr.msg_type = MCTP_MSG_TYPE_PLDM;
    req.hdr.rq = 1;
    req.hdr.pldm_type = type;
    req.hdr.cmd = cmd;
    g_inst_id++;

    uint16_t send_len = sizeof(resp.msg_type) + sizeof(resp.hdr) + resp.resp_len;
	return mctp_send_msg(mctp_p, src_ep, (uint8_t *)&msg, send_len, 1, ext_params);
#endif
    return PLDM_SUCCESS;
}

uint8_t pldm_init(mctp *mctp_inst)
{
    if (!mctp_inst)
        return PLDM_ERROR;

    return PLDM_SUCCESS;
}

uint8_t pldm_deinit(mctp *mctp_inst)
{
    return PLDM_SUCCESS;
}