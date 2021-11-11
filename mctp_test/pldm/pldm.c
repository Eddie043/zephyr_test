#include <zephyr.h>
#include <string.h>
#include <sys/printk.h>
#include <sys/slist.h>
#include <cmsis_os2.h>
#include "mctp.h"
#include "pldm.h"

#define PLDM_HDR_INST_ID_MASK 0x1F

typedef struct _req_pldm_msg {
    sys_snode_t node;
    pldm_hdr hdr;
    void (*resp_cb)(void *, uint8_t *, uint16_t);
    void *cb_args;
} req_pldm_msg;

static sys_slist_t non_resp_list;

static uint8_t pldm_resp_msg_proc(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_param ext_params)
{
	if (!mctp_p || !buf || !len)
		return PLDM_ERROR;

    pldm_msg *msg = (pldm_msg *)buf;
    sys_snode_t *node;
    sys_snode_t *s_node;
    sys_snode_t *pre_node = NULL;
    pldm_printf("msg->hdr.inst_id = %x\n", msg->hdr.inst_id);
    pldm_printf("msg->hdr.pldm_type = %x\n", msg->hdr.pldm_type);
    pldm_printf("msg->hdr.cmd = %x\n", msg->hdr.cmd);
    SYS_SLIST_FOR_EACH_NODE_SAFE(&non_resp_list, node, s_node) {
        req_pldm_msg *p = (req_pldm_msg *)node;

        pldm_printf("p->hdr.inst_id = %x\n", p->hdr.inst_id);
        pldm_printf("p->hdr.pldm_type = %x\n", p->hdr.pldm_type);
        pldm_printf("p->hdr.cmd = %x\n", p->hdr.cmd);

        /* found the proper handler */
        if ((p->hdr.inst_id == msg->hdr.inst_id) && 
            (p->hdr.pldm_type == msg->hdr.pldm_type) && 
            (p->hdr.cmd == msg->hdr.cmd)) {
            
            sys_slist_remove(&non_resp_list, pre_node, node);
            
            /* invoke resp handler */
            if (p->resp_cb)
                p->resp_cb(p->cb_args, buf, len);
            k_free(p);
        } else {
            pre_node = node;
        }
    }

    return PLDM_SUCCESS;
}

uint8_t mctp_pldm_cmd_handler(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_param ext_params)
{
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

        pldm_resp_msg_proc(mctp_p, buf, len, ext_params);

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

/* send the pldm cmd through mctp */
uint8_t mctp_pldm_send_msg(void *mctp_p, pldm_msg *msg, mctp_ext_param ext_param, 
                        void (*resp_cb)(void *, uint8_t *, uint16_t), void *cb_args)
{
    if (!mctp_p || !msg)
        return PLDM_ERROR;

    /* the request should be set inst_id/msg_type/mctp_tag_owner in the header */
    if (msg->hdr.rq) {
        static uint8_t inst_id;

        /* set pldm header */
        msg->hdr.inst_id = (inst_id++) & PLDM_HDR_INST_ID_MASK;
        msg->hdr.msg_type = MCTP_MSG_TYPE_PLDM;
        
        /* set mctp extra parameters */
        ext_param.tag_owner = 1;
    }

    uint16_t send_len = sizeof(msg->hdr) + msg->len;
    pldm_printf("msg->hdr.inst_id = %x\n", msg->hdr.inst_id);
    pldm_printf("msg->hdr.pldm_type = %x\n", msg->hdr.pldm_type);
    pldm_printf("msg->hdr.cmd = %x\n", msg->hdr.cmd);
    print_data_hex((uint8_t *)msg, send_len);
	uint8_t rc = mctp_send_msg(mctp_p, (uint8_t *)msg, send_len, ext_param);

    if (rc == MCTP_ERROR)
        return PLDM_ERROR;

    if (msg->hdr.rq) {
        /* if the msg is request, should store the msg/resp_cb/cb_args, which are used to handle the response data */
        req_pldm_msg *req_msg = (req_pldm_msg *)k_malloc(sizeof(*req_msg));
        if (!req_msg)
            return PLDM_ERROR;

        req_msg->hdr = msg->hdr;
        req_msg->resp_cb = resp_cb;
        req_msg->cb_args = cb_args;

        sys_slist_append(&non_resp_list, &req_msg->node);
    }

    /* store the msg for waiting response */
    return PLDM_SUCCESS;
}

uint8_t pldm_init(void)
{
    sys_slist_init(&non_resp_list);
    return PLDM_SUCCESS;
}

uint8_t pldm_deinit(void)
{
    return PLDM_SUCCESS;
}