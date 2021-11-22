#include <zephyr.h>
#include <string.h>
#include <sys/printk.h>
#include <sys/slist.h>
#include <cmsis_os2.h>
#include "mctp.h"
#include "pldm.h"

#define STACKSIZE 1024
#define PLDM_HDR_INST_ID_MASK 0x1F
#define PLDM_MSG_CHECK_PER_MS 1000
#define PLDM_MSG_TIMEOUT_MS 5000
#define PLDM_RESP_MSG_PROC_MUTEX_TIMEOUT_MS 500

K_THREAD_STACK_DEFINE(list_thread_stack_area, STACKSIZE);

typedef struct _req_pldm_msg {
    sys_snode_t node;
    pldm_hdr hdr;
    int64_t exp_timeout_time;
    void (*resp_fn)(void *, uint8_t *, uint16_t);
    void *cb_args;
    void (*to_fn)(void *);
    void *to_fn_args;
} req_pldm_msg;

typedef struct _pldm {
    /* pldm message response timeout prcoess resource */
    k_tid_t monitor_task;
    struct k_thread thread_data;
    sys_slist_t non_resp_list;
    struct k_mutex list_mutex;

} pldm_t;

struct _pldm_handler_query_entry {
    PLDM_TYPE type;
    uint8_t (*handler_query)(uint8_t, void **);
};

static pldm_t pldm;

static struct _pldm_handler_query_entry query_tbl[] = {
    {PLDM_TYPE_BASE, pldm_base_handler_query},
    {PLDM_TYPE_OEM, pldm_oem_handler_query}
};

static void list_monitor(void *pldm_p, void *dummy0, void *dummy1)
{
    if (!pldm_p) {
        pldm_printf("pldm is null\n");
        return;
    }

    (void)dummy0;
    (void)dummy1;

    pldm_t *pldm_inst = (pldm_t *)pldm_p;

    while (1) {
        k_msleep(PLDM_MSG_CHECK_PER_MS);

        if (k_mutex_lock(&pldm.list_mutex, K_MSEC(PLDM_RESP_MSG_PROC_MUTEX_TIMEOUT_MS))) {
            pldm_printf("pldm mutex is locked over %d ms!!\n", PLDM_RESP_MSG_PROC_MUTEX_TIMEOUT_MS);
            continue;
        }

        sys_snode_t *node;
        sys_snode_t *s_node;
        sys_snode_t *pre_node = NULL;
        int64_t cur_uptime = k_uptime_get();

        SYS_SLIST_FOR_EACH_NODE_SAFE(&pldm_inst->non_resp_list, node, s_node) {
            req_pldm_msg *p = (req_pldm_msg *)node;

            if ((p->exp_timeout_time <= cur_uptime)) {
                pldm_printf("pldm msg timeout!!\n");
                pldm_printf("type %x, cmd %x, inst_id %x\n", p->hdr.pldm_type, p->hdr.cmd, p->hdr.inst_id);
                sys_slist_remove(&pldm.non_resp_list, pre_node, node);

                if (p->to_fn)
                    p->to_fn(p->to_fn_args);

                k_free(p);
            } else {
                pre_node = node;
            }
        }
        k_mutex_unlock(&pldm.list_mutex);
    }
}

static uint8_t pldm_resp_msg_proc(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_param ext_params)
{
	if (!mctp_p || !buf || !len)
		return PLDM_ERROR;

    pldm_msg *msg = (pldm_msg *)buf;
    sys_snode_t *node;
    sys_snode_t *s_node;
    sys_snode_t *pre_node = NULL;
    sys_snode_t *found_node = NULL;

    if (k_mutex_lock(&pldm.list_mutex, K_MSEC(PLDM_RESP_MSG_PROC_MUTEX_TIMEOUT_MS))) {
        pldm_printf("pldm mutex is locked over %d ms!!\n", PLDM_RESP_MSG_PROC_MUTEX_TIMEOUT_MS);
        return PLDM_ERROR;
    }

    SYS_SLIST_FOR_EACH_NODE_SAFE(&pldm.non_resp_list, node, s_node) {
        req_pldm_msg *p = (req_pldm_msg *)node;

        /* found the proper handler */
        if ((p->hdr.inst_id == msg->hdr.inst_id) && 
            (p->hdr.pldm_type == msg->hdr.pldm_type) && 
            (p->hdr.cmd == msg->hdr.cmd)) {
            
            found_node = node;
            sys_slist_remove(&pldm.non_resp_list, pre_node, node);
            break;
        } else {
            pre_node = node;
        }
    }
    k_mutex_unlock(&pldm.list_mutex);

    if (found_node) {
        /* invoke resp handler */
        req_pldm_msg *p = (req_pldm_msg *)found_node;
        if (p->resp_fn)
            p->resp_fn(p->cb_args, buf + sizeof(p->hdr), len - sizeof(p->hdr)); /* remove pldm header for handler */
        k_free(p);
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

    pldm_cmd_proc_fn handler = NULL;
    uint8_t (*handler_query)(uint8_t, void **) = NULL;

    uint8_t i;
    for (i = 0; i < ARRAY_SIZE(query_tbl); i++) {
        if (hdr->pldm_type == query_tbl[i].type) {
            handler_query = query_tbl[i].handler_query;
        break;
    }
    }

    if (!handler_query) {
        *comp = PLDM_BASE_CODES_ERROR_UNSUPPORT_PLDM_TYPE;
        goto send_msg;
    }
    
    uint8_t rc = PLDM_ERROR;
    /* found the proper cmd handler in the pldm_type_cmd table */
    rc = handler_query(hdr->cmd, (void **)&handler);
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

uint8_t mctp_pldm_send_msg_with_timeout(void *mctp_p, pldm_msg *msg, mctp_ext_param ext_param, 
                        void (*resp_fn)(void *, uint8_t *, uint16_t), void *cb_args,
                        uint16_t timeout_ms, void (*to_fn)(void *), void *to_fn_args)
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

    if (rc == MCTP_ERROR) {
        pldm_printf("mctp_send_msg error!!\n");
        return PLDM_ERROR;
    }

    if (msg->hdr.rq) {
        /* if the msg is sending request, should store the msg/resp_fn/cb_args, which are used to handle the response data */
        req_pldm_msg *req_msg = (req_pldm_msg *)k_malloc(sizeof(*req_msg));
        if (!req_msg) {
            pldm_printf("malloc FAILED!!\n");
            return PLDM_ERROR;
        }
        memset(req_msg, 0, sizeof(*req_msg));

        req_msg->hdr = msg->hdr;
        req_msg->resp_fn = resp_fn;
        req_msg->cb_args = cb_args;
        req_msg->to_fn = to_fn;
        req_msg->to_fn_args = to_fn_args;
        
        /* the uptime is int64_t millisecond, don't care overflow */
        req_msg->exp_timeout_time = k_uptime_get() + ((timeout_ms) ? timeout_ms : PLDM_MSG_TIMEOUT_MS);

        /* TODO: should set timeout? */
        k_mutex_lock(&pldm.list_mutex, K_FOREVER);
        sys_slist_append(&pldm.non_resp_list, &req_msg->node);
        k_mutex_unlock(&pldm.list_mutex);
    }

    /* store the msg for waiting response */
    return PLDM_SUCCESS;
}

/* send the pldm cmd through mctp */
uint8_t mctp_pldm_send_msg(void *mctp_p, pldm_msg *msg, mctp_ext_param ext_param, 
                        void (*resp_fn)(void *, uint8_t *, uint16_t), void *cb_args)
{
    return mctp_pldm_send_msg_with_timeout(mctp_p, msg, ext_param, resp_fn, cb_args, 0, NULL, NULL);
#if 0
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

    if (rc == MCTP_ERROR) {
        pldm_printf("mctp_send_msg error!!\n");
        return PLDM_ERROR;
    }

    if (msg->hdr.rq) {
        /* if the msg is sending request, should store the msg/resp_fn/cb_args, which are used to handle the response data */
        req_pldm_msg *req_msg = (req_pldm_msg *)k_malloc(sizeof(*req_msg));
        if (!req_msg) {
            pldm_printf("malloc FAILED!!\n");
            return PLDM_ERROR;
        }

        req_msg->hdr = msg->hdr;
        req_msg->resp_fn = resp_fn;
        req_msg->cb_args = cb_args;
        
        /* the uptime is int64_t millisecond, don't care overflow */
        req_msg->exp_timeout_time = k_uptime_get() + PLDM_MSG_TIMEOUT_MS;

        /* TODO: should set timeout? */
        k_mutex_lock(&pldm.list_mutex, K_FOREVER);
        sys_slist_append(&pldm.non_resp_list, &req_msg->node);
        k_mutex_unlock(&pldm.list_mutex);
    }

    /* store the msg for waiting response */
    return PLDM_SUCCESS;
#endif
}

uint8_t pldm_init(void)
{
    sys_slist_init(&pldm.non_resp_list);
    
    if (k_mutex_init(&pldm.list_mutex))
        return PLDM_ERROR;
    
    pldm.monitor_task = k_thread_create(&pldm.thread_data,
        list_thread_stack_area,
        K_THREAD_STACK_SIZEOF(list_thread_stack_area),
        list_monitor,
        &pldm, NULL, NULL,
        7, 0, K_MSEC(10)
    );

    if (!pldm.monitor_task) {
        pldm_printf("create pldm monitor task failed!!\n");
        return PLDM_ERROR;
    }

    return PLDM_SUCCESS;
}

uint8_t pldm_deinit(void)
{
    return PLDM_SUCCESS;
}