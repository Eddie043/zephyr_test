#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <zephyr.h>
#include <sys/printk.h>
#include <cmsis_os2.h>
#include "mctp.h"

#define MCTP_DEFAULT_THREAD_STACK_SIZE 0x1000
#define MCTP_DEFAULT_THREAD_PRIORITY osPriorityNormal
#define MCTP_TX_QUEUE_SIZE 16

#define MCTP_HDR_HDR_VER 0x01
#define MCTP_HDR_SEQ_MASK 0x03
#define MCTP_HDR_TAG_MASK 0x07
#define MCTP_HDR_TAG_MAX 0x07

typedef struct __attribute__((packed)) {
    uint8_t hdr_ver;
    uint8_t dest_ep;
    uint8_t src_ep;
    union {
        struct {
            uint8_t msg_tag : 3;
            uint8_t to : 1;
            uint8_t pkt_seq : 2;
            uint8_t eom : 1;
            uint8_t som : 1;

        };
        uint8_t flags_seq_to_tag;
    };
} mctp_hdr;

/* set thread name */
static uint8_t set_thread_name(mctp *mctp_inst)
{
    if (!mctp_inst)
        return MCTP_ERROR;

    if (mctp_inst->medium_type <= MCTP_MEDIUM_TYPE_UNKNOWN || mctp_inst->medium_type >= MCTP_MEDIUM_TYPE_MAX)
        return MCTP_ERROR;

    if (mctp_inst->medium_type == MCTP_MEDIUM_TYPE_SMBUS) {
        mctp_smbus_conf *smbus_conf = (mctp_smbus_conf *)&mctp_inst->medium_conf;
        snprintf(mctp_inst->mctp_rx_task_name, sizeof(mctp_inst->mctp_rx_task_name), 
            "mctprx_%02x_%02x_%02x", mctp_inst->medium_type, smbus_conf->bus, smbus_conf->addr);
        snprintf(mctp_inst->mctp_tx_task_name, sizeof(mctp_inst->mctp_tx_task_name), 
            "mctptx_%02x_%02x_%02x", mctp_inst->medium_type, smbus_conf->bus, smbus_conf->addr);
    }

    return MCTP_SUCCESS;
}

/* init the medium related resources */
static uint8_t mctp_medium_init(mctp *mctp_inst, mctp_medium_conf medium_conf)
{
    if (!mctp_inst)
        return MCTP_ERROR;

    uint8_t rc = MCTP_ERROR;
    switch (mctp_inst->medium_type) {
    case MCTP_MEDIUM_TYPE_SMBUS:
        rc = mctp_smbus_init(mctp_inst, medium_conf);
        break;
    default:
        break;
    }

    return rc;
}

static uint8_t mctp_medium_deinit(mctp *mctp_inst)
{
    if (!mctp_inst)
        return MCTP_ERROR;

    switch (mctp_inst->medium_type) {
    case MCTP_MEDIUM_TYPE_SMBUS:
        mctp_smbus_deinit(mctp_inst);
        break;
    default:
        break;
    }

    return MCTP_SUCCESS;
}

static uint8_t bridge_msg(mctp *mctp_inst, uint8_t *buf, uint16_t len)
{
    if (!mctp_inst || !buf || !len)
        return MCTP_ERROR;

    if (!mctp_inst->ep_resolve)
        return MCTP_ERROR;
    
    mctp *target_mctp = NULL;
    mctp_medium_ext_param target_medium_ext_params;
    memset(&target_medium_ext_params, 0, sizeof(target_medium_ext_params));

    mctp_hdr *hdr = (mctp_hdr *)buf;
    uint8_t rc = mctp_inst->ep_resolve(hdr->dest_ep, (void **)&target_mctp, &target_medium_ext_params);
    if (rc != MCTP_SUCCESS) {
        mctp_printf("can't bridge endpoint %x\n", hdr->dest_ep);
        return MCTP_ERROR;
    }

    mctp_printf("rc = %d, bridget msg to mctp = %p\n", rc, target_mctp);
    mctp_bridge_msg(target_mctp, buf, len, target_medium_ext_params);
    return MCTP_SUCCESS;
}

/* mctp rx task */
static void mctp_rx_task(void *arg)
{
    if (!arg) {
        mctp_printf("mctp_rx_task without mctp_inst!\n");
        return;
    }
    
    mctp *mctp_inst = (mctp *)arg;
    if (!mctp_inst->read_data) {
        mctp_printf("mctp_rx_task without medium read function!\n");
        return;
    }

    mctp_printf("mctp_rx_task start %p!\n", mctp_inst);
    while (1) {
        /* TODO: read data from medium interface */

        uint8_t i = 0;
        while (1) {
            k_msleep(1000000);
            if (!(++i % 16))
                break;
        }
            
        uint8_t read_buf[256] = {0};
        mctp_medium_ext_param medium_ext_param;
        memset(&medium_ext_param, 0, sizeof(medium_ext_param));
        uint16_t read_len = mctp_inst->read_data(mctp_inst, read_buf, sizeof(read_buf), &medium_ext_param);
        if (!read_len)
            continue;
        mctp_printf("mctp_inst %p, read_len = %d\n", mctp_inst, read_len);
        if (1) {
            print_data_hex(read_buf, read_len);
        }
        
        mctp_hdr *hdr = (mctp_hdr *)read_buf;
        mctp_printf("dest_ep = %x, src_ep = %x, flags = %x\n", hdr->dest_ep, hdr->src_ep, hdr->flags_seq_to_tag);
        if (hdr->dest_ep == mctp_inst->endpoint) {
            /* TODO: handle this packet by self 
             * 1. if it is just a part of message, collect it until the EOM set.
             * 2. Otherwise, invoke rx callback function to pass message to application layer.
             */

            if (mctp_inst->rx_cb)
                mctp_inst->rx_cb(mctp_inst, hdr->src_ep, read_buf + sizeof(hdr), read_len - sizeof(hdr), medium_ext_param);
            continue;
        }

        /* try to bridge this packet */
        bridge_msg(mctp_inst, read_buf, read_len);
    }
}

/* mctp tx task */
static void mctp_tx_task(void *arg)
{
    if (!arg) {
        mctp_printf("mctp_tx_task without mctp_inst!\n");
        return;
    }
    
    mctp *mctp_inst = (mctp *)arg;

    if (!mctp_inst->mctp_tx_queue) {
        mctp_printf("mctp_tx_task without mctp_tx_queue!\n");
        return;
    }

    if (!mctp_inst->write_data) {
        mctp_printf("mctp_tx_task without medium write function!\n");
        return;
    }

    mctp_printf("mctp_tx_task start %p!\n", mctp_inst);
    while (1) {
        mctp_tx_msg mctp_msg = {0};
        osStatus_t rc = osMessageQueueGet(mctp_inst->mctp_tx_queue, &mctp_msg, NULL, osWaitForever);
        if (rc != osOK)
            continue;

        if (!mctp_msg.buf || !mctp_msg.len)
            continue;

        if (0) {
            mctp_printf("tx endpoint %x\n", mctp_msg.endpoint);
            print_data_hex(mctp_msg.buf, mctp_msg.len);
        }

        /* bridge meesage alread has the mctp transport header, so doesn't need to make header */
        /* bridge message also doesn't need to split packet */
        if (mctp_msg.is_bridge_packet) {
            mctp_inst->write_data(mctp_inst, mctp_msg.buf, mctp_msg.len, mctp_msg.medium_ext_param);

            k_free(mctp_msg.buf);
            continue;
        }

        /* set up MCTP header and send to destination endpoint */
        static uint8_t msg_tag;
        uint16_t max_msg_size = mctp_inst->max_msg_size;
        uint8_t i;
        uint8_t split_pkt_num = (mctp_msg.len / max_msg_size) + ((mctp_msg.len % max_msg_size)? 1: 0);
        mctp_printf("mctp_msg.len = %d\n", mctp_msg.len);
        mctp_printf("split_pkt_num = %d\n", split_pkt_num);
        for (i = 0; i < split_pkt_num; i++) {
            uint8_t buf[max_msg_size + MCTP_TRANSPORT_HEADER_SIZE];
            mctp_hdr *hdr = (mctp_hdr *)buf;
            uint8_t cp_msg_size = max_msg_size;

            memset(buf, 0, sizeof(buf));

            /* first packet should set SOM */
            if (!i)
                hdr->som = 1;

            /* last packet should set EOM */
            if (i == (split_pkt_num - 1)) {
                hdr->eom = 1;
                uint8_t remain = mctp_msg.len % max_msg_size;
                cp_msg_size = remain? remain: max_msg_size; /* remain data */
            }

            hdr->to = mctp_msg.tag_owner;
            hdr->pkt_seq = i & MCTP_HDR_SEQ_MASK;
            hdr->msg_tag = msg_tag & MCTP_HDR_TAG_MASK;

            hdr->dest_ep = mctp_msg.endpoint;
            hdr->src_ep = mctp_inst->endpoint;
            hdr->hdr_ver = MCTP_HDR_HDR_VER;

            mctp_printf("i = %d, cp_msg_size = %d\n", i, cp_msg_size);
            mctp_printf("hdr->flags_seq_to_tag = %x\n", hdr->flags_seq_to_tag);
            memcpy(buf + MCTP_TRANSPORT_HEADER_SIZE, mctp_msg.buf + i * max_msg_size, cp_msg_size);
            mctp_inst->write_data(mctp_inst, buf, cp_msg_size + MCTP_TRANSPORT_HEADER_SIZE, mctp_msg.medium_ext_param);
        }

        k_free(mctp_msg.buf);

        if (++msg_tag >= MCTP_HDR_TAG_MAX)
            msg_tag = 0;
    }
}

/* mctp handle initial */
mctp *mctp_init(void)
{
    mctp *mctp_inst = (mctp *)k_malloc(sizeof(*mctp_inst));
    
    if (!mctp_inst)
        return NULL;

    memset(mctp_inst, 0, sizeof(*mctp_inst));
    mctp_inst->medium_type = MCTP_MEDIUM_TYPE_UNKNOWN;
    mctp_inst->max_msg_size = MCTP_DEFAULT_MSG_MAX_SIZE;
    mctp_inst->endpoint = MCTP_DEFAULT_ENDPOINT;

    if (MCTP_DEBUG)
        mctp_printf("mctp_inst = %p\n", mctp_inst);
    return mctp_inst;
}

/* mctp handle deinitial */
uint8_t mctp_deinit(mctp *mctp_inst)
{
    if (!mctp_inst)
        return MCTP_ERROR;

    if (MCTP_DEBUG)
        mctp_printf("mctp_inst = %p\n", mctp_inst);

    mctp_stop(mctp_inst);
    mctp_medium_deinit(mctp_inst);
    
    k_free(mctp_inst);
    return MCTP_SUCCESS;
}

/* configure mctp handle with specific medium type */
uint8_t mctp_set_medium_configure(mctp *mctp_inst, MCTP_MEDIUM_TYPE medium_type, mctp_medium_conf medium_conf)
{
    if (!mctp_inst)
        return MCTP_ERROR;

    if (medium_type <= MCTP_MEDIUM_TYPE_UNKNOWN || medium_type >= MCTP_MEDIUM_TYPE_MAX)
        return MCTP_ERROR;

    mctp_inst->medium_type = medium_type;
    if (mctp_medium_init(mctp_inst, medium_conf) == MCTP_ERROR)
        goto error;
    return MCTP_SUCCESS;

error:
    mctp_medium_deinit(mctp_inst);
    mctp_inst->medium_type = MCTP_MEDIUM_TYPE_UNKNOWN;
    return MCTP_ERROR;
}

uint8_t mctp_get_medium_configure(mctp *mctp_inst, MCTP_MEDIUM_TYPE *medium_type, mctp_medium_conf *medium_conf)
{
    if (!mctp_inst || !medium_type || !medium_conf)
        return MCTP_ERROR;

    *medium_type = mctp_inst->medium_type;
    *medium_conf = mctp_inst->medium_conf;
    return MCTP_SUCCESS;
}

uint8_t mctp_stop(mctp *mctp_inst)
{
    if (!mctp_inst)
        return MCTP_ERROR;

    if (mctp_inst->mctp_rx_task_tid) {
        osThreadTerminate(mctp_inst->mctp_rx_task_tid);
        mctp_inst->mctp_rx_task_tid = NULL;
    }

    if (mctp_inst->mctp_tx_task_tid) {
        osThreadTerminate(mctp_inst->mctp_tx_task_tid);
        mctp_inst->mctp_tx_task_tid = NULL;
    }

    if (!mctp_inst->mctp_tx_queue) {
        osMessageQueueDelete(mctp_inst->mctp_tx_queue);
        mctp_inst->mctp_tx_queue = NULL;
    }

    mctp_inst->is_servcie_start = 0;
    return MCTP_SUCCESS;
}

uint8_t mctp_start(mctp *mctp_inst)
{
    if (!mctp_inst)
        return MCTP_ERROR;
    
    if (mctp_inst->is_servcie_start) {
        mctp_printf("The mctp_inst is already start!\n");
        return MCTP_ERROR;
    }

    set_thread_name(mctp_inst);
    mctp_inst->mctp_tx_queue = osMessageQueueNew(MCTP_TX_QUEUE_SIZE, sizeof(mctp_tx_msg), NULL);
    if (!mctp_inst->mctp_tx_queue)
        goto error;

    osThreadAttr_t thread_attr = {0};
    /* create rx service */

    /* the name len of osThreadAttr_t is only 16 bytes */
    thread_attr.name = (const char *)mctp_inst->mctp_rx_task_name;
    thread_attr.priority = MCTP_DEFAULT_THREAD_PRIORITY;
    thread_attr.stack_size = MCTP_DEFAULT_THREAD_STACK_SIZE;
    mctp_inst->mctp_rx_task_tid = osThreadNew(mctp_rx_task, (void *)mctp_inst, &thread_attr);
    if (!mctp_inst->mctp_rx_task_tid)
        goto error;
    
    /* let the thread can be terminated by osThreadTerminate */
    osThreadDetach(mctp_inst->mctp_rx_task_tid);
    
    mctp_printf("mctp_inst->mctp_rx_task_tid = %p\n", mctp_inst->mctp_rx_task_tid);

    /* create tx service */
    thread_attr.name = (const char *)mctp_inst->mctp_tx_task_name;
    mctp_inst->mctp_tx_task_tid = osThreadNew(mctp_tx_task, (void *)mctp_inst, &thread_attr);
    if (!mctp_inst->mctp_tx_task_tid)
        goto error;
    osThreadDetach(mctp_inst->mctp_tx_task_tid);
    
    mctp_printf("mctp_inst->mctp_tx_task_tid = %p\n", mctp_inst->mctp_tx_task_tid);
    
    mctp_inst->is_servcie_start = 1;
    return MCTP_SUCCESS;

error:
    mctp_printf("mctp_start failed!!\n");
    mctp_stop(mctp_inst);
    return MCTP_ERROR;
}

uint8_t mctp_bridge_msg(mctp *mctp_inst, uint8_t *buf, uint16_t len, mctp_medium_ext_param medium_ext_param)
{
    if (!mctp_inst || !buf || !len)
        return MCTP_ERROR;
    
    if (!mctp_inst->is_servcie_start || !mctp_inst->mctp_tx_queue) {
        mctp_printf("The mctp_inst isn't start service!\n");
        return MCTP_ERROR;
    }

    mctp_tx_msg mctp_msg = {0};
    mctp_msg.is_bridge_packet = 1;
    mctp_msg.len = len;
    mctp_msg.buf = (uint8_t *)k_malloc(len);
    if (!mctp_msg.buf)
        goto error;
    memcpy(mctp_msg.buf, buf, len);

    mctp_printf("sizeof(medium_ext_param) = %d\n", sizeof(medium_ext_param));
    mctp_msg.medium_ext_param = medium_ext_param;

    osStatus_t rc = osMessageQueuePut(mctp_inst->mctp_tx_queue, &mctp_msg, 0, 0);
    return (rc == osOK)? MCTP_SUCCESS: MCTP_ERROR;

error:
    if (mctp_msg.buf)
        k_free(mctp_msg.buf);

    return MCTP_ERROR;
}

uint8_t mctp_send_msg(mctp *mctp_inst, uint8_t dest_ep, uint8_t *buf, uint16_t len, uint8_t tag_owner, mctp_medium_ext_param medium_ext_param)
{
    if (!mctp_inst || !buf || !len)
        return MCTP_ERROR;
    
    if (!mctp_inst->is_servcie_start || !mctp_inst->mctp_tx_queue) {
        mctp_printf("The mctp_inst isn't start service!\n");
        return MCTP_ERROR;
    }

    mctp_tx_msg mctp_msg = {0};
    mctp_msg.endpoint = dest_ep;
    mctp_msg.len = len;
    mctp_msg.tag_owner = tag_owner;
    mctp_msg.buf = (uint8_t *)k_malloc(len);
    if (!mctp_msg.buf)
        goto error;
    memcpy(mctp_msg.buf, buf, len);

    mctp_printf("sizeof(medium_ext_param) = %d\n", sizeof(medium_ext_param));
    mctp_msg.medium_ext_param = medium_ext_param;

    osStatus_t rc = osMessageQueuePut(mctp_inst->mctp_tx_queue, &mctp_msg, 0, 0);
    return (rc == osOK)? MCTP_SUCCESS: MCTP_ERROR;

error:
    if (mctp_msg.buf)
        k_free(mctp_msg.buf);

    return MCTP_ERROR;
}

uint8_t mctp_reg_endpoint_resolve_func(mctp *mctp_inst, endpoint_resolve resolve_fn)
{
    if (!mctp_inst || !resolve_fn)
        return MCTP_ERROR;

    mctp_inst->ep_resolve = resolve_fn;
    return MCTP_SUCCESS;
}

uint8_t mctp_reg_msg_rx_func(mctp *mctp_inst, mctp_fn_cb rx_cb)
{
    if (!mctp_inst || !rx_cb)
        return MCTP_ERROR;

    mctp_inst->rx_cb = rx_cb;
    return MCTP_SUCCESS;
}