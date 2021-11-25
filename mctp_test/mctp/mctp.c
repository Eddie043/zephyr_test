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

#define MSG_ASSEMBLY_BUF_SIZE 1024

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
    mctp_ext_param target_ext_params;
    memset(&target_ext_params, 0, sizeof(target_ext_params));

    mctp_hdr *hdr = (mctp_hdr *)buf;
    uint8_t rc = mctp_inst->ep_resolve(hdr->dest_ep, (void **)&target_mctp, &target_ext_params);
    if (rc != MCTP_SUCCESS) {
        mctp_printf("can't bridge endpoint %x\n", hdr->dest_ep);
        return MCTP_ERROR;
    }

    mctp_printf("rc = %d, bridget msg to mctp = %p\n", rc, target_mctp);
    mctp_bridge_msg(target_mctp, buf, len, target_ext_params);
    return MCTP_SUCCESS;
}

static uint8_t mctp_pkt_assembling(mctp *mctp_inst, uint8_t *buf, uint16_t len)
{
    if (!mctp_inst || !buf || !len)
        return MCTP_ERROR;

    mctp_hdr *hdr = (mctp_hdr *)buf;
    uint8_t **buf_p = &mctp_inst->temp_msg_buf[hdr->msg_tag].buf;
    uint16_t *ofs_p = &mctp_inst->temp_msg_buf[hdr->msg_tag].ofs;
    
    /* one packet msg, do nothing */
    if (hdr->som && hdr->eom)
        return MCTP_SUCCESS;

    if (hdr->som && !hdr->eom) { /* first packet, alloc memory to hold data */
        if (*buf_p)
            free(*buf_p);
        *ofs_p = 0;

        *buf_p = (uint8_t *)k_malloc(MSG_ASSEMBLY_BUF_SIZE);
        printk("*buf_p = %p\n", *buf_p);
        if (!*buf_p) {
            mctp_printf("cannot create memory...\n");
            return MCTP_ERROR;
        }
        memset(*buf_p, 0, MSG_ASSEMBLY_BUF_SIZE);
    }

    printk("*buf_p + *ofs_p = %p\n", *buf_p + *ofs_p);
    memcpy(*buf_p + *ofs_p, buf + sizeof(hdr), len - sizeof(hdr));
    *ofs_p += len - sizeof(hdr);

    mctp_printf("*ofs_p = %d\n", *ofs_p);
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
        k_msleep(1000);

        uint8_t read_buf[256] = {0};
        mctp_ext_param ext_param;
        memset(&ext_param, 0, sizeof(ext_param));
        uint16_t read_len = mctp_inst->read_data(mctp_inst, read_buf, sizeof(read_buf), &ext_param);
        if (!read_len)
            continue;

        if (0)
            print_data_hex(read_buf, read_len);

        mctp_hdr *hdr = (mctp_hdr *)read_buf;
        mctp_printf("dest_ep = %x, src_ep = %x, flags = %x\n", hdr->dest_ep, hdr->src_ep, hdr->flags_seq_to_tag);

        /* set the tranport layer extra parameters */
        ext_param.msg_tag = hdr->msg_tag;
        ext_param.tag_owner = 0; /* the high-level application won't modify the tag_owner flag,
                                    change the tag_owner for response if needs */
        ext_param.ep = hdr->src_ep;

        if (hdr->dest_ep != mctp_inst->endpoint) {
            /* try to bridge this packet */
            bridge_msg(mctp_inst, read_buf, read_len);
            continue;
        }

        /* handle this packet by self */

        /* assembling the mctp message */
        mctp_pkt_assembling(mctp_inst, read_buf, read_len);

        /* if it is not last packet, waiting for the remain data */
        if (!hdr->eom)
            continue;

        if (mctp_inst->rx_cb) {
            uint8_t *p = read_buf + sizeof(hdr); /* default process read data buffer directly */
            uint16_t len = read_len - sizeof(hdr);
            
            if (mctp_inst->temp_msg_buf[hdr->msg_tag].buf) { /* this is assembly message */
                p = mctp_inst->temp_msg_buf[hdr->msg_tag].buf;
                len = mctp_inst->temp_msg_buf[hdr->msg_tag].ofs;

                print_data_hex(p, len);
            }

            /* handle the mctp messsage */
            mctp_inst->rx_cb(mctp_inst, p, len, ext_param);
        }

        if (mctp_inst->temp_msg_buf[hdr->msg_tag].buf) {
            k_free(mctp_inst->temp_msg_buf[hdr->msg_tag].buf);
            mctp_inst->temp_msg_buf[hdr->msg_tag].buf = NULL;
        }

        if (mctp_inst->temp_msg_buf[hdr->msg_tag].ofs)
            mctp_inst->temp_msg_buf[hdr->msg_tag].ofs = 0;
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

    if (!mctp_inst->write_data) {
        mctp_printf("mctp_tx_task without medium write function!\n");
        return;
    }

    mctp_printf("mctp_tx_task start %p!\n", mctp_inst);
    while (1) {
        mctp_tx_msg mctp_msg = {0};
        osStatus_t rc = k_msgq_get(&mctp_inst->mctp_tx_queue, &mctp_msg, K_FOREVER);
        if (rc != osOK)
            continue;

        if (!mctp_msg.buf)
            continue;

        if (!mctp_msg.len) {
            k_free(mctp_msg.buf);
            continue;
        }

        if (0) {
            mctp_printf("tx endpoint %x\n", mctp_msg.ext_param.ep);
            print_data_hex(mctp_msg.buf, mctp_msg.len);
        }

        /* bridge meesage alread has the mctp transport header, so doesn't need to make header */
        /* bridge message also doesn't need to split packet */
        if (mctp_msg.is_bridge_packet) {
            mctp_inst->write_data(mctp_inst, mctp_msg.buf, mctp_msg.len, mctp_msg.ext_param);
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

            hdr->to = mctp_msg.ext_param.tag_owner;
            hdr->pkt_seq = i & MCTP_HDR_SEQ_MASK;

            /* TODO: should avoid the msg_tag if there are pending mctp response packets? */
            /* if the message is response, keep the original msg_tag of ext_param */
            hdr->msg_tag = (hdr->to) ? (msg_tag & MCTP_HDR_TAG_MASK) : mctp_msg.ext_param.msg_tag;

            hdr->dest_ep = mctp_msg.ext_param.ep;
            hdr->src_ep = mctp_inst->endpoint;
            hdr->hdr_ver = MCTP_HDR_HDR_VER;

            mctp_printf("i = %d, cp_msg_size = %d\n", i, cp_msg_size);
            mctp_printf("hdr->flags_seq_to_tag = %x\n", hdr->flags_seq_to_tag);
            memcpy(buf + MCTP_TRANSPORT_HEADER_SIZE, mctp_msg.buf + i * max_msg_size, cp_msg_size);
            mctp_inst->write_data(mctp_inst, buf, cp_msg_size + MCTP_TRANSPORT_HEADER_SIZE, mctp_msg.ext_param);
        }

        k_free(mctp_msg.buf);
        
        /* only request mctp message needs to increase msg_tag */
        if (mctp_msg.ext_param.tag_owner)
            msg_tag++;
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

    if (mctp_inst->mctp_tx_queue.buffer_start) {
        k_free(mctp_inst->mctp_tx_queue.buffer_start);
        mctp_inst->mctp_tx_queue.buffer_start = NULL;
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

    
    uint8_t *msgq_buf = (uint8_t *)k_malloc(MCTP_TX_QUEUE_SIZE * sizeof(mctp_tx_msg));
    if (!msgq_buf) {
        mctp_printf("msgq alloc failed!!\n");
        goto error;
    }

    k_msgq_init(&mctp_inst->mctp_tx_queue, msgq_buf, sizeof(mctp_tx_msg), MCTP_TX_QUEUE_SIZE);

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

uint8_t mctp_bridge_msg(mctp *mctp_inst, uint8_t *buf, uint16_t len, mctp_ext_param ext_param)
{
    if (!mctp_inst || !buf || !len)
        return MCTP_ERROR;
    
    if (!mctp_inst->is_servcie_start) {
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

    mctp_printf("sizeof(ext_param) = %d\n", sizeof(ext_param));
    mctp_msg.ext_param = ext_param;

    int rc = k_msgq_put(&mctp_inst->mctp_tx_queue, &mctp_msg, K_NO_WAIT);
    if (!rc)
        return MCTP_SUCCESS;

error:
    if (mctp_msg.buf)
        k_free(mctp_msg.buf);

    return MCTP_ERROR;
}

uint8_t mctp_send_msg(mctp *mctp_inst, uint8_t *buf, uint16_t len, mctp_ext_param ext_param)
{
    if (!mctp_inst || !buf || !len)
        return MCTP_ERROR;
    
    if (!mctp_inst->is_servcie_start) {
        mctp_printf("The mctp_inst isn't start service!\n");
        return MCTP_ERROR;
    }

    mctp_tx_msg mctp_msg = {0};
    mctp_msg.len = len;
    mctp_msg.buf = (uint8_t *)k_malloc(len);
    if (!mctp_msg.buf)
        goto error;
    memcpy(mctp_msg.buf, buf, len);
    mctp_msg.ext_param = ext_param;

    int rc = k_msgq_put(&mctp_inst->mctp_tx_queue, &mctp_msg, K_NO_WAIT);
    if (!rc)
        return MCTP_SUCCESS;

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