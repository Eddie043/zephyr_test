#ifndef _MCTP_H
#define _MCTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/printk.h>
#include <zephyr.h>
#include <cmsis_os2.h>

#define MCTP_DEBUG 1

#define MCTP_SUCCESS 0
#define MCTP_ERROR 1

#define MCTP_TASK_NAME_LEN 32
#define MCTP_DEFAULT_MSG_MAX_SIZE 64
#define MCTP_DEFAULT_ENDPOINT 0x0A

#define MCTP_TRANSPORT_HEADER_SIZE 4
#define MCTP_MEDIUM_META_SIZE_SMBUS 3
#define MCTP_PEC_SIZE 1 /* SMBUS/I3C */
#define MCTP_META_INFO_SIZE (MCTP_TRANSPORT_HEADER_SIZE + MCTP_PEC_SIZE)

#define MCTP_MAX_MSG_TAG_NUM 8

#define mctp_printf(format, s...) \
	do { \
        if (MCTP_DEBUG) \
		    printk("[%lld][%s::%s::%d]" format, k_uptime_get(), __FILE__, __func__, __LINE__, ## s); \
	} while (0)

typedef enum {
	MCTP_MSG_TYPE_CTRL = 0x00,
	MCTP_MSG_TYPE_PLDM,
	MCTP_MSG_TYPE_NCSI,
	MCTP_MSG_TYPE_ETH,
	MCTP_MSG_TYPE_NVME,
	MCTP_MSG_TYPE_VEN_DEF_PCI = 0x7E,
	MCTP_MSG_TYPE_VEN_DEF_IANA = 0x7F
} MCTP_MSG_TYPE;

typedef enum {
    MCTP_MEDIUM_TYPE_UNKNOWN = 0,
    MCTP_MEDIUM_TYPE_SMBUS,
    MCTP_MEDIUM_TYPE_I3C,
    MCTP_MEDIUM_TYPE_MAX
} MCTP_MEDIUM_TYPE;

/* smbus extra medium data of endpoint */
typedef struct _mctp_i3c_ext_param {
    uint8_t addr; /* 8 bit address */
    uint32_t dummy; // TODO: test only
} mctp_i3c_ext_param;

/* smbus extra medium data of endpoint */
typedef struct _mctp_smbus_ext_param {
    uint8_t addr; /* 8 bit address */
} mctp_smbus_ext_param;

/* mctp extra parameters prototype */
typedef struct _mctp_ext_param {
    /* mctp transport layer parameters */
    uint8_t tag_owner;
    uint8_t msg_tag;
    uint8_t ep;

    /* medium parameters */
    MCTP_MEDIUM_TYPE type;
    union {
        mctp_smbus_ext_param smbus_ext_param;
        mctp_i3c_ext_param i3c_ext_param;
    };
} mctp_ext_param;

/* mctp recevice data callback function prototype */
/* ext_params shoule be bypass to mctp_send_msg if need */
typedef uint8_t (*mctp_fn_cb)(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_param ext_params);

/* medium write/read function prototype */
typedef uint16_t (*medium_tx)(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_param ext_params);
typedef uint16_t (*medium_rx)(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_param *ext_params);

/* prototype for destitation endpoint resloved */
typedef uint8_t (*endpoint_resolve)(uint8_t dest_endpoint, void **mctp_inst, mctp_ext_param *ext_params);

/* smbus config for mctp medium_conf */
typedef struct _mctp_i3c_conf {
    uint8_t bus;
    uint8_t addr;
    uint32_t dummy;
} mctp_i3c_conf;

/* smbus config for mctp medium_conf */
typedef struct _mctp_smbus_conf {
    uint8_t bus;
    uint8_t addr;
} mctp_smbus_conf;

/* mctp medium conf */
typedef union {
    mctp_smbus_conf smbus_conf;
    mctp_i3c_conf i3c_conf;
} mctp_medium_conf;

/* mctp tx message struct */
typedef struct __attribute__((aligned(4))) {
    uint8_t is_bridge_packet;
    uint8_t *buf;
    uint16_t len;
    mctp_ext_param ext_param;
} mctp_tx_msg;

/* mctp main struct */
typedef struct _mctp {
    uint8_t is_servcie_start;
    MCTP_MEDIUM_TYPE medium_type;
    uint8_t endpoint;
    uint16_t max_msg_size;

    /* medium related */
    mctp_medium_conf medium_conf;
    medium_rx read_data;
    medium_tx write_data;
    
    /* get mctp route information by application layer */
    endpoint_resolve ep_resolve;

    /* read/write task */
    osThreadId_t mctp_rx_task_tid;
    osThreadId_t mctp_tx_task_tid;
    uint8_t mctp_rx_task_name[MCTP_TASK_NAME_LEN];
    uint8_t mctp_tx_task_name[MCTP_TASK_NAME_LEN];

    /* write queue */
    struct k_msgq mctp_tx_queue;

    /* point to the rx message buffer that is assembling */
    struct {
        uint8_t *buf;
        uint16_t ofs;
    } temp_msg_buf[MCTP_MAX_MSG_TAG_NUM];
    
    /* the callback when recevie mctp data */
    mctp_fn_cb rx_cb;
} mctp;

/* debug util */
static inline void print_data_hex(uint8_t *buf, uint32_t len)
{
    if (!buf || !len)
        return;

    uint16_t i;
    for (i = 0; i < len; i++) {
        if (!(i % 16) && i)
            printk("\n");
        printk("%02X ", *(buf + i));
    }
    printk("\n");
}

/* public function */
mctp *mctp_init(void);

uint8_t mctp_deinit(mctp *mctp_inst);

uint8_t mctp_set_medium_configure(mctp *mctp_inst, MCTP_MEDIUM_TYPE medium_type, mctp_medium_conf medium_conf);

/* medium_conf should be freed by application */
uint8_t mctp_get_medium_configure(mctp *mctp_inst, MCTP_MEDIUM_TYPE *medium_type, mctp_medium_conf *medium_conf);

/* mctp service start */
uint8_t mctp_start(mctp *mctp_inst);

/* mctp service stop */
uint8_t mctp_stop(mctp *mctp_inst);

/* send message to destination endpoint */
uint8_t mctp_send_msg(mctp *mctp_inst, uint8_t *buf, uint16_t len, mctp_ext_param ext_params);

/* bridge message to destination endpoint */
uint8_t mctp_bridge_msg(mctp *mctp_inst, uint8_t *buf, uint16_t len, mctp_ext_param ext_params);

/* medium init/deinit */
uint8_t mctp_smbus_init(mctp *mctp_inst, mctp_medium_conf medium_conf);
uint8_t mctp_smbus_deinit(mctp *mctp_inst);

/* register endpoint resolve function */
uint8_t mctp_reg_endpoint_resolve_func(mctp *mctp_inst, endpoint_resolve resolve_fn);

/* register callback function when the mctp message is received */
uint8_t mctp_reg_msg_rx_func(mctp *mctp_inst, mctp_fn_cb rx_cb);

#ifdef __cplusplus
}
#endif

#endif /* _PLDM_H */