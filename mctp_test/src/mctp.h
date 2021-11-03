#include <stdint.h>
#include <sys/printk.h>
#include <cmsis_os2.h>

#define MCTP_DEBUG 1

#define MCTP_SUCCESS 0
#define MCTP_ERROR 1

#define MCTP_TASK_NAME_LEN 32
#define MCTP_DEFAULT_MSG_MAX_SIZE 64
#define MCTP_DEFAULT_ENDPOINT 0x09

#define MCTP_TRANSPORT_HEADER_SIZE 4
#define MCTP_PEC_SIZE 1 /* SMBUS/I3C */
#define MCTP_META_INFO_SIZE (MCTP_TRANSPORT_HEADER_SIZE + MCTP_PEC_SIZE)

#define mctp_printf(format, s...) \
	do { \
        if (MCTP_DEBUG) \
		    printk("[%s::%s::%d]" format, __FILE__, __func__, __LINE__, ## s); \
	} while (0)

typedef enum {
    MCTP_MEDIUM_TYPE_UNKNOWN = 0,
    MCTP_MEDIUM_TYPE_SMBUS,
    MCTP_MEDIUM_TYPE_I3C,
    MCTP_MEDIUM_TYPE_MAX
} MCTP_MEDIUM_TYPE;

/* mctp recevice data callback function prototype */
typedef uint8_t (*mctp_rx_cb)(void *mctp_p, uint8_t src_ep, uint8_t *buf, uint32_t len);

/* medium write/read function prototype */
typedef uint16_t (*medium_txrx)(void *mctp_p, uint8_t *buf, uint32_t len, void *medium_ext_params);

/* prototype for destitation endpoint resloved */
typedef uint8_t (*endpoint_resolve)(uint8_t dest_endpoint, void **mctp_inst, void **medium_ext_params);

/* mctp route entry struct */
typedef struct _mctp_route_entry {
    uint8_t endpoint;
    uint8_t bus; /* TODO: only consider smbus/i3c */
    uint8_t addr; /* TODO: only consider smbus/i3c */
} mctp_route_entry;

/* smbus extra medium data of endpoint */
typedef struct _mctp_smbus_ext_param {
    uint8_t addr;
} mctp_smbus_ext_param;

/* smbus config for mctp medium_conf */
typedef struct _mctp_smbus_conf {
    uint8_t bus;
    uint8_t addr;
} mctp_smbus_conf;

/* mctp tx message struct */
typedef struct _mctp_tx_msg {
    uint8_t is_bridge_packet;
    uint8_t endpoint;
    uint8_t tag_owner;
    uint8_t *buf;
    uint16_t len;
    void *medium_ext_param;
} mctp_tx_msg;

/* mctp main struct */
typedef struct _mctp {
    uint8_t is_servcie_start;
    MCTP_MEDIUM_TYPE medium_type;
    uint8_t endpoint;
    uint16_t max_msg_size;

    /* medium related */
    void *medium_conf;
    medium_txrx read_data;
    medium_txrx write_data;
    
    /* get mctp route information by application layer */
    endpoint_resolve ep_resolve;

    /* read/write task */
    osThreadId_t mctp_rx_task_tid;
    osThreadId_t mctp_tx_task_tid;
    uint8_t mctp_rx_task_name[MCTP_TASK_NAME_LEN];
    uint8_t mctp_tx_task_name[MCTP_TASK_NAME_LEN];

    /* write queue */
    osMessageQueueId_t mctp_tx_queue;
    
    /* the callback when recevie mctp data */
    mctp_rx_cb rx_cb;
} mctp;

/* public function */
mctp *mctp_init(void);

uint8_t mctp_deinit(mctp *mctp_inst);

uint8_t mctp_set_medium_configure(mctp *mctp_inst, MCTP_MEDIUM_TYPE medium_type, void *medium_conf);

/* medium_conf should be freed by application */
uint8_t mctp_get_medium_configure(mctp *mctp_inst, MCTP_MEDIUM_TYPE *medium_type, void **medium_conf);

/* mctp service start */
uint8_t mctp_start(mctp *mctp_inst);

/* mctp service stop */
uint8_t mctp_stop(mctp *mctp_inst);

/* send message to destination endpoint */
uint8_t mctp_send_msg(mctp *mctp_inst, uint8_t dest_ep, uint8_t *buf, uint16_t len, uint8_t tag_owner, void *medium_ext_params);

/* bridge message to destination endpoint */
uint8_t mctp_bridge_msg(mctp *mctp_inst, uint8_t *buf, uint16_t len, void *medium_ext_params);

/* medium init/deinit */
uint8_t mctp_smbus_init(mctp *mctp_inst, mctp_smbus_conf *medium_conf);
uint8_t mctp_smbus_deinit(mctp *mctp_inst);

/* register endpoint resolve function */
uint8_t mctp_reg_endpoint_resolve_func(mctp *mctp_inst, endpoint_resolve resolve_fn);



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