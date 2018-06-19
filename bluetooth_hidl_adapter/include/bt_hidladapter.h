#include <sys/types.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint16_t event;
    uint16_t len;
    uint16_t offset;
    uint16_t layer_specific;
    uint8_t data[];
} _BT_HDR;

#define BT_HDR _BT_HDR
#define BT_HDR_SZ (sizeof(BT_HDR))

typedef void  (*hidl_hci_data_cb)(BT_HDR* packet);
typedef void  (*hidl_hci_info_cb)(void);
typedef char* (*hidl_alloc_cb)(int size);
typedef int   (*hidl_dealloc_cb)(void* start_pointer, char* p_buf/*not used,set to NULL*/);

typedef struct {
    size_t size; // set to sizefo(bt_hidl_cb_t) 
    hidl_hci_data_cb hci_event_received;
    hidl_hci_data_cb acl_data_received;
    hidl_hci_data_cb sco_data_received;
    hidl_hci_info_cb initialization_complete;
    hidl_alloc_cb    alloc;
    hidl_dealloc_cb  dealloc;
} bt_hidl_cb_t;

void hci_initialize(const bt_hidl_cb_t* cb);
void hci_close();
void hci_transmit(BT_HDR* packet);
#ifdef __cplusplus
}
#endif
