#define LOG_TAG "bt_hidladapter"

#include "bt_hidladapter.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <utils/Log.h>
#include <stdlib.h>

#include <android/hardware/bluetooth/1.0/IBluetoothHci.h>
#include <android/hardware/bluetooth/1.0/IBluetoothHciCallbacks.h>
#include <android/hardware/bluetooth/1.0/types.h>
#include <hwbinder/ProcessState.h>

using android::hardware::bluetooth::V1_0::IBluetoothHci;
using android::hardware::bluetooth::V1_0::IBluetoothHciCallbacks;
using android::hardware::bluetooth::V1_0::HciPacket;
using android::hardware::bluetooth::V1_0::Status;
using android::hardware::ProcessState;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::hidl_vec;

// handle(2Byte) + ACL length(2Byte) = 4 Byte
#define HCI_ACL_PREAMBLE_SIZE 4

#define MSG_EVT_MASK 0xFF00

#define MSG_HC_TO_STACK_HCI_EVT 0x1000
#define MSG_HC_TO_STACK_HCI_ACL 0x1100
#define MSG_HC_TO_STACK_HCI_SCO 0x1200

#define MSG_STACK_TO_HC_HCI_CMD 0x2000
#define MSG_STACK_TO_HC_HCI_ACL 0x2100
#define MSG_STACK_TO_HC_HCI_SCO 0x2200

#define STREAM_TO_UINT16(u16, p)                                  \
{                                                                 \
    (u16) = ((uint16_t)(*(p)) + (((uint16_t)(*((p) + 1))) << 8)); \
    (p) += 2;                                                     \
}                                                                 \


android::sp<IBluetoothHci> btHci;
bt_hidl_cb_t* hidlCb;

void reassemble_and_dispatch(BT_HDR* packet) {
    uint8_t* stream = packet->data;
    uint16_t handle, acl_length, l2cap_length;
    STREAM_TO_UINT16(handle, stream);
    STREAM_TO_UINT16(acl_length, stream);
    STREAM_TO_UINT16(l2cap_length, stream);
    if (acl_length != packet->len - HCI_ACL_PREAMBLE_SIZE)
}

class BluetoothHciCallbacks : public IBluetoothHciCallbacks {
    public:
	BluetoothHciCallbacks() {
	}

	BT_HDR* WrapPacketAndCopy(uint16_t event, const hidl_vec<uint8_t>& data) {
	    int packet_size = data.size() + BT_HDR_SZ;
	    char* p_buff = hidlCb->alloc(packet_size);
	    if (p_buff == NULL) {
		ALOGE("alloc memory failed");
		return nullptr;
	    }
	    BT_HDR* packet = reinterpret_cast<BT_HDR*>(p_buff);
            packet->offset = 0;
	    packet->len = data.size();
	    ALOGD("size is: %d", packet->len);
	    packet->layer_specific = 0;
	    packet->event = event;

	    // TODO(eisenbach): Avoid copy here; if BT_HDR->data can be ensured to
	    // be the only way the data is accessed, a pointer could be passed here...
	    memcpy(packet->data, data.data(), data.size());
	    return packet;
	}

	Return<void> initializationComplete(Status status) {
	    ALOGI("initializationComplete");
	    if(status == Status::SUCCESS) {
		hidlCb->initialization_complete();
	    }
	    return Void();
	}

	Return<void> hciEventReceived(const hidl_vec<uint8_t>& event) {
	    ALOGI("hciEventReceived");
	    BT_HDR* packet = WrapPacketAndCopy(MSG_HC_TO_STACK_HCI_EVT, event);
	    if(packet != nullptr) {
	        hidlCb->hci_event_received(packet);
	    }
	    return Void();
	}

	Return<void> aclDataReceived(const hidl_vec<uint8_t>& data) {
	    ALOGI("aclDataReceived");
	    BT_HDR* packet = WrapPacketAndCopy(MSG_HC_TO_STACK_HCI_ACL, data);
	    if(packet != nullptr) {
	        hidlCb->acl_event_received(packet);
	    }
	    return Void();
	}

	Return<void> scoDataReceived(const hidl_vec<uint8_t>& data) {
	    ALOGI("scoDataReceived");
	    BT_HDR* packet = WrapPacketAndCopy(MSG_HC_TO_STACK_HCI_SCO, data);
	    if(packet != nullptr) {
	        hidlCb->sco_data_received(packet);
	    }
	    return Void();
	}
};

void hci_initialize(const bt_hidl_cb_t* cb) {
    ALOGI("%s", __func__);
    if (cb == nullptr) {
	ALOGE("%s: bt_hidl_cb is null", __func__);
	return;
    }
    hidlCb = (bt_hidl_cb_t*)cb;
    
    btHci = IBluetoothHci::getService();

    // If android.hardware.bluetooth* is not found, Bluetooth can not continue.
    if (btHci == nullptr) {
	ALOGE("%s: IBluetoothHci::getService() failed", __func__);
	return;
    }
    ALOGI("%s: IBluetoothHci::getService() returned %p (%s)", __func__, btHci.get(), (btHci->isRemote() ? "remote" : "local"));

    // Block allows allocation of a variable that might be bypassed by goto.
    {
	android::sp<IBluetoothHciCallbacks> callbacks = new BluetoothHciCallbacks();
	btHci->initialize(callbacks);
    }
}

void hci_close() {
    btHci->close();
    btHci = nullptr;
}

void hci_transmit(BT_HDR* packet) {
    HciPacket data;
    data.setToExternal(packet->data + packet->offset, packet->len);

    uint16_t event = packet->event & MSG_EVT_MASK;
    ALOGI("%s: packet type (0x%x)", __func__,  event);
    switch (event & MSG_EVT_MASK) {
	case MSG_STACK_TO_HC_HCI_CMD:
	    btHci->sendHciCommand(data);
	    break;
	case MSG_STACK_TO_HC_HCI_ACL:
	    btHci->sendAclData(data);
	    break;
	case MSG_STACK_TO_HC_HCI_SCO:
	    btHci->sendScoData(data);
	    break;
	default:
	    ALOGE("%s: unknown packet type to transmit", __func__);
	    break;
    }
}

