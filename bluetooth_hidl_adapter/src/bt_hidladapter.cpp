#define LOG_TAG "bt_hidladapter"

#include "bt_hidladapter.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <utils/Log.h>
#include <map>

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
using std::map;

// |<---HCI_ACL_PREAMBLE_SIZE--->|<----L2CAP_HEADER_SIZE------>|
// -----------------------------------------------------------------------
// |handle(2Bytes)|ACLlen(2Bytes)|L2CAPlen(2Bytes)|CID(2Bytes) |L2CAP data
// -----------------------------------------------------------------------
#define HCI_ACL_PREAMBLE_SIZE 4
#define L2CAP_HEADER_SIZE 4


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

#define STREAM_SKIP_UINT16(p) \
    do {                      \
	(p) += 2;             \
    }  while (0)              \

#define UINT16_TO_STREAM(p, u16)       \
{                                      \
    *(p)++ = (uint8_t)(u16);           \
    *(p)++ = (uint8_t)((u16) >> 8);    \
}                                      \

#define GET_BOUNDARY_FLAG(handle)  (((handle) >> 12) & 0x0003)
#define HANDLE_MASK 0x0FFF
#define START_PACKET_BOUNDARY 2
#define CONTINUATION_PACKET_BOUNDARY 1

android::sp<IBluetoothHci> btHci;
bt_hidl_cb_t* hidlCb;
map<uint16_t, char*> partial_packets;

/**Reassemble received ACL packet*/
void reassemble_and_dispatch(BT_HDR* packet) {

    uint8_t* stream = packet->data;
    uint16_t handle, acl_length, l2cap_length;

    STREAM_TO_UINT16(handle, stream);
    STREAM_TO_UINT16(acl_length, stream);
    STREAM_TO_UINT16(l2cap_length, stream);

    if (acl_length != packet->len - HCI_ACL_PREAMBLE_SIZE) {
	ALOGE("bad acl length, drop this packet");
	if(hidlCb->dealloc(packet, NULL) == -1){
	    ALOGE("%s(line %d): dealloc error", __func__, __LINE__);
	}
	return;
    }

    uint8_t boundary_flag = GET_BOUNDARY_FLAG(handle);
    handle = handle & HANDLE_MASK;

    if (boundary_flag == START_PACKET_BOUNDARY) {
	map<uint16_t, char*>::iterator itr = partial_packets.find(handle);
	if (itr != partial_packets.end()) {
	    ALOGW("found unfinished packet for handle with start packet, dropping old");
	    char* old_stream = itr->second;
	    if(hidlCb->dealloc(old_stream, NULL) == -1){
		ALOGE("%s(line %d): dealloc error", __func__, __LINE__);
	    }
	    partial_packets.erase(itr);
	}

        if (acl_length < L2CAP_HEADER_SIZE) {
	    ALOGW("L2CAP packet too small, dropping it");
	    if(hidlCb->dealloc(packet, NULL) == -1){
		ALOGE("%s(line %d): dealloc error", __func__, __LINE__);
	    }
	    return;
	}

	//Note that the l2cap_length refers to the reassembled l2cap packet length
	uint16_t full_length = l2cap_length + L2CAP_HEADER_SIZE + HCI_ACL_PREAMBLE_SIZE;
	ALOGW("full_length: %d, packet->len: %d", full_length, packet->len);

	//Do not need reassembling
	if (full_length <= packet->len) {
	    if (full_length < packet->len) {
		ALOGW("full length %d less than the hci length %d, but we still keep it",
			l2cap_length, packet->len);
	    }

	    //This packet is not followed with continuation packet, do not need reassembling.
	    //Send to upper layer
	    hidlCb->acl_data_received(packet);
	    return;
	}

	//Do need reassembling
	//We need to reallocate memory for both start packet and the coming continuation packet
	BT_HDR* partial_packet = (BT_HDR*)hidlCb->alloc(full_length + BT_HDR_SZ);
	if(partial_packet == NULL) {
	    ALOGE("%s: alloc error", __func__);
	    return;
	}
	partial_packet->event = packet->event;
	partial_packet->len = full_length;
	partial_packet->offset = packet->len;
        memcpy(partial_packet->data, packet->data, packet->len);

	//Update the ACL data size to indicate the full expected length
	stream = partial_packet->data;
	STREAM_SKIP_UINT16(stream); //Skip the handle
	UINT16_TO_STREAM(stream, full_length - HCI_ACL_PREAMBLE_SIZE);
	
	//Store in map until continuation packet comes
	partial_packets[handle] = (char*)partial_packet;

        //Free old packet buffer.
	if(hidlCb->dealloc(packet, NULL) == -1){
	    ALOGE("%s(line %d): dealloc error", __func__, __LINE__);
	}
    } else if (boundary_flag == CONTINUATION_PACKET_BOUNDARY){
	map<uint16_t, char*>::iterator itr =  partial_packets.find(handle);
        if (itr == partial_packets.end()) {
	    ALOGW("got continuation for unknown packet, Dropping it");
	    if(hidlCb->dealloc(packet, NULL) == -1){
		ALOGE("%s(line %d): dealloc error", __func__, __LINE__);
	    }
	    return;
	}

	//Start packet found
        BT_HDR* partial_packet = (BT_HDR*)itr->second;

	//Reassemble packet
	packet->offset = HCI_ACL_PREAMBLE_SIZE;
	uint16_t projected_offset = partial_packet->offset + (packet->len - HCI_ACL_PREAMBLE_SIZE);
	if (projected_offset > partial_packet->len) {
	    ALOGW("continuation packet exceed expection, Truncating it");
	    packet->len = partial_packet->len - partial_packet->offset;
	    projected_offset = partial_packet->len;
	}

	memcpy(partial_packet->data + partial_packet->offset,
		packet->data + packet->offset, packet->len - packet->offset);

	//Free the old packet buffer, since we don't need it anymore
	if(hidlCb->dealloc(packet, NULL) == -1){
	    ALOGE("%s(line %d): dealloc error", __func__, __LINE__);
	}
	partial_packet->offset = projected_offset;

	if (partial_packet->offset == partial_packet->len) {
	    partial_packets.erase(handle);
	    partial_packet->offset = 0;
	    hidlCb->acl_data_received(partial_packet);
	}

    } else {
	ALOGE("bad flag, drop this packet");
	if(hidlCb->dealloc(packet, NULL) == -1){
	    ALOGE("%s(line %d): dealloc error", __func__, __LINE__);
	}
    }
}


class BluetoothHciCallbacks : public IBluetoothHciCallbacks {
    public:
	BluetoothHciCallbacks() {
	}

	BT_HDR* WrapPacketAndCopy(uint16_t event, const hidl_vec<uint8_t>& data) {
	    int packet_size = data.size() + BT_HDR_SZ;
	    char* p_buff = hidlCb->alloc(packet_size);
	    if (p_buff == NULL) {
		ALOGE("%s: alloc memory failed", __func__);
		return nullptr;
	    }
	    BT_HDR* packet = reinterpret_cast<BT_HDR*>(p_buff);
            packet->offset = 0;
	    packet->len = data.size();
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

		//packets we received here has been fragmented, we need to reassemble it.
	        //hidlCb->acl_data_received(packet);
		reassemble_and_dispatch(packet);
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
	    btHci->sendAclData(data);//upper layer have got max acl length already, do not need fragment
	    break;
	case MSG_STACK_TO_HC_HCI_SCO:
	    btHci->sendScoData(data);
	    break;
	default:
	    ALOGE("%s: unknown packet type to transmit", __func__);
	    break;
    }

    if(hidlCb->dealloc((void*)packet, NULL) == -1){
	ALOGE("%s: dealloc error", __func__);
    }
}
