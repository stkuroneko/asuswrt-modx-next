/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "lib/uuid.h"
#include "btio/btio.h"
#include "gdbus/gdbus.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/timeout.h"
#include "src/log.h"
#include "src/error.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/gatt-database.h"
#include "src/dbus-common.h"
#include "gatt-amap.h"

#define LE_LINK         0x80

int ble_data_len = 0;
int ble_count_len = 0;
int ble_dev_id = 0;
unsigned char ble_data[MAX_PACKET_SIZE];

extern int hci_open_dev(int dev_id);
extern int hci_close_dev(int dd);
extern int hci_disconnect(int dd, uint16_t handle, uint8_t reason, int to);

/*
static void print_uuid(const bt_uuid_t *uuid)
{
	char uuid_str[MAX_LEN_UUID_STR];
	bt_uuid_t uuid128;

	bt_uuid_to_uuid128(uuid, &uuid128);
	bt_uuid_to_string(&uuid128, uuid_str, sizeof(uuid_str));

	printf("%s\n", uuid_str);
}

struct cmd {
	unsigned int id;
	uint16_t opcode;
	void *data;
	uint8_t size;
};

unsigned int bt_adapter_send(struct btd_adapter *adapter, uint16_t opcode, const void *data, uint8_t size)
{
	struct cmd *cmd;

	if (!adapter)
		return 0;

	cmd = new0(struct cmd, 1);
	cmd->opcode = opcode;
	cmd->size = size;
	cmd->id = 2;

	if (cmd->size > 0) {
		cmd->data = malloc(cmd->size);
		if (!cmd->data) {
			free(cmd);
			return 0;
		}

		memcpy(cmd->data, data, cmd->size);
	}

	if (!queue_push_tail(adapter->dev_id, cmd)) {	// Can't push cmd. Wait to finish.
		free(cmd->data);
		free(cmd);
		return 0;
	}
}

static void init_adv_data(struct btd_adapter *adapter) {
	struct bt_hci_cmd_le_set_adv_data cmd;
        uint8_t enable = 0x01;
	uint8_t  iBdata[31] = {
		0x02, 0x01, 		// [Field length] [Flags]
		0x06,			// [BR/EDR Not Supported]
		0x1a, 0xff, 0xd7, 0x00,	// [Field length] [Vendor field] [Company LSB] [Company MSB] e.g. QCA
		0x02, 0x15		// [Beacon Type] [Length]
		// UUID
		0x00, 0x00, 0xAB, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x08, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB, 
		0x00, 0x00, 0x00, 0x00,	// [Major-LSB] [Major-MSB] [Minor-LSB] [Minor-MSB]
		0x00, 0x00		// [RSSI] [Field terminator]
	};
	uint8_t  altBdata[31] = {
		0x02, 0x01, 		// [Field length] [Flags]
		0x1a,			// [LE General Discoverable]
		0x1b, 0xff, 0xd7, 0x00,	// [Field length] [Vendor field] [Company LSB] [Company MSB] e.g. QCA
		0xBC, 0xAC,		// [AltBeacon advertisement Proximity_Type]
		// UUID
		0x00, 0x00, 0xAB, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x08, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB, 
		0x00, 0x00, 0x00, 0x00,	// [Beacon Group 2bits] [Beacon Unit 2bits]
		0x00, 0x00		// [RSSI] [Reserved]
	};

	memcpy(cmd.data , altBdata, sizeof(altBdata));

	cmd.len = 1 + cmd.data[0] + 1 + cmd.data[3];

	bt_adapter_send(adapter, BT_HCI_CMD_LE_SET_ADV_DATA, &cmd, sizeof(cmd));
	bt_adapter_send(adapter, BT_HCI_CMD_LE_SET_ADV_ENABLE, &enable, 1);
}

static char *type2str(uint8_t type)
{
	switch (type) {
	case SCO_LINK:
		return "SCO";
	case ACL_LINK:
		return "ACL";
	case ESCO_LINK:
		return "eSCO";
	case LE_LINK:
		return "LE";
	default:
		return "Unknown";
	}
}
*/

static void remove_current_conn()
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	uint8_t reason = HCI_OE_USER_ENDED_CONNECTION;
	int hci_dev_id=0, i;

	DBG_INFO("");
	if (!(cl = malloc(10 * sizeof(*ci) + sizeof(*cl)))) {
		DBG_INFO("Can't allocate memory");
		goto exit;
	}
	
	DBG_INFO("%s, adapter->dev id :%ld", __func__, ble_dev_id);
	cl->dev_id = ble_dev_id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	hci_dev_id = hci_open_dev(ble_dev_id);
	if (ioctl(hci_dev_id, HCIGETCONNLIST, (void *) cl)) {
		DBG_INFO("Can't get connection list");
		goto exit;
	}
 
	for (i=0; i < cl->conn_num; i++, ci++) {
		char addr[18];
		ba2str(&ci->bdaddr, addr);
		DBG_INFO("\t%s %s handle %d, Disconnection.\n", 
			ci->out ? "<" : ">", addr, ci->handle);

		if (hci_disconnect(hci_dev_id, htobs(ci->handle), reason, 10000) < 0)
			DBG_INFO("Disconnect failed");
	}

exit:
	free(cl);
	hci_close_dev(ble_dev_id);

	ble_data_len = 0;
	ble_count_len = 0;
	return;
}

static bool amap_nvram_cb(void *user_data)
{
	struct btd_gatt_database *database = user_data;
	struct btd_device *device;
	struct bt_gatt_server *server;
	bdaddr_t bdaddr;
	uint8_t bdaddr_type, *value = NULL;
	size_t len = 0, index;

	if (!get_dst_info(database->amap_att, &bdaddr, &bdaddr_type))
		return false;

	device = btd_adapter_get_device(database->adapter, &bdaddr, bdaddr_type);
	if (!device)
		return false;

	server = btd_device_get_gatt_server(device);

#ifdef RTCONFIG_WIRELESSREPEATER
	if (fileData_s.aplist_len > 0) {
		len = fileData_s.aplist_len;
		value = fileData_s.aplist;
	}
	else 
#endif
	{
		len = database->amap_value_len;
		if (len <= 0) return false;

		value = database->amap_value;
	}
	print_data_topic("TX", (int)len);

	for (index=0; index<=len; index+=MAX_LE_DATALEN) {

		if (index>0) value += MAX_LE_DATALEN;
		print_data_info(value, (index+MAX_LE_DATALEN)>len ? (len-index):MAX_LE_DATALEN, MAX_LE_DATALEN, index, 0);

		bt_gatt_server_send_notification(
			server,
			database->amap_nvram_handle, value,
			(index+MAX_LE_DATALEN)>len ? (len-index):MAX_LE_DATALEN);
		usleep(50* MILLISEC);
	}
	
#ifdef RTCONFIG_WIRELESSREPEATER
	if (!IsNULL_PTR(fileData_s.aplist)) {
		MFREE(fileData_s.aplist);
		fileData_s.aplist_len = 0;
	}
#endif

	if (nvram_get_int("bt_turn_off")==1)
		nvram_set_int("bt_turn_off", 2);
	return true;
}

static void amap_write_value(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct btd_gatt_database *database = user_data;
	uint8_t error = 0;

	if ( !value || !len || len > MAX_LE_DATALEN) {
		error = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (!ble_data_len) {
#if defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
		DBG_INFO("value: %02x %02x %02x %02x", value[0], value[1], value[2], value[3]);
		if (value[1] != 0) {
			error = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
			goto done;
		}
#endif

		ble_data_len = (int)value[2]*256 + (int)value[3];
		if (ble_data_len > MAX_PACKET_SIZE) {
#if defined(RTCONFIG_QCA)
			remove_current_conn();
#endif
			error = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
			goto done;
		}

		memset(ble_data, '\0', MAX_PACKET_SIZE);
		print_data_topic("RX", ble_data_len);
	}

#if defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
	if (ble_count_len + len > MAX_PACKET_SIZE) {
		error = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}
#endif

	memcpy(ble_data+ble_count_len, value, len);
	print_data_info((uint8_t *)value, len, MAX_LE_DATALEN, ble_count_len, 0);
	ble_count_len += (int)len;

	if (ble_count_len < ble_data_len) {
#if defined(RTCONFIG_QCA)
		alarm(5);
#endif
		goto done2;
	}
	else if (ble_count_len > ble_data_len) {
		error = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (ble_data_len) {
		unsigned char uchar_out[MAX_PACKET_SIZE];
		int len_out;

#if defined(RTCONFIG_QCA)
		alarm(0);
#endif
		memset(uchar_out, '\0', MAX_PACKET_SIZE);

		len_out = ble_encrypt_svr(ble_data, uchar_out, ble_data_len);
		if ( len_out < MAX_PACKET_SIZE )
			uchar_out[len_out] = '\0';

		if(len_out < 1) {
			error = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
			goto done;
		}

		memset(database->amap_value, '\0', MAX_PACKET_SIZE);
		memcpy(database->amap_value, uchar_out, len_out);
		database->amap_value_len = len_out;
		database->amap_att = att;
	}

	amap_nvram_cb(database);
done:
	ble_data_len = 0;
	ble_count_len = 0;
done2:
	gatt_db_attribute_write_result(attrib, id, error);
}

void amap_gatt_service(struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct gatt_db_attribute *service;
	bt_uuid_t uuid;

	/* Service */
	ble_dev_id = btd_adapter_get_index(adapter);
	bt_uuid16_create(&uuid, UUID_AMAP);
	service = gatt_db_add_service(database->db, &uuid, true, MAX_AMAP_SERVICE);
	database->amap_handle = database_add_record(database, UUID_AMAP,
						service,
						"AMAP Definition Profile");
	/* Product Value */
	bt_uuid16_create(&uuid, GATT_CHARAC_AMAP_PRODUCT);
	database->svc_chngd = gatt_db_service_add_characteristic(service, &uuid,
						BT_ATT_PERM_WRITE,
						BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_NOTIFY,
						NULL,
						amap_write_value,
						database);
	database->amap_nvram_handle = gatt_db_attribute_get_handle(database->svc_chngd);
	database->svc_chngd_ccc = service_add_ccc(service, database, NULL, NULL, NULL);

	ble_key_act("Server", "Init");
	ble_dbg = nvram_match("ble_dbg", "1")?1:0;
	nvram_set_int("bt_turn_off", 0);
	gatt_db_service_set_active(service, true);
#if defined(RTCONFIG_QCA)
	signal(SIGALRM, remove_current_conn);
#endif
	DBG_INFO("QIS Gatt Service !!");
}
/*AMAP END*/
