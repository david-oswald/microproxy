#include <ets_sys.h>
#include <osapi.h>
#include <gpio.h>
#include <os_type.h>
#include <c_types.h>
#include <user_interface.h>
#include <espnow.h>
#include <mem.h>
#include "user_config.h"
#include "tweetnacl.h"
#include "tcp.h"

// dummy event structs
#define user_procTaskPrio        0
#define user_procTaskQueueLen    1
os_event_t user_procTaskQueue[user_procTaskQueueLen];
static volatile os_timer_t reg_timer;
struct send_tuple {
	u8 *	addr;
	u8 *	data;
};

void (*recv_cb)(u8 *mac_addr, u8 *data, u8 len);
void (*register_relay)(void);
void send_data(struct send_tuple *st);
void wifi_handle_event_cb(System_Event_t *evt);
void decrypt(u8 *d, u8 *m, unsigned long long mlen);
void n_inc();
void print_nonce();

// Local secret key
static const unsigned char sk[] = { 0x94, 0xab, 0x22, 0xe8, 0x32, 0xad, 0x93, 0x58, 0xf3, 0x4d, 0x54, 0x6a, 0x58, 0x9c, 0xb9, 0x0d, 0x5d, 0x3f, 0xe0, 0xe0, 0x51, 0x6f, 0x6a, 0x4d, 0xd8, 0x28, 0xbf, 0x62, 0xb6, 0x0f, 0x9d, 0x16 };

// Remote public key
static const unsigned char pk[] = { 0x5c, 0xab, 0xa3, 0xb6, 0xc5, 0xd1, 0x21, 0x3b, 0x90, 0x36, 0x3c, 0x90, 0x31, 0x0d, 0x04, 0x1a, 0xda, 0xb4, 0x0a, 0xa2, 0x0b, 0xde, 0xa5, 0x67, 0x09, 0x7e, 0x5f, 0x84, 0x04, 0xbb, 0xb5, 0xf9 };

// Nonce - first 16 byte are static, final 8 byte are counter
static unsigned char n[] = { 0xc5, 0xd1, 0x21, 0x3b, 0x90, 0x36, 0x3c, 0x90, 0x31, 0x0d, 0x04, 0x1a, 0xda, 0xb4, 0x0a, 0xa2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

// Key for ESPnow functionality. Not security relevant
const u8 key_len = 16;
u8 KEY[16] = { 0x33, 0x44, 0x33, 0x44, 0x33, 0x44, 0x33, 0x44, 0x33, 0x44, 0x33, 0x44, 0x33, 0x44, 0x33, 0x44 };


unsigned char *test_data = "Hello????";

static u8 rep_mac[] = REP_MAC;
static u8 cep_mac[] = CEP_MAC;
static u8 my_mac[] = MY_MAC;
static u8 n_mac[] = N_MAC;

static u8 rep_mac2[] = REP_MAC2;
static u8 cep_mac2[] = CEP_MAC2;
static u8 my_mac2[] = MY_MAC2;
static u8 n_mac2[] = N_MAC2;

static u8 next[6];
static u8 prev[6];

static int rcv_count = 0;
static int snd_count = 0;
unsigned char *k;

void relay_rcv_hook(char *data)
{
	os_printf("Pushing data into relay\n");
	struct send_tuple *st = (struct send_tuple *)os_malloc(sizeof(struct send_tuple));
	st->data = data;
	switch (ROLE) {
	case REMOTE_ENDPOINT:
		st->addr = prev;
		break;
	case CLIENT_ENDPOINT:
		st->addr = next;
		break;
	default:
		os_printf("ERROR\n Middle node rcved data on tcp lis, dropping data\n");
		return;
	}
	send_data(st);
	os_free(st);
	os_printf("Data pushed\n");
}

void n_inc()
{
	u64 nn;

	os_memcpy(&nn, &n[15], 8);
	os_printf("internal nonce counter val: %llu\n", nn);
	nn += 1;
	os_printf("internal nonce counter val: %llu\n", (long unsigned int)nn);
	os_memcpy(&n[15], &nn, 8);
}

void print_nonce()
{
	int count = 24;
	size_t i;

	for (i = 0; i < count; i++)
		os_printf("%x", n[i]);
	os_printf("\n");
	os_printf("Nonce counter val: %llu\n", (long unsigned int)n[15]);
}

void encrypt(u8 *c, u8 *pt, unsigned long long mlen)
{
	uint32 t = system_get_time();
	unsigned char m[crypto_box_ZEROBYTES + mlen];

	os_memset(m, 0, crypto_box_ZEROBYTES + mlen);
	os_memcpy((void *)&m[crypto_box_ZEROBYTES], pt, mlen);
	crypto_box_afternm(c, m, mlen + crypto_box_ZEROBYTES, n, k);
	t = system_get_time() - t;
	os_printf("Encrypted in %d microseconds\n", t);

	if (CRYPTO_DEBUG_MODE) {
		os_printf("DEBUGGING DEC BEGINING\n");

		os_memset(c, 0, crypto_box_BOXZEROBYTES);
		u8 m2[mlen + crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES];
		// os_printf("C has length %d", mlen+crypto_box_ZEROBYTES+crypto_box_BOXZEROBYTES);
		os_memset(m2, 0, mlen + crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES);
		os_printf("M2 has length %llu\n", mlen + crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES);
		os_printf("Printing M2 data, len %llu\n", mlen + crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES);
		int i;
		for (i = 0; i < mlen + crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES; i++)
			os_printf("%x:", m2[i]);
		os_printf("\n");
		decrypt(m2, c, mlen);

	}
}

void decrypt(u8 *m, u8 *c, unsigned long long mlen)
{
	int i;

	uint32 t = system_get_time();

	i = crypto_box_open_afternm(m, c, mlen + crypto_box_ZEROBYTES, n, k);
	t = system_get_time() - t;

	if (i) {
		os_printf("Crypto failed with: %d\n", i);
		return;
	}

	os_printf("Decrypted in %d microseconds\n", t);
}

void node_recv_cb(u8 *mac_addr, u8 *data, u8 len)
{
	os_printf("Got data, forwarding...\n From: "MACSTR ", Length: %d\n", MAC2STR(mac_addr), len);

	// simple daisy chain addr
	u8 *da;
	if (*mac_addr == *cep_mac)
		da = rep_mac;
	else
		da = cep_mac;
	
	// send
	if (esp_now_send(da, data, len)) {
		os_printf("Failed to send to: %d\n", da);
		return;
	}
	os_printf("OK\n");
}

void process_message(u8 *mac_addr, u8 *data, u8 mlen)
{
	os_printf("Recived data!\n");
	print_nonce();

	u8 c[mlen];

	u8 *output;
	os_memcpy(c, data, mlen);
	rcv_count++;
	int i;
	unsigned long long clen = mlen;

	if (!data) {
		os_printf("Recived null data! But given length: %d\n", clen);
		return;
	}

	if (USE_CRYPTO) 
	{
		// we expect at least 8 byte nonce + 1 byte data
		if(mlen < 9) {
			os_printf("Received data length %d < 8 + 1\n", clen);
			return;
		}
		
		// extract nonce counter here!
		os_memcpy(&n[15], c, 8);
		print_nonce();
		os_printf("clen %d", clen);
		clen -= 8;
		os_printf("clen %d", clen);
		u8 newc[clen];
		os_memcpy(newc, &c[8], clen);
		
		/// TODO: Should check for nonce > current_nonce to avoid replay

		u8 m[clen + crypto_box_ZEROBYTES];

		os_memset(m, 0, clen + crypto_box_ZEROBYTES);
		decrypt(m, newc, clen - crypto_box_ZEROBYTES);

		output = &m[crypto_box_ZEROBYTES];
		os_printf("Data reached end of chain,\n From: "MACSTR "\nCount: %d\nData: %s\nLength: %llu\n",
			  MAC2STR(mac_addr), rcv_count, output, clen);

		if (add_tcp_msg(output))
			os_printf("failed to add msg to lis");

	} else {
		os_printf("Data reached end of chain,\n From: "MACSTR "\nCount: %d\nData: %s\nLength: %llu\n",
			  MAC2STR(mac_addr), rcv_count, data, clen);
		if (add_tcp_msg(data))
			os_printf("failed to add msg to lis");
	}
}

void remote_recv_cb(u8 *mac_addr, u8 *data, u8 mlen)
{
	process_message(mac_addr, data, mlen);

	if (DEBUG_RESPONSE) {
		struct send_tuple *st = (struct send_tuple *)os_malloc(sizeof(struct send_tuple));
		st->data = "Yes I can hear you, :)";
		st->addr = mac_addr;
		send_data(st);
		os_free(st);
	}
}

void client_recv_cb(u8 *mac_addr, u8 *data, u8 mlen)
{
	process_message(mac_addr, data, mlen);
}

void send_data(struct send_tuple *st)
{
	u8 *mac_addr = st->addr;
	u8 *data = st->data;
	int e, m;

	os_printf("Sending data!\n");

	e = wifi_station_get_connect_status();
	m = wifi_get_opmode();

	if (STRICT_STA_MODE && (m == STA_MODE) && (e != STATION_GOT_IP) && (e != STATION_IDLE)) {
		os_printf("send aborted, STA not reday errorno: %d\n", e);
		return;
	}

	if (!data) {
		os_printf("Send aborted, data is NULL\n");
		return;
	}

	e = esp_now_is_peer_exist(mac_addr);

	if (e <= 0) {
		os_printf("Next node unknown, errorno %d, MAC: "MACSTR "\n", e, MAC2STR(mac_addr));
		return;
	}

	if (USE_CRYPTO) {
		unsigned long long mlen = os_strlen(data) + 1;
		unsigned long long clen = crypto_box_ZEROBYTES + mlen;
		unsigned char c[clen];
		os_memset(c, 0, clen);

		n_inc();
		print_nonce();
		encrypt(c, data, mlen);
		// append nonce here +inc before
		// create expanded payload counter+chipertext (nc)

		unsigned long long nclen = clen + 8;
		unsigned char nc[nclen];
		// copy counter into nc
		memcpy(nc, &n[15], 8);
		//copy ciphertext into nc
		memcpy(&nc[8], c, clen);

		if (esp_now_send(mac_addr, nc, nclen)) {
			os_printf("Failed to send chipertext: \"%s\"\n plaintext: \"%s\"\n to: "MACSTR "\n\n", &c[crypto_box_BOXZEROBYTES], data, MAC2STR(mac_addr), snd_count);
		} else {
			snd_count++;
			os_printf("Sent chipertext: \"%x\"\n plaintext: \"%s\"\n to: "MACSTR "\nCount: %d\n\n",
				  &c[crypto_box_BOXZEROBYTES], data, MAC2STR(mac_addr), snd_count);
		}
	} else {
		if (esp_now_send(mac_addr, data, os_strlen(data) + 1)) {
			os_printf("Failed to send \"%s\" to: "MACSTR "\nCount: %d\n\n", data, MAC2STR(mac_addr), snd_count);
		} else {
			snd_count++;
			os_printf("Sent: \"%s\"\n to: "MACSTR "\nCount: %d\n\n", data, MAC2STR(mac_addr), snd_count);
		}
	}
}

void setup_staion(u8 *mac, char *ssid)
{
	os_printf("Setting up to connect to: "MACSTR "\n", MAC2STR(mac));
	struct station_config sta_config;
	struct station_config *c = &sta_config;
	bool n;
	n = wifi_station_disconnect();

	if (!n)
		os_printf("Failed to disconnect\n");

	// configure module to current AP
	n = wifi_station_get_config(c);

	if (!n) {
		os_printf("Failed to get config\n");
		return;
	}
	os_memset(&c->ssid, 0, 32);
	os_memset(&c->password, 0, 64);
	os_memcpy(&(c->ssid), ssid, os_strlen(ssid) + 1);
	os_memcpy(&(c->password), PWD, os_strlen(PWD) + 1);
	c->bssid_set = 0;

	if (STRICT_STA_MODE) {
		c->bssid_set = 1;
		os_memcpy(c->bssid, mac, 6);
		os_printf("Enforcing mac of host to:  "MACSTR "\n", MAC2STR(c->bssid));
	}

	n = wifi_station_set_config(c);
	if (!n) {
		os_printf("Failed to set config\n");
		return;
	}

	n = wifi_station_connect();
	if (!n) {
		os_printf("Failed to connect\n");
		return;
	}
	os_printf("STA setup OK\n");
}

void setup_ap(char *ssid)
{
	struct softap_config config;
	struct softap_config *cp = &config;
	int n;

	os_printf("configuring accses point...");

	n = wifi_station_disconnect();
	// will always fail in ap mode,
	// beacuse nothing to be connected too,
	// so printout not required
	if ((wifi_get_opmode() != SAP_MODE) && !n)
		os_printf("Failed to disconnect\n");

	n = wifi_softap_get_config(cp);
	if (!n) {
		os_printf("Failed to get config\n");
		return;
	}
	os_memset(&cp->ssid, 0, 32);
	os_memset(&cp->password, 0, 64);
	os_memcpy(&cp->ssid, ssid, os_strlen(ssid) + 1);
	os_memcpy(&cp->password, PWD, os_strlen(PWD) + 1);
	cp->ssid_len = os_strlen(ssid);

	if (AP_SETUP_DEBUG) {
		int i = os_strlen(ssid);
		int j = os_strlen(&cp->ssid);
		if (1)
			os_printf("ssid copy check, lengths: %d %d %d\nssid: %s\nCOPIED ssid:%s\n",
				  i, j, cp->ssid_len, ssid, &cp->ssid);
	}

	cp->authmode = USE_AUTH_MODE;
	cp->ssid_hidden = 1;
	cp->max_connection = 4;
	cp->channel = CHANNEL;

	n = wifi_softap_set_config(cp);
	if (!n) {
		os_printf("Failed to set config\n");
		return;
	}
	os_printf("OK\n");
}

void register_client_ep()
{
	os_printf("%s\n", "Running local end point setup...");
	setup_ap(CEP_SSID);
	setup_staion(n_mac, NODE_SSID);

	int n = esp_now_add_peer(n_mac, NODE_ROLE, CHANNEL, KEY, key_len);
	if (n) {
		os_printf("Failed to add mac: "MACSTR ", errorno: %d\n", MAC2STR(n_mac), n);
		return;
	}
	os_timer_disarm(&reg_timer);
	os_printf("%s\n", "Done.");

	os_printf("Starting espconn\n");
	test_lis();
	os_printf("espconn running\n");
}
void register_remote_ep()
{
	os_printf("%s\n", "Running remote end point setup...");

	// will always fail in SAP mode as ap cannot connect to ap, so dc pointless
	if ((wifi_get_opmode() != SAP_MODE) && !wifi_station_disconnect())
		os_printf("Failed to disconnect from ap\n");
	setup_ap(REP_SSID);
	setup_staion(n_mac, NODE_SSID);


	int n = esp_now_add_peer(n_mac, NODE_ROLE, CHANNEL, KEY, key_len);
	if (n) {
		os_printf("Failed to add "MACSTR ", errorno: %d\n", MAC2STR(cep_mac), n);
		return;
	}
	os_timer_disarm(&reg_timer);
	os_printf("%s\n", "Done.");
	os_printf("Starting escponn\n");

	test_lis();
	os_printf("espconn running\n");

}
void register_node()
{
	os_printf("%s\n", "attempting to reg as node...");

	// will always fail in SAP mode as ap cannot connect to ap, so dc pointless
	if ((wifi_get_opmode() != SAP_MODE) && !wifi_station_disconnect())
		os_printf("Failed to disconnect from ap\n");

	setup_ap(NODE_SSID);

	int n;
	// add cep_mac
	n = esp_now_add_peer(cep_mac, CEP_ROLE, CHANNEL, KEY, key_len);
	if (n) {
		os_printf("Failed to  add "MACSTR ", errorno: %d\n", MAC2STR(cep_mac), n);
		return;
	}

	n = esp_now_add_peer(rep_mac, REP_ROLE, CHANNEL, KEY, key_len);
	if (n) {
		os_printf("Failed to add "MACSTR ", errorno: %d\n", MAC2STR(rep_mac), n);
		return;
	}
	os_printf("%s\n", "Done.");

	os_timer_disarm(&reg_timer);
}

//Init function
void ICACHE_FLASH_ATTR
user_init()
{
	int n;

	// Initialize UART0
	uart_div_modify(0, UART_CLK_FREQ / 115200);
	wifi_station_set_auto_connect(0);
	wifi_station_set_reconnect_policy(0);

	wifi_set_channel(CHANNEL);

	// Init Espnow
	if (esp_now_init()) {
		os_printf("%s\n", "ESPNOW INIT FAIL");
		return;
	}

	wifi_set_event_handler_cb(&wifi_handle_event_cb);

	// crypto init
	// This will never be freed, known mem leak,
	k = (unsigned char *)os_malloc(crypto_box_BEFORENMBYTES);
	crypto_box_beforenm(k, pk, sk);

	switch (ROLE) {
	case CLIENT_ENDPOINT:
		recv_cb = &client_recv_cb;
		register_relay = &register_client_ep;
		esp_now_set_self_role(CEP_ROLE);
		wifi_set_opmode(ST_AP_MODE);
		
		// reverse of REP
		wifi_set_macaddr(0, my_mac);
		wifi_set_macaddr(1, my_mac2);
		wifi_station_set_reconnect_policy(1);

		// configure macs, no prev for cep;
		os_memcpy(next, n_mac, 6);

		break;

	case REMOTE_ENDPOINT:
		recv_cb = &remote_recv_cb;
		register_relay = &register_remote_ep;
		esp_now_set_self_role(REP_ROLE);
		wifi_set_opmode(ST_AP_MODE);
		wifi_set_macaddr(0, my_mac);
		wifi_set_macaddr(1, my_mac2);

		wifi_softap_dhcps_start();

		os_memcpy(prev, n_mac, 6);
		break;

	default:
		recv_cb = &node_recv_cb;
		register_relay = &register_node;
		esp_now_set_self_role(NODE_ROLE);
		wifi_set_opmode(SAP_MODE);
		wifi_set_macaddr(1, my_mac);
		wifi_set_macaddr(0, my_mac2);

		wifi_softap_dhcps_start();

		os_memcpy(prev, cep_mac, 6);
		os_memcpy(next, rep_mac, 6);

		break;
	}

	// register self on mesh
	os_printf("I have role of: %d\n", esp_now_get_self_role());
	n = esp_now_add_peer(my_mac, esp_now_get_self_role(), CHANNEL, KEY, key_len);
	if (n) {
		os_printf("Failed to add self: "MACSTR ", errorno: %d\n", MAC2STR(my_mac), n);
		return;
	}

	// reg main data callaback
	esp_now_register_recv_cb(recv_cb);
	
	// start the reg timier
	os_timer_disarm(&reg_timer);
	os_timer_setfn(&reg_timer, (os_timer_func_t *)register_relay, NULL);
	os_timer_arm(&reg_timer, 5000, 1);

	os_printf("%s\n", "Initilisation done.");
}

void wifi_handle_event_cb(System_Event_t *evt)
{
	os_printf("event %x\n", evt->event);
	switch (evt->event) {
	case EVENT_STAMODE_CONNECTED:
		os_printf("connect to ssid %s\n",
			  evt->event_info.connected.ssid);
		break;
	case EVENT_STAMODE_DISCONNECTED:
		os_printf("disconnect from ssid %s, reason %d\n",
			  evt->event_info.disconnected.ssid,
			  evt->event_info.disconnected.reason);
		break;
	case EVENT_STAMODE_AUTHMODE_CHANGE:
		os_printf("mode: %d -> %d\n",
			  evt->event_info.auth_change.old_mode,
			  evt->event_info.auth_change.new_mode);
		break;
	case EVENT_STAMODE_GOT_IP:
		os_printf("ip:" IPSTR ",mask:" IPSTR ",gw:" IPSTR,
			  IP2STR(&evt->event_info.got_ip.ip),
			  IP2STR(&evt->event_info.got_ip.mask),
			  IP2STR(&evt->event_info.got_ip.gw));
		os_printf("\n");
		break;
	case EVENT_SOFTAPMODE_STACONNECTED:
		os_printf("station: " MACSTR "join, AID = %d\n",
			  MAC2STR(evt->event_info.sta_connected.mac),
			  evt->event_info.sta_connected.aid);
		break;
	case EVENT_SOFTAPMODE_STADISCONNECTED:
		os_printf("station: " MACSTR "leave, AID = %d\n",
			  MAC2STR(evt->event_info.sta_disconnected.mac),
			  evt->event_info.sta_disconnected.aid);
		break;
	default:
		break;
	}
}

// included to prevent undefined reference errors
void ICACHE_FLASH_ATTR user_rf_pre_init(void)
{
}
