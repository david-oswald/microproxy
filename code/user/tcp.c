#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "c_types.h"
#include "espnow.h"
#include "espconn.h"
#include "user_interface.h"
//#include <user_config.h>
#include "mem.h"
#include "ip_addr.h"

typedef struct ip_addr ip_addr_t;
//dummy event structs
#define user_procTaskPrio        0
#define user_procTaskQueueLen    1
os_event_t user_procTaskQueue[user_procTaskQueueLen];
static volatile os_timer_t scan_timer, chk_timer, brute_timer;
//Do nothing function
static void ICACHE_FLASH_ATTR user_procTask(os_event_t *events)
{
	os_delay_us(10);
}

struct espconn *ec;

void esp_struct_init_soc(struct espconn *ec, u8 *remote_ip, int remote_port);
void test_soc(u8 *remote_ip);

void esp_struct_init_lis(struct espconn *ec);
void test_lis();

void conn_cb(void *arg);
void dc_cb(void *arg);
void reconn_cb(void *arg, sint8 err);
void rcv_cb(void *arg, char *pdata, unsigned short len);
void snd_cb(void *arg);
void write_fin_cb(void *arg);
char *tcp_buff;

//Init function

/*enum espconn_state {
 * ESPCONN_NONE,
 * ESPCONN_WAIT,
 * ESPCONN_LISTEN,
 * ESPCONN_CONNECT,
 * ESPCONN_WRITE,
 * ESPCONN_READ,
 * ESPCONN_CLOSE
 * };*/
void test_soc(u8 *remote_ip)
{
	struct espconn *ec = (struct espconn *)os_malloc(sizeof(struct espconn));
	int e;

	esp_struct_init_soc(ec, remote_ip, 8080);

	os_printf("Setting conn cb...");
	e = espconn_regist_connectcb(ec, &conn_cb);
	if (e) {
		os_printf("Failed! errno: %d", e);
		return;
	}
	os_printf("OK\n");

	os_printf("Setting reconn cb...");
	e = espconn_regist_reconcb(ec, &reconn_cb);
	if (e) {
		os_printf("Failed! errno: %d", e);
		return;
	}
	os_printf("OK\n");

	os_printf("Connecting...");
	e = espconn_connect(ec);
	if (e) {
		os_printf("Failed! errno: %d", e);
		return;
	}
	os_printf("OK\n");
}
int add_tcp_msg(char *m)
{
	char *new_buff;
	int e;
	int mlen = os_strlen(m);
	int newlen;

	if (tcp_buff) {
		int oldlen = os_strlen(tcp_buff);
		new_buff = (char *)os_malloc(mlen + oldlen + 1);
		if (!new_buff) {
			os_printf("tcp realloc fail\n");
			return -1;
		}
		os_memcpy(new_buff, tcp_buff, oldlen);
		os_memcpy(&new_buff[oldlen], m, mlen + 1);
		os_free(tcp_buff);
		tcp_buff = new_buff;
		newlen = mlen + oldlen + 1;
	} else {
		tcp_buff = (char *)os_malloc(mlen + 1);
		if (!tcp_buff) {
			os_printf("tcp buff malloc fail\n");
			return -1;
		}
		os_memcpy(tcp_buff, m, mlen + 1);
		newlen = mlen + 1;
	}

	os_printf("Attempting direct send...");
	e = espconn_sent(ec, tcp_buff, newlen);
	if (e)
		os_printf("Failed errno, data kept: %d", e);
	else
		tcp_buff = NULL;
	return 0;
}
void test_lis()
{
	ec = (struct espconn *)os_malloc(sizeof(struct espconn));
	if (!ec) {
		os_printf("MALLOC fail of espconn struct!\n");
		return;
	}
	int e;
	esp_struct_init_lis(ec);

	os_printf("Setting conn cb...");
	e = espconn_regist_connectcb(ec, &conn_cb);
	if (e) {
		os_printf("Failed! errno: %d", e);
		return;
	}
	os_printf("OK\n");

	os_printf("Setting reconn cb...");
	e = espconn_regist_reconcb(ec, &reconn_cb);
	if (e) {
		os_printf("Failed! errno: %d", e);
		return;
	}
	os_printf("OK\n");

	os_printf("Accepting...");
	e = espconn_accept(ec);
	if (e) {
		os_printf("Failed! errno: %d", e);
		return;
	}
	os_printf("OK\n");
}

void conn_cb(void *arg)
{
	os_printf("Connected!\n");
	struct espconn *ec = (struct espconn *)arg;
	int e;

	os_printf("Setting keep alive...");
	e = espconn_set_opt(ec, ESPCONN_KEEPALIVE);
	if (e) {
		os_printf("Failed! errno: %d", e);
		return;
	}

	os_printf("Setting rcv cb...");
	e = espconn_regist_recvcb(ec, &rcv_cb);
	if (e) {
		os_printf("Failed! errno: %d", e);
		return;
	}
	os_printf("OK\n");

	os_printf("Setting sent cb...");
	e = espconn_regist_sentcb(ec, &snd_cb);
	if (e) {
		os_printf("Failed! errno: %d", e);
		return;
	}
	os_printf("OK\n");

	os_printf("Getting dc cb...");
	e = espconn_regist_disconcb(ec, &dc_cb);
	if (e) {
		os_printf("Failed! errno: %d", e);
		return;
	}
	os_printf("OK\n");


	char *m;
	if (tcp_buff)
		m = tcp_buff;
	else
		m = "Hi Mr pc....\nSadly I have no data for you right now.\n ";

	os_printf("Current ec state: %d", ec->state);
	os_printf("Attempting to send: %s\n", m);
	e = espconn_sent(ec, m, os_strlen(m) + 1);
	//TODO threadsafe this.
	//tcp_buff = null;
	if (e) {
		os_printf("Failed! errno: %d", e);
		return;
	}
	os_printf("OK\n");
}
void dc_cb(void *arg)
{
	os_printf("Connection id RIP\n");
}

void reconn_cb(void *arg, sint8 err)
{
	os_printf("entered reconn cb... errno %d: \n", err);
	//send_data()
}
void rcv_cb(void *arg, char *pdata, unsigned short len)
{
	os_printf("Recived incoming non-relay data of length %d.\nData: %s\n", len, pdata);
	relay_rcv_hook(pdata);
	//send_data()
}
void snd_cb(void *arg)
{
	os_printf("Send data out of relay.");
	os_free(tcp_buff);
	tcp_buff = NULL;
}
void write_fin_cb(void *arg)
{
	os_printf("Data written to buffer.\n");
}
void esp_struct_init_soc(struct espconn *ec, u8 *remote_ip, int remote_port)
{
	struct _esp_tcp *tcp = (struct _esp_tcp *)os_malloc(sizeof(struct _esp_tcp));

	tcp->remote_port = remote_port;
	tcp->local_port = 8080;

	struct ip_info ip;
	os_printf("Getting local ip...");
	if (!wifi_get_ip_info(1, &ip)) {
		os_printf("Failed!\n");
		os_free(tcp);
	}
	os_printf("OK\n Local IP: "IPSTR "\n", IP2STR(&ip.ip));
	//tcp->local_ip = (u8*)ip.ip.addr;
	os_memcpy(&tcp->local_ip, ip.ip.addr, 4);
	//tcp->remote_ip = remote_ip;
	os_memcpy(&tcp->remote_ip, remote_ip, 4);


	// tcp->connect_callback = &conn_cb;
	// tcp->reconnect_callback = &reconn_cb;
	// tcp->disconnect_callback = &dc_cb;
	// tcp->write_finish_fn = &write_fin_cb;

	ec->proto.tcp = tcp;
	ec->type = ESPCONN_TCP;

	// ec->recv_callback = &rcv_cb;
	// ec->sent_callback = &snd_cb;


	//TODO check this
	ec->state = ESPCONN_NONE;
	ec->link_cnt = 0;
	ec->reverse = NULL;
}

void esp_struct_init_lis(struct espconn *ec)
{
	struct _esp_tcp *tcp = (struct _esp_tcp *)os_malloc(sizeof(struct _esp_tcp));

	if (!tcp) {
		os_printf("MALLOC FAIL, tcp struct\n");
		return;
	}

	//tcp->remote_port = remote_port;
	tcp->local_port = 8080;

	struct ip_info ip;
	os_printf("Getting local ip...");
	if (!wifi_get_ip_info(1, &ip)) {
		os_printf("Failed!\n");
		os_free(tcp);
	}
	os_printf("OK\n Local IP: "IPSTR "\n", IP2STR(&ip.ip));
	//tcp->local_ip = (u8*)ip.ip.addr;
	os_memcpy(&tcp->local_ip, &ip.ip.addr, 4);
	//tcp->remote_ip = remote_ip;
	//os_memcpy(&tcp->remote_ip, remote_ip, 4);


	// tcp->connect_callback = &conn_cb;
	// tcp->reconnect_callback = &reconn_cb;
	// tcp->disconnect_callback = &dc_cb;
	// tcp->write_finish_fn = &write_fin_cb;

	ec->proto.tcp = tcp;
	ec->type = ESPCONN_TCP;

	// ec->recv_callback = &rcv_cb;
	// ec->sent_callback = &snd_cb;


	//TODO check these
	ec->state = ESPCONN_NONE;
	ec->link_cnt = 0;
	ec->reverse = NULL;
}

//included to prevent undefined reffrence errors....
//from an SKD binary blob,
//void ICACHE_FLASH_ATTR user_rf_pre_init(void){}
