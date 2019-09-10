void esp_struct_init(struct espconn *ec, u8 *remote_ip, int remote_port);
void test(u8 *remote_ip);
void conn_cb(void *arg);
void dc_cb(void *arg);
void reconn_cb(void *arg);
void rcv_cb(void *arg, char *pdata, unsigned short len);
void snd_cb(void *arg);
void write_fin_cb(void *arg);
