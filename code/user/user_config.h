#define CEP_MAC { 0x1a, 0xfe, 0x34, 0xa6, 0xc1, 0x23 }
#define N_MAC { 0x8e, 0x78, 0x9b, 0x5e, 0x17, 0x90 }
#define REP_MAC { 0x5c, 0xcf, 0x7f, 0x02, 0x33, 0x76 }

#define CEP_MAC2 { 0x1a, 0xfe, 0x34, 0xa6, 0xc1, 0x07 }
#define N_MAC2 { 0x8e, 0x78, 0x9b, 0x5e, 0x17, 0x07 }
#define REP_MAC2 { 0x5c, 0xcf, 0x7f, 0x02, 0x33, 0x07 }

#define NODE  0
#define CLIENT_ENDPOINT 1
#define REMOTE_ENDPOINT 2

#define AP_MACS { CEP_MAC, REP_MAC, N_MAC }
#define STA_MACS { CEP_MAC2, REP_MAC2, N_MAC2 }

#define MY_MAC CEP_MAC
#define MY_MAC2 CEP_MAC2
#define ROLE CLIENT_ENDPOINT


#define STA_MODE 1
#define SAP_MODE 2
#define ST_AP_MODE 3

#define CHANNEL 6

#define USE_CRYPTO 1
#define CRYPTO_DEBUG_MODE 0
#define DEBUG_RESPONSE 0
#define DBF_ENC 1
#define USE_AUTH_MODE 4
//#define ENFORCE_AP_MAC 1
#define STRICT_STA_MODE 0
#define AP_SETUP_DEBUG 0

#define REP_ROLE 1
#define NODE_ROLE 2
#define CEP_ROLE 1

#define NODE_ROLE2 1

#define REP_SSID "remoteendpoint"
#define CEP_SSID "clientendpoint"
#define NODE_SSID "nodepoint"

#define PWD "F0rtyTw0andab0t"

//remote as ap
