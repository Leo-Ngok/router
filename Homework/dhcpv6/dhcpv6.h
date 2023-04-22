#include <stdint.h>

struct dhcpv6_hdr {
  // 1-byte message type
  uint8_t msg_type;
  // 3-byte transaction id
  uint8_t transaction_id_hi;
  uint16_t transaction_id_lo;
  // options follow
};

struct dhcpv6_opt_hdr {
  uint16_t option_code;
  uint16_t option_len;
  // option data (DIY!!)
};

struct dhcpv6_duid_hdr {
  uint16_t type;      // DUID-Type
  uint16_t hardware;  // hardware type
};

struct dhcpv6_opt_iana_hdr {
  dhcpv6_opt_hdr opts;
  uint32_t iaid;
  uint32_t t1;
  uint32_t t2;
};

struct dhcpv6_opt_iaaddr_hdr {
  dhcpv6_opt_hdr opts;
  in6_addr ip;
  uint32_t pref_lft;
  uint32_t valid_lft;
};

// https://www.rfc-editor.org/rfc/rfc8415.html#section-24
// https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml
#ifndef DHCPV6_MSG_TYPES
#define DHCPV6_MSG_TYPES

#define DHCPV6_MSG_SOLICIT              1
#define DHCPV6_MSG_ADVERTISE            2
#define DHCPV6_MSG_REQUEST              3
#define DHCPV6_MSG_CONFIRM              4
#define DHCPV6_MSG_RENEW                5
#define DHCPV6_MSG_REBIND               6
#define DHCPV6_MSG_REPLY                7
#define DHCPV6_MSG_RELEASE              8
#define DHCPV6_MSG_DECLINE              9
#define DHCPV6_MSG_RECONFIGURE          10
#define DHCPV6_MSG_INFORMATION_REQUEST  11
#define DHCPV6_MSG_RELAY_FORW           12
#define DHCPV6_MSG_RELAY_REPL           13
#define DHCPV6_MSG_LEASEQUERY           14
#define DHCPV6_MSG_LEASEQUERY_REPLY     15
#define DHCPV6_MSG_LEASEQUERY_DONE      16
#define DHCPV6_MSG_LEASEQUERY_DATA      17
#define DHCPV6_MSG_RECONFIGURE_REQUEST  18
#define DHCPV6_MSG_RECONFIGURE_REPLY    19
#define DHCPV6_MSG_DHCPV4_QUERY         20
#define DHCPV6_MSG_DHCPV4_RESPONSE      21
#define DHCPV6_MSG_ACTIVELEASEQUERY     22
#define DHCPV6_MSG_STARTTLS             23
#define DHCPV6_MSG_BNDUPD               24
#define DHCPV6_MSG_BNDREPLY             25
#define DHCPV6_MSG_POOLREQ              26
#define DHCPV6_MSG_POOLRESP             27
#define DHCPV6_MSG_UPDREQ               28
#define DHCPV6_MSG_UPDREQALL            39
#define DHCPV6_MSG_UPDDONE              30
#define DHCPV6_MSG_CONNECT              31
#define DHCPV6_MSG_CONNECTREPLY         32
#define DHCPV6_MSG_DISCONNECT           33
#define DHCPV6_MSG_STATE                34
#define DHCPV6_MSG_CONTACT              35

#endif

#ifndef DHCPV6_OPT_CODES
#define DHCPV6_OPT_CODES

#define DHCPV6_OPT_CLIENTID     1
#define DHCPV6_OPT_SERVERID     2
#define DHCPV6_OPT_IA_NA        3
#define DHCPV6_OPT_IA_TA        4
#define DHCPV6_OPT_IAADDR       5
#define DHCPV6_OPT_ORO          6
#define DHCPV6_OPT_PREFERENCE   7
#define DHCPV6_OPT_ELAPSED_TIME 8
#define DHCPV6_OPT_RELAY_MSG    9
// 10 is not assigned.
#define DHCPV6_OPT_AUTH         11
#define DHCPV6_OPT_UNICAST      12
#define DHCPV6_OPT_STATUS_CODE  13
#define DHCPV6_OPT_RAPID_COMMIT 14
#define DHCPV6_OPT_USER_CLASS   15
#define DHCPV6_OPT_VENDOR_CLASS 16
#define DHCPV6_OPT_VENDOR_OPTS  17
#define DHCPV6_OPT_INTERFACE_ID 18
#define DHCPV6_OPT_RECONF_MSG   19
#define DHCPV6_OPT_RECONF_ACCEPT 20
#define DHCPV6_OPT_SIP_SERVER_D 21
#define DHCPV6_OPT_SIP_SERVER_A 22
#define DHCPV6_OPT_DNS_SERVERS  23
#define DHCPV6_OPT_DOMAIN_LIST  24
#define DHCPV6_OPT_IA_PD        25
#define DHCPV6_OPT_IAPREFIX     26
#define DHCPV6_OPT_NIS_SERVERS          27
#define DHCPV6_OPT_NISP_SERVERS         28
#define DHCPV6_OPT_NIS_DOMAIN_NAME      29
#define DHCPV6_OPT_NISP_DOMAIN_NAME     30
#define DHCPV6_OPT_SNTP_SERVERS         31
#define DHCPV6_OPT_INFORMATIDHCP_OPT_REFRESH_TIME 32
#define DHCPV6_OPT_BCMCS_SERVER_D       33
#define DHCPV6_OPT_BCMCS_SERVER_A       34
/* 35 is unassigned */
#define DHCPV6_OPT_GEOCONF_CIVIC        36
#define DHCPV6_OPT_REMOTE_ID            37
#define DHCPV6_OPT_SUBSCRIBER_ID 	      38
#define DHCPV6_OPT_CLIENT_FQDN 	        39
#define DHCPV6_OPT_PANA_AGENT 	        40
#define DHCPV6_OPT_NEW_POSIX_TIMEZONE 	41
#define DHCPV6_OPT_NEW_TZDB_TIMEZONE 	  42
#define DHCPV6_OPT_ERO 	                43
#define DHCPV6_OPT_LQ_QUERY 	          44
#define DHCPV6_OPT_CLIENT_DATA 	        45
#define DHCPV6_OPT_CLT_TIME 	          46
#define DHCPV6_OPT_LQ_RELAY_DATA      	47
#define DHCPV6_OPT_LQ_CLIENT_LINK 	    48
#define DHCPV6_OPT_MIP6_HNIDF 	        49
#define DHCPV6_OPT_MIP6_VDINF 	        50
#define DHCPV6_OPT_V6_LOST 	            51
#define DHCPV6_OPT_CAPWAP_AC_V6 	      52
#define DHCPV6_OPT_RELAY_ID 	          53
#define DHCPV6_OPT_IPv6_Address_MoS 	  54
#define DHCPV6_OPT_IPv6_FQDN_MoS 	      55
#define DHCPV6_OPT_NTP_SERVER 	        56
#define DHCPV6_OPT_V6_ACCESS_DOMAIN 	  57
#define DHCPV6_OPT_SIP_UA_CS_LIST 	    58
#define DHCPV6_OPT_BOOTFILE_URL 	      59
#define DHCPV6_OPT_BOOTFILE_PARAM 	    60
#define DHCPV6_OPT_CLIENT_ARCH_TYPE 	  61
#define DHCPV6_OPT_NII 	                62
#define DHCPV6_OPT_GEOLOCATION 	        63
#define DHCPV6_OPT_AFTR_NAME 	          64
#define DHCPV6_OPT_ERP_LOCAL_DOMAIN_NAME 	  65
#define DHCPV6_OPT_RSOO 	              66
#define DHCPV6_OPT_PD_EXCLUDE 	        67
#define DHCPV6_OPT_VSS 	                68
#define DHCPV6_OPT_MIP6_IDINF 	        68
#define DHCPV6_OPT_MIP6_UDINF 	        69
#define DHCPV6_OPT_MIP6_HNP 	          71
#define DHCPV6_OPT_MIP6_HAA 	          72
#define DHCPV6_OPT_MIP6_HAF 	          73
#define DHCPV6_OPT_RDNSS_SELECTION 	    74
#define DHCPV6_OPT_KRB_PRINCIPAL_NAME 	75
#define DHCPV6_OPT_KRB_REALM_NAME 	    76
#define DHCPV6_OPT_KRB_DEFAULT_REALM_NAME 	77
#define DHCPV6_OPT_KRB_KDC 	            78
#define DHCPV6_OPT_CLIENT_LINKLAYER_ADDR 	  79
#define DHCPV6_OPT_LINK_ADDRESS 	      80
#define DHCPV6_OPT_RADIUS 	            81
#define DHCPV6_OPT_SOL_MAX_RT 	        82
#define DHCPV6_OPT_INF_MAX_RT 	        83
#define DHCPV6_OPT_ADDRSEL 	            84
#define DHCPV6_OPT_ADDRSEL_TABLE 	      85
#define DHCPV6_OPT_V6_PCP_SERVER 	      86
#define DHCPV6_OPT_DHCPV4_MSG 	        87
#define DHCPV6_OPT_DHCP4_O_DHCP6_SERVER 	  88
#define DHCPV6_OPT_S46_RULE 	          89
#define DHCPV6_OPT_S46_BR               90
#define DHCPV6_OPT_S46_DMR              91
#define DHCPV6_OPT_S46_V4V6BIND 	      92
#define DHCPV6_OPT_S46_PORTPARAMS 	    93
#define DHCPV6_OPT_S46_CONT_MAPE 	      94
#define DHCPV6_OPT_S46_CONT_MAPT 	      95
#define DHCPV6_OPT_S46_CONT_LW 	        96
#define DHCPV6_OPT_4RD 	                97
#define DHCPV6_OPT_4RD_MAP_RULE 	      98
#define DHCPV6_OPT_4RD_NON_MAP_RULE 	  99
#define DHCPV6_OPT_LQ_BASE_TIME 	      100
#define DHCPV6_OPT_LQ_START_TIME 	      101
#define DHCPV6_OPT_LQ_END_TIME 	        102
#define DHCPV6_OPT_CAPTIVE_PORTAL 	    103
#define DHCPV6_OPT_MPL_PARAMETERS 	    104
#define DHCPV6_OPT_ANI_ATT 	            105
#define DHCPV6_OPT_ANI_NETWORK_NAME 	  106
#define DHCPV6_OPT_ANI_AP_NAME 	        107
#define DHCPV6_OPT_ANI_AP_BSSID 	      108
#define DHCPV6_OPT_ANI_OPERATOR_ID 	    109
#define DHCPV6_OPT_ANI_OPERATOR_REALM 	110
#define DHCPV6_OPT_S46_PRIORITY 	      111
#define DHCPV6_OPT_MUD_URL_V6 	        112
#define DHCPV6_OPT_V6_PREFIX64 	        113
#define DHCPV6_OPT_F_BINDING_STATUS 	  114
#define DHCPV6_OPT_F_CONNECT_FLAGS 	    115
#define DHCPV6_OPT_F_DNS_REMOVAL_INFO 	116
#define DHCPV6_OPT_F_DNS_HOST_NAME 	    117
#define DHCPV6_OPT_F_DNS_ZONE_NAME 	    118
#define DHCPV6_OPT_F_DNS_FLAGS 	        119
#define DHCPV6_OPT_F_EXPIRATION_TIME 	  120
#define DHCPV6_OPT_F_MAX_UNACKED_BNDUPD 	  121
#define DHCPV6_OPT_F_MCLT 	            122
#define DHCPV6_OPT_F_PARTNER_LIFETIME 	123
#define DHCPV6_OPT_F_PARTNER_LIFETIME_SENT 	124
#define DHCPV6_OPT_F_PARTNER_DOWN_TIME 	125
#define DHCPV6_OPT_F_PARTNER_RAW_CLT_TIME 	126
#define DHCPV6_OPT_F_PROTOCOL_VERSION 	127
#define DHCPV6_OPT_F_KEEPALIVE_TIME 	  128
#define DHCPV6_OPT_F_RECONFIGURE_DATA 	129
#define DHCPV6_OPT_F_RELATIONSHIP_NAME 	130
#define DHCPV6_OPT_F_SERVER_FLAGS 	    131
#define DHCPV6_OPT_F_SERVER_STATE 	    132
#define DHCPV6_OPT_F_START_TIME_OF_STATE 	  133
#define DHCPV6_OPT_F_STATE_EXPIRATION_TIME 	134
#define DHCPV6_OPT_RELAY_PORT 	        135
#define DHCPV6_OPT_V6_SZTP_REDIRECT 	  136
#define DHCPV6_OPT_S46_BIND_IPV6_PREFIX 	  137
#define DHCPV6_OPT_IA_LL 	              138
#define DHCPV6_OPT_LLADDR               139
#define DHCPV6_OPT_SLAP_QUAD            140
#define DHCPV6_OPT_V6_DOTS_RI           141
#define DHCPV6_OPT_V6_DOTS_ADDRESS      142
#define DHCPV6_OPT_V6_DNR               144
#define DHCPV6_OPT_REGISTERED_DOMAIN    145
#define DHCPV6_OPT_FORWARD_DIST_MANAGER 146
#define DHCPV6_OPT_REVERSE_DIST_MANAGER 147

#endif

#ifndef DUID_TYPES
#define DUID_TYPES

#define DUID_LLT 1
#define DUID_EN 2
#define DUID_LL 3
#define DUID_UUID 4

#endif
