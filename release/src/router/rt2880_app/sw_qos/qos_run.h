#ifndef __QOS_RUN_H__
#define __QOS_RUN_H__

struct qos_rule_s;
struct af_group_s;

void QoSFlush(void);
void QoSCreate(char *wanif);

void DRRQoSRun(char *interface, struct qos_rule_s *rules, int rule_count, const char *chain, int bandwidth, struct af_group_s *af_group);
void SPQQoSRun(char *interface, struct qos_rule_s *rules, int rule_count, const char *chain, int bandwidth);
void SPQDRRQoSRun(char *interface, struct qos_rule_s *rules, int rule_count, const char *chain, int bandwidth, struct af_group_s *af_group);

struct qos_rule_s
{
	int		af_index;			/*	which queue this rule belong to, QOS_QUEUE[4-1] */

	int		dp_index;			/*	reserved									*/

	char	mac_address[18];	/*	src mac address, ex: 11:22:33:44:55:66  	*/

	char	sip[32];			/*	source ip, 		ex: 111.222.111.222 		*/

	char	dip[32];			/*	dest ip 									*/

	char	pktlenfrom[8];		/*	packet length, from 		ex: "163"		*/
	char	pktlento[8];		/*	packet length, to 		ex: "234"			*/

	char	protocol[16];		/* "TCP", "UDP", "ICMP", or "Application"		*/

	char	sprf[8], sprt[8];	/*	TCP/UDP source port range
									ex: sprf= "79", sprt="93"					*/

	char	dprf[8], dprt[8];	/*	TCP/UDP dest port range						
									ex: dprf= "12345", sprt="12678"				*/

	char	layer7[64];			/*	layer7 filter name. see /etc_ro/l7-protocols.
									Bind with "Application". 					*/
	
	char	dscp[8];			/*	DSCP class name, ex: "AF42", "AF13", "BE",
									or "EF".	 								*/

	char	remarker[8];		/*	remark DSCP class, ex: "AF23", "AF13", "BE", "EF",
									or "N/A"(not change).						*/
};

struct port_based_rule_s
{
	unsigned int port;
	unsigned int priority;
};

struct af_group_s
{
	float af1_ceil, af1_rate;
	float af2_ceil, af2_rate;
	float af3_ceil, af3_rate;
	float af4_ceil, af4_rate;
	float af5_ceil, af5_rate;
	float af6_ceil, af6_rate;
};

extern int debug_buildrule;

#define FIFO_QUEUE_LEN	100

#define QOS_QUEUE1		5		/* highest queue */
#define QOS_QUEUE2		2		/* middle  queue */
#define QOS_QUEUE3		6		/* default queue */
#define QOS_QUEUE4		1		/* lowest  queue */

#define DEFAULT_GROUP			QOS_QUEUE3

#define QOS_QUEUE1_MIN(x)		(x.af5_rate)
#define QOS_QUEUE1_MAX(x)		(x.af5_ceil)
#define QOS_QUEUE2_MIN(x)		(x.af2_rate)
#define QOS_QUEUE2_MAX(x)		(x.af2_ceil)
#define QOS_QUEUE3_MIN(x)		(x.af6_rate)
#define QOS_QUEUE3_MAX(x)		(x.af6_ceil)
#define QOS_QUEUE4_MIN(x)		(x.af1_rate)
#define QOS_QUEUE4_MAX(x)		(x.af1_ceil)
#define QOS_QUEUE5_MIN(x)		(x.af4_rate)	/* not used */
#define QOS_QUEUE5_MAX(x)		(x.af4_ceil)	/* not used */
#define QOS_QUEUE6_MIN(x)		(x.af3_rate)	/* not used */
#define QOS_QUEUE6_MAX(x)		(x.af3_ceil)	/* not used */

#define QOS_PREROUTING_RULE_CHAIN	"qos_prerouting_rule_chain"
#define QOS_POSTROUTING_RULE_CHAIN	"qos_postrouting_rule_chain"

#define QOS_PREROUTING_IMQ_CHAIN	"qos_prerouting_imq_chain"
#define QOS_POSTROUTING_IMQ_CHAIN	"qos_postrouting_imq_chain"

#define CLASSIFIER_RULE			0
#define REMARK_RULE				1
#define RETURN_RULE				2

#define QOS_MODEL_DRR			1
#define QOS_MODEL_SPQ			2
#define QOS_MODEL_SPQ_DRR		3
#define QOS_MODEL_REMARKONLY	4

#define HARD_LIMIT_RATE_MIN			2.0			// kbits

#define AF1_MAX_LATENCY				500			// ms
#define AF2_MAX_LATENCY				500			// ms
#define AF3_MAX_LATENCY				500			// ms
#define AF4_MAX_LATENCY				500			// ms
#define AF5_MAX_LATENCY				300			// ms (EF)
#define AF6_MAX_LATENCY				500			// ms (BE)



#endif


