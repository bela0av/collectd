#include "collectd.h"
#include "plugin.h"
#include "common.h"
#include "configfile.h"

#include <stdio.h>
#include <time.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>

#if HAVE_SYSLOG_H
# include <syslog.h>
#endif

static char *syslog_host = NULL;
static int syslog_port;
static int syslog_facility;
static int syslog_severity;
static int notif_severity;
static _Bool override_severity;

static int socketFileDescriptor;

static int rsyslog_config(oconfig_item_t *ci) {
	int i;
	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (0 == strcasecmp(child->key, "Host"))
			cf_util_get_string(child, &syslog_host);
		else if (0 == strcasecmp(child->key, "Port"))
			cf_util_get_int(child, &syslog_port);
		else if (0 == strcasecmp(child->key, "Facility"))
			cf_util_get_int(child, &syslog_facility);
		else if (0 == strcasecmp(child->key, "Severity"))
			cf_util_get_int(child, &syslog_severity);
		else if (0 == strcasecmp(child->key, "OverrideSeverity"))
			cf_util_get_boolean(child, &override_severity);
		else if (0 == strcasecmp(child->key, "NotifyLevel")) {
			char *notif_severity_string = NULL;
			cf_util_get_string(child, &notif_severity_string);
			notif_severity = parse_notif_severity(notif_severity_string);
			if (notif_severity < 0)
				return (-1);
		} else
			WARNING(
					"notify_remote_syslog plugin: Ignoring unknown config option \"%s\".",
					child->key);
	} DEBUG ("notify_remote_syslog plugin: Host: %s",syslog_host); DEBUG ("notify_remote_syslog plugin: Port: %d",syslog_port); DEBUG ("notify_remote_syslog plugin: Facility: %d",syslog_facility); DEBUG ("notify_remote_syslog plugin: Severity: %d",syslog_severity); DEBUG ("notify_remote_syslog plugin: NotifyLevel: %d",notif_severity); DEBUG ("notify_remote_syslog plugin: OverrideSeverity: %d",override_severity);
	return 0;
}

static int rsyslog_init(void) {
	socketFileDescriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socketFileDescriptor < 0) {
		ERROR("notify_remote_syslog plugin: socket() failed: %s\n",
				strerror(errno));
		return (-1);
	}
	return 0;
}

static int rsyslog_shutdown(void) {
	shutdown(socketFileDescriptor, SHUT_RDWR);
	close(socketFileDescriptor);
	return 0;
}

static int rsyslog_write_socket(char *pLogMessage) {
	struct hostent *pServer = gethostbyname(syslog_host);
	if (pServer == NULL) {
		ERROR("notify_remote_syslog plugin: unable to resolve '%s'\n",
				syslog_host);
		return (-1);
	}

	struct sockaddr_in sockServerAddr;
	memset(&sockServerAddr, 0, sizeof(struct sockaddr_in));
	sockServerAddr.sin_family = AF_INET;
	memcpy(&sockServerAddr.sin_addr.s_addr, pServer->h_addr, pServer->h_length); /* remote syslogd server ip */
	//sockServerAddr.sin_port = htons((uint16_t) *syslog_port);
	sockServerAddr.sin_port = htons(514);

	/* send the log message to the socket */
	size_t bytesSent = sendto(socketFileDescriptor, /* socket file descriptor */
	pLogMessage, /* message to be sent */
	strlen(pLogMessage), /* message size in bytes */
	0, /* flag: ? */
	(struct sockaddr *) &sockServerAddr, /* points to a sockaddr structure containing the destination address */
	sizeof(sockServerAddr)); /* specifies the length of the sockaddr structure pointed to by the previous argument */

	DEBUG (pLogMessage);

	if (bytesSent < 0) {
		ERROR("notify_remote_syslog plugin: send() failed: %s\n",
				strerror(errno));
		return (-1);
	}DEBUG ("notify_remote_syslog plugin: Successfully sent.\n");
	return 0;
}

char *replace(const char *s, char ch, const char *repl) {
	int count = 0;
	const char *t;
	for (t = s; *t; t++)
		count += (*t == ch);

	size_t rlen = strlen(repl);
	char *res = malloc(strlen(s) + (rlen - 1) * count + 1);
	char *ptr = res;
	for (t = s; *t; t++) {
		if (*t == ch) {
			memcpy(ptr, repl, rlen);
			ptr += rlen;
		} else {
			*ptr++ = *t;
		}
	}
	*ptr = 0;
	return res;
}

const char *coalesce(const char *s) {
	if (s && !s[0]) {
		s = "UNDEF";
	}
	return s;
}

static int rsyslog_notify(const notification_t *n, user_data_t *ud) {

	char time_buf[80];

	struct tm *utc_time;
	time_t t;
	t = time(NULL);
	utc_time = gmtime(&t);
	strftime(time_buf, sizeof(time_buf), "%FT%T", utc_time);
	DEBUG ("UTC time and date: %s", time_buf);

	char buf[1024] = "";
	int log_severity;
	const char *severity_string;

	if (n->severity > notif_severity)
		return (0);

	switch (n->severity) {
	case NOTIF_FAILURE:
		severity_string = "FAILURE";
		log_severity = LOG_ERR;
		break;
	case NOTIF_WARNING:
		severity_string = "WARNING";
		log_severity = LOG_WARNING;
		break;
	case NOTIF_OKAY:
		severity_string = "OKAY";
		log_severity = LOG_NOTICE;
		break;
	default:
		severity_string = "UNKNOWN";
		log_severity = LOG_ERR;
	}

	if (override_severity)
		syslog_severity = log_severity;

	int syslog_priority = syslog_facility * 8 + syslog_severity;

	ssnprintf(buf, sizeof(buf), "<%i>1 %s %s %s %s %s %s %s %s Message: %s\n",
			syslog_priority, time_buf, n->host, "COLLECTD", severity_string,
			coalesce(replace(n->plugin, ' ', "_")),
			coalesce(replace(n->plugin_instance, ' ', "_")),
			coalesce(replace(n->type, ' ', "_")),
			coalesce(replace(n->type_instance, ' ', "_")), n->message);

	DEBUG ("notify_remote_syslog plugin: %s",buf);

	rsyslog_write_socket(buf);

	return 0;
}

void module_register(void) {
	plugin_register_complex_config("notify_remote_syslog", rsyslog_config);
	plugin_register_notification("notify_remote_syslog", rsyslog_notify, NULL);
	plugin_register_init("notify_remote_syslog", rsyslog_init);
	plugin_register_shutdown("notify_remote_syslog", rsyslog_shutdown);
	return;
}

