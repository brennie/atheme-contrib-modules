#ifndef INCLUDE_OS_ALERT_H
#define INCLUDE_OS_ALERT_H

/* A pattern, represented by a glob or a regex */
typedef struct {
	enum {
		PAT_GLOB = 0, PAT_REGEX = 1
	} type;

	union {
		char *glob;

		struct {
			char *pattern;
			int flags;
			atheme_regex_t *regex;
		} regex;
	} pattern;
} alert_pattern_t;

/* The type of event that a criteria can be triggered on. */
typedef enum {
	EVT_CONNECT  = 0x01,
	EVT_IDENTIFY = 0x02,
	EVT_REGISTER = 0x04,
	EVT_DROP     = 0x08,
	EVT_HOST     = 0x10,
	EVT_JOIN     = 0x20,
	EVT_PART     = 0x40,
	EVT_NICK     = 0x80
	
} alert_event_t;

typedef struct alert_criteria_ alert_criteria_t;
typedef struct alert_action_ alert_action_t;
typedef struct alert_ alert_t;

/* A constructor for an alert criteria. */
typedef struct {
	alert_criteria_t *(*prepare)(char **args);
	bool (*exec)(user_t *u, alert_criteria_t *c);
	void (*cleanup)(alert_criteria_t *c);

	void (*display)(char *s, size_t size, alert_criteria_t *c);

	alert_event_t event_mask;
} alert_criteria_constructor_t;

/* An alert criteria. */
struct alert_criteria_ {
	alert_criteria_constructor_t *cons;
};

typedef struct {
	alert_criteria_t base;
	alert_pattern_t *pattern;
} alert_pattern_criteria_t;

typedef struct {
	alert_criteria_t base;
	bool identified;
} alert_identified_criteria_t;

/* A constructor for an alert action. */
typedef struct {
	alert_action_t *(*prepare)(char **args);
	void (*exec)(user_t *u, alert_action_t *a);
	void (*cleanup)(alert_action_t *a);

	void (*display)(char *s, size_t size, alert_action_t *a);
} alert_action_constructor_t;

/* An alert action. */
struct alert_action_ {
	alert_action_constructor_t *cons;
	alert_t *alert;
};

/* An alert */
struct alert_ {
	char *owner;              /* Who owns the alert. This is an entity name. */
	alert_event_t event_mask; /* What events this triggers on. */
	alert_action_t *action;   /* The alert action. */
	mowgli_list_t criteria;   /* The list of criteria. */

	mowgli_node_t *node;       /* The pointer in nodes */
	mowgli_node_t *owned_node; /* The pointer in owned_nodes */
};

#endif
