/*
 * Copyright (c) 2014 Barret Rennie <barret@brennie.ca>
 * Rights to this code are as documented in doc/LICENSE.
 *
 * A command similar to OS RWATCH but with more diverse criteria.
 */

#include "atheme-compat.h"

DECLARE_MODULE_V1
(
	"contrib/os_alert", false, _modinit, _moddeinit,
	"v0.1",
	"Barret Rennie <barret@brennie.ca>"
);

static service_t *operserv;

static void os_cmd_alert(sourceinfo_t *si, int parc, char *parv[]);

command_t os_alert = {
	"ALERT",
	N_("Checks if users joining the network match criteria and performs actions on them."),
	PRIV_USER_AUSPEX, 2, os_cmd_alert, { .path = "contrib/os_alert"}
};

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

/* Extract a pattern, which is either a regular expression or a glob match,
 * which can be multi-word glob if it is quoted.
 */
alert_pattern_t* pattern_extract(char **args, bool allow_quotes)
{
	alert_pattern_t *p = NULL;
	char *pattern;

	return_val_if_fail(args != NULL, NULL);
	return_val_if_fail(*args != NULL, NULL);

	while (**args == ' ')
		(*args)++;

	if (**args == '/')
	{
		int flags;
		pattern = regex_extract(*args, args, &flags);

		p = smalloc(sizeof(alert_pattern_t));
		p->type = PAT_REGEX;
		p->pattern.regex.pattern = pattern;
		p->pattern.regex.flags = flags;
		p->pattern.regex.regex = regex_create(pattern, flags);
	}
	else
	{
		if (!allow_quotes && **args == '"')
			return NULL;

		if (**args == '"')
		{
			pattern = strtok(*args + 1, "\"");

			return_val_if_fail(pattern != NULL, NULL);
		}
		else
			pattern = strtok(*args, " ");

		*args = strtok(NULL, "");

		p = smalloc(sizeof(alert_pattern_t));
		p->type = PAT_GLOB;
		p->pattern.glob = pattern;
	}

	return p;
}

/* Free the pattern. */
void pattern_destroy(alert_pattern_t *p)
{
	return_if_fail(p != NULL);

	if (p->type == PAT_REGEX)
	{
		free(p->pattern.regex.pattern);
		regex_destroy(p->pattern.regex.regex);
	}
	else
		free(p->pattern.glob);

	free(p);
}

/* Do a pattern match with the given pattern against the string s. */
bool pattern_match(alert_pattern_t *p, const char *s)
{
	return_val_if_fail(p != NULL, false);
	return_val_if_fail(s != NULL, false);

	switch (p->type)
	{
		case PAT_GLOB:
			return match(p->pattern.glob, s);

		case PAT_REGEX:
			return regex_match(p->pattern.regex.regex, (char *)s);

		default:
			return false;
	}
}

/* The type of event that a criteria can be triggered on. */
typedef enum {
	EVT_CONNECT  = 0x01,
	EVT_IDENTIFY = 0x02,
	EVT_REGISTER = 0x04,
	EVT_JOIN     = 0x08,
	EVT_PART     = 0x10,
	EVT_NICK     = 0x20
} alert_event_t;

/* A constructor for an alert criteria. */
typedef struct {
	char *name;

	alert_criteria_t *(*prepare)(char **args);
	bool (*exec)(user_t *u, alert_criteria_t *c);
	void (*cleanup)( alert_criteria_t *c);

	alert_event_t event_mask;
} alert_criteria_constructor_t;

/* An alert criteria. */
struct alert_criteria_ {
	alert_criteria_constructor_t *cons;
};

typedef struct alert_action_ alert_action_t;
typedef struct alert_ alert_t;

/* A constructor for an alert action. */
typedef struct {
	char *name;

	alert_action_t *(*prepare)(sourceinfo_t *si, char **args);
	void (*exec)(user_t *u, alert_action_t *a);
	void (*cleanup)(alert_action_t *a);
} alert_action_constructor_t;

/* An alert action. */
struct alert_action_ {
	alert_action_constructor_t *cons;
	alert_t *alert;
};

/* An alert */
struct alert_ {
	const char *owner;        /* Who owns the alert. This is an entity name. */
	alert_event_t event_mask; /* What events this triggers on. */
	alert_action_t *action;   /* The alert action. */
	mowgli_list_t criteria;   /* The list of criteria. */
};

/*
 * Add-on interface.
 *
 * This allows third-party module writers to extend the alert API. Just copy
 * the prototypes out of os_alert.c, and add the alert_cmdtree symbol to your
 * module with MODULE_TRY_REQUEST_SYMBOL().
 *
 * Then add your criteria to the tree with mowgli_patricia_add().
 */
mowgli_patricia_t *alert_cmdtree = NULL;
mowgli_patricia_t *alert_acttree = NULL;

/* The list of active alerts. */
mowgli_list_t all_alerts = { NULL, NULL, 0 };

/* A map of users (entity names) to mowgli_list_t of alerts with pointers into
 * the all_alerts list. */
mowgli_patricia_t *alerts = NULL;

void _modinit(module_t *module)
{
	operserv = service_find("operserv");
	service_bind_command(operserv, &os_alert);
}

void _moddeinit(module_unload_intent_t intent)
{
	service_unbind_command(operserv, &os_alert);
	operserv = NULL;
}

static void os_cmd_alert(sourceinfo_t *si, int parc, char *parv[])
{
	command_fail(si, fault_badparams, _("Not yet implemented."));
}