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
static void os_cmd_alert_add(sourceinfo_t *si, int parc, char *parv[]);
static void os_cmd_alert_del(sourceinfo_t *si, int parc, char *parv[]);
static void os_cmd_alert_list(sourceinfo_t *si, int parc, char *parv[]);

command_t os_alert = {
	"ALERT",
	N_("Checks if users joining the network match criteria and performs actions on them."),
	PRIV_USER_AUSPEX, 3, os_cmd_alert, { .path = "contrib/os_alert"}
};

command_t os_alert_add = {
	"ADD",
	N_("Add an alert."),
	AC_NONE, 2, os_cmd_alert_add, { .path = ""}
};

command_t os_alert_del = {
	"DEL",
	N_("Delete an alert."),
	AC_NONE, 1, os_cmd_alert_del, { .path = "" }
};

command_t os_alert_list = {
	"LIST",
	N_("List alerts."),
	AC_NONE, 0, os_cmd_alert_list, { .path = "" }
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
		p->pattern.regex.pattern = sstrdup(pattern);
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
		p->pattern.glob = sstrdup(pattern);
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

typedef struct alert_criteria_ alert_criteria_t;
typedef struct alert_action_ alert_action_t;
typedef struct alert_ alert_t;

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

typedef struct {
	alert_criteria_t base;
	alert_pattern_t *pattern;
} alert_nick_criteria_t;

alert_criteria_t *alert_nick_criteria_prepare(char **args)
{
	alert_nick_criteria_t *criteria;
	alert_pattern_t *pattern;

	return_val_if_fail(args != NULL, NULL);
	return_val_if_fail(*args != NULL, NULL);

	pattern = pattern_extract(args, false);
	return_val_if_fail(pattern != NULL, NULL);

	criteria = smalloc(sizeof(alert_nick_criteria_t));
	criteria->pattern = pattern;
}

bool alert_nick_criteria_exec(user_t *u, alert_criteria_t *c)
{
	alert_nick_criteria_t *criteria = (alert_nick_criteria_t *)c;

	return_val_if_fail(u != NULL, NULL);
	return_val_if_fail(c != NULL, NULL);

	return pattern_match(criteria->pattern, u->nick);
}

void alert_nick_criteria_cleanup(alert_criteria_t *c)
{
	alert_nick_criteria_t *criteria = (alert_nick_criteria_t *)c;

	return_if_fail(c != NULL);

	pattern_destroy(criteria->pattern);
	free(criteria);
}

alert_criteria_constructor_t alert_nick_criteria = {
	"NICK",
	alert_nick_criteria_prepare, alert_nick_criteria_exec, alert_nick_criteria_cleanup,
	EVT_CONNECT | EVT_NICK
};

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
	char *owner;              /* Who owns the alert. This is an entity name. */
	alert_event_t event_mask; /* What events this triggers on. */
	alert_action_t *action;   /* The alert action. */
	mowgli_list_t criteria;   /* The list of criteria. */

	mowgli_node_t *node;       /* The pointer in nodes */
	mowgli_node_t *owned_node; /* The pointer in owned_nodes */
};

static alert_action_t *alert_notice_action_prepare(sourceinfo_t *si, char **args)
{
	return_val_if_fail(si != NULL, NULL);

	return smalloc(sizeof(alert_action_t));
}

static void alert_notice_action_exec(user_t *u, alert_action_t *a)
{
	mowgli_node_t *node = NULL;
	myentity_t *ent = NULL;

	return_if_fail(u != NULL);
	return_if_fail(a != NULL);

	ent = myentity_find(a->alert->owner);
	return_if_fail(ent != NULL);
	return_if_fail(isuser(ent));

	myuser_notice(operserv->nick, (myuser_t *)ent, "\2Alert:\2  %s!%s@%s %s {%s}", u->nick, u->user, u->host, u->gecos, u->server->name);

}

static void alert_notice_action_cleanup(alert_action_t *a)
{
	return_if_fail(a != NULL);

	free(a);
}

alert_action_constructor_t alert_notice_action = {
	"NOTICE", alert_notice_action_prepare,
	alert_notice_action_exec, alert_notice_action_cleanup
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
mowgli_list_t alerts = { NULL, NULL, 0 };

/* A map of users (entity names) to mowgli_list_t of alerts with pointers into
 * the all_alerts list. */
mowgli_patricia_t *owned_alerts = NULL;

/* Sub-command tree. */
mowgli_patricia_t *os_alert_cmds = NULL;

void _modinit(module_t *module)
{
	operserv = service_find("operserv");
	service_bind_command(operserv, &os_alert);

	alert_cmdtree = mowgli_patricia_create(strcasecanon);
	mowgli_patricia_add(alert_cmdtree, alert_nick_criteria.name, &alert_nick_criteria);

	alert_acttree = mowgli_patricia_create(strcasecanon);
	mowgli_patricia_add(alert_acttree, alert_notice_action.name, &alert_notice_action);

	owned_alerts = mowgli_patricia_create(strcasecanon);

	os_alert_cmds = mowgli_patricia_create(strcasecanon);
	command_add(&os_alert_add, os_alert_cmds);
	command_add(&os_alert_del, os_alert_cmds);
	command_add(&os_alert_list, os_alert_cmds);
}

/* Destroy an alert and remove it from all lists */
static void alert_destroy(alert_t *alert)
{
	mowgli_list_t *owned_list = NULL;

	return_if_fail(alert != NULL);

	alert->action->cons->cleanup(alert->action);

	while (alert->criteria.count != 0)
	{
		mowgli_node_t *head = alert->criteria.head;
		alert_criteria_t *criteria = head->data;

		criteria->cons->cleanup(criteria);

		mowgli_node_delete(head, &alert->criteria);
		mowgli_node_free(head);
	}

	mowgli_node_delete(alert->node, &alerts);
	mowgli_node_free(alert->node);

	owned_list = mowgli_patricia_retrieve(owned_alerts, alert->owner);

	mowgli_node_delete(alert->owned_node, owned_list);
	mowgli_node_free(alert->owned_node);

	if (owned_list->count == 0)
	{
		mowgli_patricia_delete(owned_alerts, alert->owner);
		mowgli_list_free(owned_list );
	}

	free(alert->owner);
}

void owned_alerts_cleanup(const char *key, void *data, void *unused)
{
	mowgli_node_free(data);
	(void)unused;
}

void _moddeinit(module_unload_intent_t intent)
{
	service_unbind_command(operserv, &os_alert);

	mowgli_patricia_delete(alert_cmdtree, alert_nick_criteria.name);
	mowgli_patricia_destroy(alert_cmdtree, NULL, NULL);

	mowgli_patricia_delete(alert_acttree, alert_notice_action.name);
	mowgli_patricia_destroy(alert_acttree, NULL, NULL);

	command_delete(&os_alert_add, os_alert_cmds);
	command_delete(&os_alert_del, os_alert_cmds);
	command_delete(&os_alert_list, os_alert_cmds);

	mowgli_patricia_destroy(os_alert_cmds, NULL, NULL);

	operserv = NULL;

	while (alerts.count != 0)
		alert_destroy(alerts.head->data);

	mowgli_patricia_destroy(owned_alerts, owned_alerts_cleanup, NULL);
}


static void os_cmd_alert(sourceinfo_t *si, int parc, char *parv[])
{
	/* Grab args */
	char *cmd = parv[0];
	command_t *c;

	/* Bad/missing arg */
	if (!cmd)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "ALERT");
		command_fail(si, fault_needmoreparams, _("Syntax: ALERT ADD|DEL|LIST"));
		return;
	}

	c = command_find(os_alert_cmds, cmd);
	if (c == NULL)
	{
		command_fail(si, fault_badparams, _("Invalid command. Use \2/%s%s help\2 for a command listing."), (ircd->uses_rcommand == false) ? "msg " : "", si->service->disp);
		return;
	}

	command_exec(si->service, si, c, parc - 1, parv + 1);
}

static void os_cmd_alert_add(sourceinfo_t *si, int parc, char *parv[])
{
	alert_action_constructor_t *actcons = NULL;
	alert_action_t *action = NULL;
	alert_event_t event_mask = 0;
	alert_t *alert;

	mowgli_list_t criteria_list = { NULL, NULL, 0 };
	mowgli_list_t *owned_alerts_list = NULL;

	char *args = parv[1];
	bool failed = false;

	if (!parv[0])
	{
		command_fail(si, fault_badparams, STR_INVALID_PARAMS, "ALERT ADD");
		command_fail(si, fault_badparams, _("Syntax: ALERT ADD <action> <params>"));
		return;
	}

	actcons = mowgli_patricia_retrieve(alert_acttree, parv[0]);
	if (actcons == NULL)
	{
		command_fail(si, fault_badparams, STR_INVALID_PARAMS, "ALERT");
		command_fail(si, fault_badparams, _("Syntax: ALERT ADD <action> <params>"));
		return;
	}

	action = actcons->prepare(si, &args);
	if (action == NULL)
	{
		command_fail(si, fault_nosuch_target, _("Invalid criteria specified."));
		return;
	}
	action->cons = actcons;

	/* Parse out all the criteria. */
	while (true)
	{
		alert_criteria_constructor_t *cons;
		alert_criteria_t *criteria;

		char *cmd = strtok(args, " ");

		if (cmd == NULL)
		{
			if (criteria_list.count == 0)
				failed = true;
			break;
		}

		cons = mowgli_patricia_retrieve(alert_cmdtree, cmd);
		if (cons == NULL)
		{
			command_fail(si, fault_nosuch_target, _("Invalid criteria specified."));
			failed = true;
			break;
		}

		args = strtok(NULL, "");
		if (args == NULL)
		{
			command_fail(si, fault_nosuch_target, _("Invalid criteria specified."));
			failed = true;
			break;

		}

		criteria = cons->prepare(&args);
		slog(LG_DEBUG, "operserv/alert: adding criteria %p(%s) to list [remain: %s]", criteria, cmd, args);
		if (criteria == NULL)
		{
			command_fail(si, fault_nosuch_target, _("Invalid criteria specified."));
			failed = true;
			break;
		}

		slog(LG_DEBUG, "operserv/alert: new args position [%s]", args);

		criteria->cons = cons;
		event_mask |= cons->event_mask;

		mowgli_node_add(criteria, mowgli_node_create(), &criteria_list);
	}

	/* If we fail at any point, we must clean up the list of criteria. */
	if (failed)
	{
		while (criteria_list.count != 0)
		{
			mowgli_node_t *node = criteria_list.head;
			alert_criteria_t *criteria = node->data;
			criteria->cons->cleanup(criteria);

			mowgli_node_delete(node, &criteria_list);
			mowgli_node_free(node);
		}
		return;
	}

	alert = smalloc(sizeof(alert_t));
	alert->owner = sstrdup(entity(si->smu)->name);
	alert->action = action;
	alert->action->alert = alert;
	alert->criteria = criteria_list;
	alert->event_mask = event_mask;

	alert->node = mowgli_node_create();
	alert->owned_node = mowgli_node_create();

	/* Add the alert to the list of all alerts. */
	mowgli_node_add(alert, alert->node, &alerts);

	/* If the requesting user doesn't have any alerts, we create a new list for
	 * him/her.
	 */
	owned_alerts_list = mowgli_patricia_retrieve(owned_alerts, alert->owner);
	if (owned_alerts_list == NULL)
	{
		owned_alerts_list = mowgli_list_create();
		mowgli_patricia_add(owned_alerts, alert->owner, owned_alerts_list);
	}
	/* Add the alert to the owner's list of alerts. */
	mowgli_node_add(alert, alert->owned_node, owned_alerts_list);

	command_success_nodata(si, _("Added alert \x02%d\x02."), owned_alerts_list->count);
}

static void os_cmd_alert_del(sourceinfo_t *si, int parc, char *parv[])
{
	int n;
	mowgli_list_t *owned_list = NULL;

	if (!parv[0])
	{
		command_fail(si, fault_badparams, STR_INVALID_PARAMS, "ALERT DEL");
		command_fail(si, fault_badparams,  _("Syntax: ALERT DEL <n>"));
		return;
	}

	n = atoi(parv[0]);

	if (n < 0)
	{
		command_fail(si, fault_nosuch_target, "Invalid alert identifier.");
		return;
	}

	owned_list = mowgli_patricia_retrieve(owned_alerts, entity(si->smu)->name);
	if (owned_list == NULL)
		command_fail(si, fault_nosuch_target, "You have no alerts.");

	else if (n > owned_list->count)
		command_fail(si, fault_nosuch_target, "No such alert.");

	else
	{
		alert_t *alert = mowgli_node_nth_data(owned_list, n - 1);

		return_if_fail(alert != NULL);

		alert_destroy(alert);

		command_success_nodata(si, _("Deleted alert."));
	}
}

static void os_cmd_alert_list(sourceinfo_t *si, int parc, char *parv[])
{
	mowgli_list_t *owned_list = mowgli_patricia_retrieve(owned_alerts, entity(si->smu)->name);
	if (owned_list == NULL)
		command_fail(si, fault_nosuch_target, "You have no alerts.");
	
	else
	{
		mowgli_node_t *node = NULL;
		int i = 1;
		command_success_nodata(si, _("Alerts:"));
		MOWGLI_LIST_FOREACH(node, owned_list->head)
		{
			alert_t *alert = node->data;
			command_success_nodata(si, "Alert: %d %s", i, alert->action->cons->name);
			i++;
		}
		command_success_nodata(si, _("End of alerts."));
	}
}
