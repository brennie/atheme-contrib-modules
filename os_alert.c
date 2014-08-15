/*
 * Copyright (c) 2014 Barret Rennie <barret@brennie.ca>
 * Rights to this code are as documented in doc/LICENSE.
 *
 * A command similar to OS RWATCH but with more diverse criteria.
 */

#include "atheme-compat.h"

#include "os_alert.h"

DECLARE_MODULE_V1
(
	"contrib/os_alert", false, _modinit, _moddeinit,
	"v0.1",
	"Barret Rennie <barret@brennie.ca>"
);

/*
 * Add-on interface.
 *
 * This allows third-party module writers to extend the alert API. Just include
 * "os_alert.h" and add the alert_cmdtree symbol to your module with
 * MODULE_TRY_REQUEST_SYMBOL().
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

/* Append to s using the pattern and variable args. */
static void snappendf(char *s, size_t size, const char *pattern, ...)
{
	va_list args;
	size_t len;

	return_if_fail(s != NULL);

	va_start(args, pattern);
	len = strlen(s);
	vsnprintf(s + len, size - len, pattern, args);
	va_end(args);
}

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

/* Extract a pattern, which is either a regular expression or a glob match,
 * which can be multi-word glob if it is quoted.
 */
static alert_pattern_t* pattern_extract(char **args, bool allow_quotes)
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
		return_val_if_fail(pattern != NULL, NULL);
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
static void pattern_destroy(alert_pattern_t *p)
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

static void pattern_display(char *s, size_t len, alert_pattern_t *p)
{
	return_if_fail(s != NULL);
	return_if_fail(p != NULL);

	if (p->type == PAT_REGEX)
	{
		snappendf(s, len, " /%s/", p->pattern.regex.pattern);
		if (p->pattern.regex.flags & AREGEX_ICASE)
			snappendf(s, len, "i");
		if (p->pattern.regex.flags & AREGEX_PCRE)
			snappendf(s, len, "p");
	}
	else if (strchr(p->pattern.glob, ' ') == NULL)
		snappendf(s, len, " %s", p->pattern.glob);
	else
		snappendf(s, len, " \"%s\"", p->pattern.glob);
}

/* Do a pattern match with the given pattern against the string s. */
static bool pattern_match(alert_pattern_t *p, const char *s)
{
	return_val_if_fail(p != NULL, false);
	return_val_if_fail(s != NULL, false);

	switch (p->type)
	{
		case PAT_GLOB:
			return !match(p->pattern.glob, s);

		case PAT_REGEX:
			return regex_match(p->pattern.regex.regex, (char *)s);

		default:
			return false;
	}
}

static alert_criteria_t *alert_pattern_criteria_prepare(char **args)
{
	alert_pattern_criteria_t *criteria;
	alert_pattern_t *pattern;

	return_val_if_fail(args != NULL, NULL);
	return_val_if_fail(*args != NULL, NULL);

	pattern = pattern_extract(args, false);
	return_val_if_fail(pattern != NULL, NULL);

	criteria = smalloc(sizeof(alert_pattern_criteria_t));
	criteria->pattern = pattern;

	return (alert_criteria_t *)criteria;
}

static bool alert_nick_criteria_exec(user_t *u, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_val_if_fail(u != NULL, false);
	return_val_if_fail(c != NULL, false);

	return pattern_match(criteria->pattern, u->nick);
}

static void alert_pattern_criteria_cleanup(alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_if_fail(c != NULL);

	pattern_destroy(criteria->pattern);
	free(criteria);
}

static void alert_nick_criteria_display(char *s, size_t size, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_if_fail(c != NULL);
	return_if_fail(c != NULL);

	snappendf(s, size, " NICK");
	pattern_display(s, size, criteria->pattern);
}

alert_criteria_constructor_t alert_nick_criteria = {
	alert_pattern_criteria_prepare, alert_nick_criteria_exec, alert_pattern_criteria_cleanup,
	alert_nick_criteria_display,
	EVT_CONNECT | EVT_NICK
};

static bool alert_user_criteria_exec(user_t *u, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_val_if_fail(u != NULL, false);
	return_val_if_fail(c != NULL, false);

	return pattern_match(criteria->pattern, u->user);
}

static void alert_user_criteria_display(char *s, size_t size, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_if_fail(c != NULL);
	return_if_fail(c != NULL);

	snappendf(s, size, " USER");
	pattern_display(s, size, criteria->pattern);
}

alert_criteria_constructor_t alert_user_criteria = {
	alert_pattern_criteria_prepare, alert_user_criteria_exec, alert_pattern_criteria_cleanup,
	alert_user_criteria_display,
	EVT_CONNECT
};

static alert_criteria_t *alert_gecos_criteria_prepare(char **args)
{
	alert_pattern_criteria_t *criteria;
	alert_pattern_t *pattern;

	return_val_if_fail(args != NULL, NULL);
	return_val_if_fail(*args != NULL, NULL);

	pattern = pattern_extract(args, true);
	return_val_if_fail(pattern != NULL, NULL);

	criteria = smalloc(sizeof(alert_pattern_criteria_t));
	criteria->pattern = pattern;

	return (alert_criteria_t *)criteria;
}

static bool alert_gecos_criteria_exec(user_t *u, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_val_if_fail(u != NULL, false);
	return_val_if_fail(c != NULL, false);

	return pattern_match(criteria->pattern, u->gecos);
}

static void alert_gecos_criteria_display(char *s, size_t size, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_if_fail(s != NULL);
	return_if_fail(c != NULL);

	snappendf(s, size, " GECOS");
	pattern_display(s, size, criteria->pattern);
}

alert_criteria_constructor_t alert_gecos_criteria = {
	alert_gecos_criteria_prepare, alert_gecos_criteria_exec, alert_pattern_criteria_cleanup,
	alert_gecos_criteria_display,
	EVT_CONNECT
};

static bool alert_host_criteria_exec(user_t *u, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_val_if_fail(u != NULL, false);
	return_val_if_fail(c != NULL, false);

	return pattern_match(criteria->pattern, u->host);
}

static void alert_host_criteria_display(char *s, size_t size, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_if_fail(s != NULL);
	return_if_fail(c != NULL);

	snappendf(s, size, " HOST");
	pattern_display(s, size, criteria->pattern);
}

alert_criteria_constructor_t alert_host_criteria = {
	alert_pattern_criteria_prepare, alert_host_criteria_exec, alert_pattern_criteria_cleanup,
	alert_host_criteria_display,
	EVT_CONNECT | EVT_HOST
};

static bool alert_ip_criteria_exec(user_t *u, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_val_if_fail(u != NULL, false);
	return_val_if_fail(c != NULL, false);

	return pattern_match(criteria->pattern, u->ip);
}

static void alert_ip_criteria_display(char *s, size_t size, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_if_fail(s != NULL);
	return_if_fail(c != NULL);

	snappendf(s, size, " IP");
	pattern_display(s, size, criteria->pattern);
}

alert_criteria_constructor_t alert_ip_criteria = {
	alert_pattern_criteria_prepare, alert_ip_criteria_exec, alert_pattern_criteria_cleanup,
	alert_ip_criteria_display,
	EVT_CONNECT
};

static bool alert_mask_criteria_exec(user_t *u, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;
	char usermask[512];

	return_val_if_fail(u != NULL, false);
	return_val_if_fail(c != NULL, false);

	snprintf(usermask, sizeof(usermask), "%s!%s@%s", u->nick, u->user, u->host);

	return pattern_match(criteria->pattern, usermask);
}

static void alert_mask_criteria_display(char *s, size_t size, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_if_fail(s != NULL);
	return_if_fail(c != NULL);

	snappendf(s, size, " HOST");
	pattern_display(s, size, criteria->pattern);
}

alert_criteria_constructor_t alert_mask_criteria = {
	alert_pattern_criteria_prepare, alert_mask_criteria_exec, alert_pattern_criteria_cleanup,
	alert_mask_criteria_display,
	EVT_CONNECT | EVT_NICK | EVT_HOST
};

static bool alert_server_criteria_exec(user_t *u, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_val_if_fail(u != NULL, false);
	return_val_if_fail(c != NULL, false);

	return pattern_match(criteria->pattern, u->server->name);
}

static void alert_server_criteria_display(char *s, size_t size, alert_criteria_t *c)
{
	alert_pattern_criteria_t *criteria = (alert_pattern_criteria_t *)c;

	return_if_fail(s != NULL);
	return_if_fail(c != NULL);

	snappendf(s, size, " SERVER");
	pattern_display(s, size, criteria->pattern);
}

alert_criteria_constructor_t alert_server_criteria = {
	alert_pattern_criteria_prepare, alert_server_criteria_exec, alert_pattern_criteria_cleanup,
	alert_server_criteria_display,
	EVT_CONNECT
};

static alert_criteria_t *alert_identified_criteria_prepare(char **args)
{
	alert_identified_criteria_t *criteria;
	char *p;
	bool identified;

	return_val_if_fail(args != NULL, NULL);
	return_val_if_fail(*args != NULL, NULL);

	p = strtok(*args, " ");

	if (strlen(p) == 1)
		switch(toupper(*p))
		{
			case 'Y':
			case 'T':
				identified = true;
				break;

			case 'N':
			case 'F':
				identified = false;
				break;

			default:
				return NULL;
		}
	else if (!strcasecmp("YES", p) || !strcasecmp("TRUE", p))
		identified = true;

	else if (!strcasecmp("NO", p) || !strcasecmp("FALSE", p))
		identified = false;

	else
		return NULL;

	*args = strtok(NULL, "");

	criteria = smalloc(sizeof(alert_identified_criteria_t));
	criteria->identified = identified;

	return (alert_criteria_t *)criteria;
}

static bool alert_identified_criteria_exec(user_t *u, alert_criteria_t *c)
{
	alert_identified_criteria_t *criteria = (alert_identified_criteria_t *)c;

	return_val_if_fail(u != NULL, false);
	return_val_if_fail(c != NULL, false);

	return criteria->identified == (u->myuser != NULL);
}

static void alert_identified_criteria_cleanup(alert_criteria_t *c)
{
	alert_identified_criteria_t *criteria = (alert_identified_criteria_t *)c;

	return_if_fail(c != NULL);

	free(criteria);
}

static void alert_identified_criteria_display(char *s, size_t size, alert_criteria_t *c)
{
	alert_identified_criteria_t *criteria = (alert_identified_criteria_t *)c;

	return_if_fail(s != NULL);
	return_if_fail(c != NULL);

	snappendf(s, size, " IDENTIFIED %c", (criteria->identified ? 'Y' : 'N'));
}

alert_criteria_constructor_t alert_identified_criteria = {
	alert_identified_criteria_prepare, alert_identified_criteria_exec, alert_identified_criteria_cleanup,
	alert_identified_criteria_display,
	EVT_CONNECT | EVT_IDENTIFY | EVT_REGISTER | EVT_DROP
};

static alert_action_t *alert_notice_action_prepare(char **args)
{
	(void)args;
	return smalloc(sizeof(alert_action_t));
}

static void alert_notice_action_exec(user_t *u, alert_action_t *a)
{
	mowgli_node_t *node = NULL;
	myentity_t *ent = NULL;
	ssize_t index = -1;
	mowgli_list_t *owned_alerts_list = NULL;

	return_if_fail(u != NULL);
	return_if_fail(a != NULL);

	ent = myentity_find(a->alert->owner);
	return_if_fail(ent != NULL);
	return_if_fail(isuser(ent));

	owned_alerts_list = mowgli_patricia_retrieve(owned_alerts, a->alert->owner);
	return_if_fail(owned_alerts != NULL);

	index = 1 + mowgli_node_index(a->alert->owned_node, owned_alerts_list);

	myuser_notice(operserv->nick, (myuser_t *)ent, "\2Alert (%d):\2  %s!%s@%s %s {%s}", index, u->nick, u->user, u->host, u->gecos, u->server->name);
}

static void alert_notice_action_cleanup(alert_action_t *a)
{
	return_if_fail(a != NULL);

	free(a);
}

static void alert_notice_action_display(char *s, size_t len, alert_action_t *a)
{
	snappendf(s, len, "NOTICE");
}

alert_action_constructor_t alert_notice_action = {
	alert_notice_action_prepare, alert_notice_action_exec, alert_notice_action_cleanup,
	alert_notice_action_display
};

static void exec_events(user_t *u, alert_event_t event_mask);

static void user_added(hook_user_nick_t *n)
{
	return_if_fail(n != NULL);
	return_if_fail(n->u != NULL);

	if (!is_internal_client(n->u))
		exec_events(n->u, EVT_CONNECT);
}

static void user_nickchanged(hook_user_nick_t *n)
{
	return_if_fail(n != NULL);
	return_if_fail(n->u != NULL);

	if (!is_internal_client(n->u))
		exec_events(n->u, EVT_NICK);
}

static void channel_joined(hook_channel_joinpart_t *n)
{
	return_if_fail(n != NULL);
	return_if_fail(n->cu != NULL);

	if (!is_internal_client(n->cu->user))
		exec_events(n->cu->user, EVT_JOIN);
}

static void channel_parted(hook_channel_joinpart_t *n)
{
	return_if_fail(n != NULL);
	return_if_fail(n->cu != NULL);

	if (!is_internal_client(n->cu->user))
		exec_events(n->cu->user, EVT_PART);
}

static void user_registered(myuser_t *mu)
{
	mowgli_node_t *node = NULL;

	return_if_fail(mu != NULL);

	MOWGLI_LIST_FOREACH(node, mu->logins.head)
	{
		user_t *login = node->data;

		if (!is_internal_client(login))
			exec_events(login, EVT_REGISTER);
	}
}

static void user_dropped(myuser_t *mu)
{
	mowgli_node_t *node = NULL;

	return_if_fail(mu != NULL);

	MOWGLI_LIST_FOREACH(node, mu->logins.head)
	{
		user_t *login = node->data;

		if (!is_internal_client(login))
			exec_events(login, EVT_DROP);
	}
}

static void user_identified(user_t *u)
{
	return_if_fail(u != NULL);

	if (!is_internal_client(u))
		exec_events(u, EVT_IDENTIFY);
}

static void user_host_set(user_t *u)
{
	return_if_fail(u != NULL);

	if (!is_internal_client(u))
		exec_events(u, EVT_HOST);
}

/* Write an alert_t to the database. */
static void serialize(database_handle_t *db, alert_t *alert);

/* Write all alerts to the database. */
static void serialize_all(database_handle_t *db);

/* Read an alert_t from the database and add it to the list of alerts. */
static void deserialize(database_handle_t *db, const char *type);

/* Sub-command tree. */
mowgli_patricia_t *os_alert_cmds = NULL;

void _modinit(module_t *module)
{
	operserv = service_find("operserv");
	service_bind_command(operserv, &os_alert);

	alert_cmdtree = mowgli_patricia_create(strcasecanon);
	mowgli_patricia_add(alert_cmdtree, "NICK", &alert_nick_criteria);
	mowgli_patricia_add(alert_cmdtree, "USER", &alert_user_criteria);
	mowgli_patricia_add(alert_cmdtree, "GECOS", &alert_gecos_criteria);
	mowgli_patricia_add(alert_cmdtree, "HOST", &alert_host_criteria);
	mowgli_patricia_add(alert_cmdtree, "IP", &alert_ip_criteria);
	mowgli_patricia_add(alert_cmdtree, "MASK", &alert_mask_criteria);
	mowgli_patricia_add(alert_cmdtree, "SERVER", &alert_server_criteria);
	mowgli_patricia_add(alert_cmdtree, "IDENTIFIED", &alert_identified_criteria);

	alert_acttree = mowgli_patricia_create(strcasecanon);
	mowgli_patricia_add(alert_acttree, "NOTICE", &alert_notice_action);

	owned_alerts = mowgli_patricia_create(strcasecanon);

	os_alert_cmds = mowgli_patricia_create(strcasecanon);
	command_add(&os_alert_add, os_alert_cmds);
	command_add(&os_alert_del, os_alert_cmds);
	command_add(&os_alert_list, os_alert_cmds);

	hook_add_event("user_add");
	hook_add_user_add(user_added);

	hook_add_event("user_nickchange");
	hook_add_user_nickchange(user_nickchanged);

	hook_add_event("channel_join");
	hook_add_channel_join(channel_joined);

	hook_add_event("channel_part");
	hook_add_channel_part(channel_parted);

	hook_add_event("user_registered");
	hook_add_user_register(user_registered);

	hook_add_event("user_dropped");
	hook_add_user_drop(user_dropped);

	hook_add_event("user_indentified");
	hook_add_user_identify(user_identified);

	hook_add_event("user_sethost");
	hook_add_user_sethost(user_host_set);

	db_register_type_handler("ALERT", deserialize);
	hook_add_db_write(serialize_all);
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

static void owned_alerts_cleanup(const char *key, void *data, void *unused)
{
	mowgli_node_free(data);
	(void)unused;
}

void _moddeinit(module_unload_intent_t intent)
{
	service_unbind_command(operserv, &os_alert);

	mowgli_patricia_delete(alert_cmdtree, "NICK");
	mowgli_patricia_delete(alert_cmdtree, "USER");
	mowgli_patricia_delete(alert_cmdtree, "GECOS");
	mowgli_patricia_delete(alert_cmdtree, "HOST");
	mowgli_patricia_delete(alert_cmdtree, "IP");
	mowgli_patricia_delete(alert_cmdtree, "MASK");
	mowgli_patricia_delete(alert_cmdtree, "SERVER");
	mowgli_patricia_delete(alert_cmdtree, "IDENTIFIED");
	mowgli_patricia_destroy(alert_cmdtree, NULL, NULL);

	mowgli_patricia_delete(alert_acttree, "NOTICE");
	mowgli_patricia_destroy(alert_acttree, NULL, NULL);

	command_delete(&os_alert_add, os_alert_cmds);
	command_delete(&os_alert_del, os_alert_cmds);
	command_delete(&os_alert_list, os_alert_cmds);

	mowgli_patricia_destroy(os_alert_cmds, NULL, NULL);

	operserv = NULL;

	while (alerts.count != 0)
		alert_destroy(alerts.head->data);

	mowgli_patricia_destroy(owned_alerts, owned_alerts_cleanup, NULL);

	db_unregister_type_handler("ALERT");

	hook_del_user_add(user_added);
	hook_del_user_nickchange(user_nickchanged);
	
	hook_del_channel_join(channel_joined);
	hook_del_channel_part(channel_parted);

	hook_del_user_register(user_registered);
	hook_del_user_drop(user_dropped);
	hook_del_user_identify(user_identified);
	hook_del_user_sethost(user_host_set);
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

static int parse_alert(myuser_t *mu, alert_action_constructor_t *actcons, char **args)
{
	alert_action_t *action = NULL;
	alert_event_t event_mask = 0;
	alert_t *alert;

	mowgli_list_t criteria_list = { NULL, NULL, 0 };
	mowgli_list_t *owned_alerts_list = NULL;

	bool failed = false;

	return_val_if_fail(mu != NULL, -1);

	action = actcons->prepare(args);
	if (action == NULL)
		return -1;
	
	action->cons = actcons;

	/* Parse out all the criteria. */
	while (true)
	{
		alert_criteria_constructor_t *cons;
		alert_criteria_t *criteria;

		char *cmd = strtok(*args, " ");

		if (cmd == NULL)
		{
			if (criteria_list.count == 0)
				failed = true;
			break;
		}

		cons = mowgli_patricia_retrieve(alert_cmdtree, cmd);
		if (cons == NULL)
		{
			failed = true;
			break;
		}

		*args = strtok(NULL, "");
		if (args == NULL)
		{
			failed = true;
			break;

		}

		criteria = cons->prepare(args);
		slog(LG_DEBUG, "operserv/alert: adding criteria (%s) to list [remain: %s]", cmd, *args);
		if (criteria == NULL)
		{
			failed = true;
			break;
		}

		slog(LG_DEBUG, "operserv/alert: new args position [%s]", *args);

		criteria->cons = cons;
		event_mask |= cons->event_mask;

		mowgli_node_add(criteria, mowgli_node_create(), &criteria_list);
	}

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
		return -1;
	}

	alert = smalloc(sizeof(alert_t));
	alert->owner = sstrdup(entity(mu)->name);
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

	return owned_alerts_list->count;
}

static void os_cmd_alert_add(sourceinfo_t *si, int parc, char *parv[])
{
	alert_action_constructor_t *actcons = NULL;
	int id;

	if (!parv[0])
	{
		command_fail(si, fault_badparams, STR_INVALID_PARAMS, "ALERT ADD");
		command_fail(si, fault_badparams, _("Syntax: ALERT ADD <action> <params>"));
		return;
	}


	actcons = mowgli_patricia_retrieve(alert_acttree, parv[0]);
	if (actcons == NULL)
	{
		command_fail(si, fault_badparams, STR_INVALID_PARAMS, "ALERT ADD");
		command_fail(si, fault_badparams, _("Syntax: ALERT ADD <action> <params>"));
		return;
	}

	id = parse_alert(si->smu, actcons, &parv[1]);
	if (id < 0)
		command_fail(si, fault_nosuch_target, _("Invalid criteria specified."));
	else
		command_success_nodata(si, _("Added alert \x02%d\x02."), id);
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
			mowgli_node_t *criteria_node = NULL;
			char buf[512] = {0};
			alert->action->cons->display(buf, sizeof(buf), alert->action);
			MOWGLI_LIST_FOREACH(criteria_node, alert->criteria.head)
			{
				alert_criteria_t *criteria = criteria_node->data;
				alert_criteria_constructor_t *cons = criteria->cons;

				cons->display(buf, sizeof(buf), criteria);
			}

			command_success_nodata(si, "Alert %d: %s", i, buf);
			i++;
		}
		command_success_nodata(si, _("End of alerts."));
	}
}

static void exec_events(user_t *u, alert_event_t event_mask)
{
	mowgli_node_t *alert_node = NULL;

	return_if_fail(u != NULL);
	return_if_fail(event_mask != 0);

	MOWGLI_LIST_FOREACH(alert_node, alerts.head)
	{
		alert_t *alert = alert_node->data;

		if (alert->event_mask & event_mask)
		{

			bool success = true;
			mowgli_node_t *criteria_node = NULL;


			MOWGLI_LIST_FOREACH(criteria_node, alert->criteria.head)
			{
				alert_criteria_t *criteria = criteria_node->data;
				alert_criteria_constructor_t *cons = criteria->cons;

				if (!cons->exec(u, criteria))
				{
					success = false;
					break;
				}
			}

			if (success)
			{
				alert_action_constructor_t *cons = alert->action->cons;
				cons->exec(u, alert->action);
			}
		}
	}
}

static void deserialize(database_handle_t *db, const char *type)
{
	mowgli_node_t *node;
	const char *owner = db_sread_word(db);
	myuser_t *mu = myuser_find_ext(owner);
	const char *action_name = db_sread_word(db);
	alert_action_constructor_t *actcons = NULL;
	const char *args = db_sread_str(db);
	char *modified_args = NULL;

	return_if_fail(mu != NULL);

	actcons = mowgli_patricia_retrieve(alert_acttree, action_name);
	if (actcons == NULL)
		slog(LG_ERROR, "os/alert: could not parse action (%s) from db", action_name);
	else
	{
		const char *readonly_args = db_sread_str(db);
		char *args = sstrdup(readonly_args);
		char *modified_args = args;

		if (parse_alert(mu, actcons, &modified_args) < 0)
			slog(LG_ERROR, "Could not parse alert: action=(%s) args=[%s]", action_name, args);

		free(args);
	}
}

static void serialize(database_handle_t *db, alert_t *alert)
{
	mowgli_node_t *node;
	char buffer[512] = {0};
 
	db_start_row(db, "ALERT");
	db_write_word(db, alert->owner);

	alert->action->cons->display(buffer, sizeof(buffer), alert->action);

	MOWGLI_LIST_FOREACH(node, alert->criteria.head)
	{
		alert_criteria_t *criteria = node->data;
		criteria->cons->display(buffer, sizeof(buffer), criteria);
	}

	db_write_str(db, buffer);
	db_commit_row(db);
}

static void serialize_all(database_handle_t *db)
{
	mowgli_node_t *node;
	MOWGLI_LIST_FOREACH(node, alerts.head)
		serialize(db, node->data);
}
