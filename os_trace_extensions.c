/*
 * Copyright (c) 2014 Barret Rennie <barret@brennie.ca>
 * Portions copyright (c) 2010 William Pitcock <nenolod@atheme.org>
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Extra criteria and actions for the os_trace module.
 */

#include "atheme-compat.h"

DECLARE_MODULE_V1
(
	"contrib/os_trace_extensions", false, _modinit, _moddeinit,
	"v0.1",
	"Barret Rennie <barret@brennie.ca>"
);

typedef struct {
	void /*trace_query_domain_t */ *(*prepare)(char **args);
	bool (*exec)(user_t *u, void /* trace_query_domain_t */ *q);
	void (*cleanup)(void /* trace_query_domain_t */ *q);
} trace_query_constructor_t;

typedef struct {
	trace_query_constructor_t *cons;
	mowgli_node_t node;
} trace_query_domain_t;

typedef struct {
	trace_query_domain_t domain;
	char *pattern;
} trace_query_glob_field_domain_t;

static void *trace_glob_field_prepare(char **args)
{
	trace_query_glob_field_domain_t *domain;

	return_val_if_fail(args != NULL, NULL);
	return_val_if_fail(*args != NULL, NULL);

	domain = scalloc(sizeof(trace_query_glob_field_domain_t), 1);
	domain->pattern = strtok(*args, " ");
	*args = strtok(NULL, "");

	return domain;
}

static void *trace_gecos_prepare(char **args)
{
	trace_query_glob_field_domain_t *domain = NULL;
	char *pattern = NULL;

	return_val_if_fail(args != NULL, NULL);
	return_val_if_fail(*args != NULL, NULL);

	if (**args == '"')
	{
		pattern = strtok(*args + 1, "\"");
		return_val_if_fail(pattern != NULL, NULL);
	}
	else
		pattern = strtok(*args, " ");
	

	*args = strtok(NULL, "");

	domain = scalloc(sizeof(trace_query_glob_field_domain_t), 1);
	domain->pattern = pattern;

	slog(LG_DEBUG, "PATTERN: %s", pattern);

	return domain;
}


static void trace_glob_field_cleanup(void *q)
{
	trace_query_glob_field_domain_t *domain = (trace_query_glob_field_domain_t *)q;

	return_if_fail(domain != NULL);

	free(domain);
}

/* Do the common NULL checks for all glob-field queries and return the domain
 * if they pass. Otherwise, return NULL. */
static trace_query_glob_field_domain_t *trace_glob_field_exec(user_t *u, void *q)
{
	trace_query_glob_field_domain_t *domain = (trace_query_glob_field_domain_t *)q;

	return_val_if_fail(domain != NULL, NULL);
	return_val_if_fail(u != NULL, NULL);
	return_val_if_fail(domain->pattern != NULL, NULL);

	return domain;
}

static bool trace_account_exec(user_t *u, void *q)
{
	trace_query_glob_field_domain_t *domain = trace_glob_field_exec(u, q);
	mowgli_node_t *node = NULL;

	return_val_if_fail(domain != NULL, false);

	if (u->myuser == NULL)
		return false;

	MOWGLI_LIST_FOREACH(node, u->myuser->nicks.head)
	{
		myuser_name_t *username = (myuser_name_t *)node->data;

		if (!match(domain->pattern, username->name))
			return true;
	}

	return false;
}

static bool trace_gecos_exec(user_t *u, void *q)
{
	trace_query_glob_field_domain_t *domain = trace_glob_field_exec(u, q);

	return_val_if_fail(domain != NULL, false);

	return !match(domain->pattern, u->gecos);
}

static bool trace_host_exec(user_t *u, void *q)
{
	trace_query_glob_field_domain_t *domain = trace_glob_field_exec(u, q);

	return_val_if_fail(domain != NULL, false);

	return !match(domain->pattern, u->host);
}

static bool trace_ip_exec(user_t *u, void *q)
{
	trace_query_glob_field_domain_t *domain = trace_glob_field_exec(u, q);

	return_val_if_fail(domain != NULL, false);

	return !match(domain->pattern, u->ip);
}

static bool trace_nick_exec(user_t *u, void *q)
{
	trace_query_glob_field_domain_t *domain = trace_glob_field_exec(u, q);

	return_val_if_fail(domain != NULL, false);

	return !match(domain->pattern, u->nick);
}

static bool trace_user_exec(user_t *u, void *q)
{
	trace_query_glob_field_domain_t *domain = trace_glob_field_exec(u, q);

	return_val_if_fail(domain != NULL, false);
	
	return !match(domain->pattern, u->user);
}

trace_query_constructor_t trace_account = { trace_glob_field_prepare, trace_account_exec, trace_glob_field_cleanup };
trace_query_constructor_t trace_gecos = { trace_gecos_prepare, trace_gecos_exec, trace_glob_field_cleanup };
trace_query_constructor_t trace_host = { trace_glob_field_prepare, trace_host_exec, trace_glob_field_cleanup };
trace_query_constructor_t trace_ip = { trace_glob_field_prepare, trace_ip_exec, trace_glob_field_cleanup };
trace_query_constructor_t trace_nick = { trace_glob_field_prepare, trace_nick_exec, trace_glob_field_cleanup };
trace_query_constructor_t trace_user = { trace_glob_field_prepare, trace_user_exec, trace_glob_field_cleanup };

mowgli_patricia_t **trace_cmdtree = NULL;

void _modinit(module_t *m)
{
	if (!module_find_published("contrib/os_trace"))
	{
		slog(LG_ERROR, "modules/contrib/os_trace_extensions requires modules/contrib/os_trace");
		slog(LG_ERROR, "either load that module first or remove this module from your atheme.conf");

		m->mflags = MODTYPE_FAIL;
		return;
	}

	MODULE_TRY_REQUEST_DEPENDENCY(m, "contrib/os_trace");
	MODULE_TRY_REQUEST_SYMBOL(m, trace_cmdtree, "contrib/os_trace", "trace_cmdtree");

	mowgli_patricia_add(*trace_cmdtree, "ACCOUNT", &trace_account);
	mowgli_patricia_add(*trace_cmdtree, "GECOS", &trace_gecos);
	mowgli_patricia_add(*trace_cmdtree, "HOST", &trace_host);
	mowgli_patricia_add(*trace_cmdtree, "IP", &trace_ip);
	mowgli_patricia_add(*trace_cmdtree, "NICK", &trace_nick);
	mowgli_patricia_add(*trace_cmdtree, "USER", &trace_user);
}

void _moddeinit(module_unload_intent_t intent)
{
	mowgli_patricia_delete(*trace_cmdtree, "ACCOUNT");
	mowgli_patricia_delete(*trace_cmdtree, "GECOS");
	mowgli_patricia_delete(*trace_cmdtree, "HOST");
	mowgli_patricia_delete(*trace_cmdtree, "IP");
	mowgli_patricia_delete(*trace_cmdtree, "NICK");
	mowgli_patricia_delete(*trace_cmdtree, "USER");
	trace_cmdtree = NULL;
}	
