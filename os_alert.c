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