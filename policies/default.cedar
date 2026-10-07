// Sentryra Tier 1 default policy set.
// Every escalate-permit is conditioned on the mandate not denying: an escalate signal can never
// turn a mandate deny into a (human-approvable) escalation. Only these deterministic rules can produce "allow".
// @effect("escalate") on a permit means: if this permit is satisfied, the decision is escalate
// (strictest wins: deny > escalate > allow). forbid always wins.

@id("mandate-allow")
permit (principal, action, resource)
when { context.mandate_effect == "allow" };

@id("mandate-escalate")
@effect("escalate")
permit (principal, action, resource)
when { context.mandate_effect == "escalate" };

// Tools not in the signed tool catalogue are classed destructive: fail closed, escalate.
@id("uncatalogued-tool-escalate")
@effect("escalate")
permit (principal, action, resource)
when { context.in_catalogue == false && context.mandate_effect != "deny" };

// Arguments copied from untrusted tool output into a sink argument are escalated for a human.
@id("taint-sink-escalate")
@effect("escalate")
permit (principal, action, resource)
when { context.sink_tainted && context.mandate_effect != "deny" };

// SQL DDL is forbidden unless a passing mandate scope explicitly lists the DDL verb in
// sql.statement_types; even then it always needs a human.
@id("sql-forbid-ddl")
forbid (principal, action, resource)
when { context.sql.is_sql && context.sql.has_ddl && !context.sql.ddl_mandated };

@id("sql-mandated-ddl-escalate")
@effect("escalate")
permit (principal, action, resource)
when { context.sql.is_sql && context.sql.has_ddl && context.sql.ddl_mandated && context.mandate_effect != "deny" };

// SQL that does not parse fails closed.
@id("sql-forbid-unparseable")
forbid (principal, action, resource)
when { context.sql.is_sql && context.sql.parse_error };

// SQL DML (INSERT/UPDATE/DELETE) needs a human.
@id("sql-dml-escalate")
@effect("escalate")
permit (principal, action, resource)
when { context.sql.is_sql && context.sql.has_dml && context.mandate_effect != "deny" };
