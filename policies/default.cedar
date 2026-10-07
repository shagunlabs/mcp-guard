// Sentryra Tier 1 default policy set. Only these deterministic rules can produce "allow".
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
when { context.sink_tainted };

// SQL: no DDL, ever, through the agent path.
@id("sql-forbid-ddl")
forbid (principal, action, resource)
when { context.sql.is_sql && context.sql.has_ddl };

// SQL that does not parse fails closed.
@id("sql-forbid-unparseable")
forbid (principal, action, resource)
when { context.sql.is_sql && context.sql.parse_error };

// SQL DML (INSERT/UPDATE/DELETE) needs a human.
@id("sql-dml-escalate")
@effect("escalate")
permit (principal, action, resource)
when { context.sql.is_sql && context.sql.has_dml };
