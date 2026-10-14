@load base/protocols/conn/removal-hooks

# Copyright 2025 Battelle Energy Alliance, LLC

################################################################################
##
## ICSNPP - ANS1 C12.22
## 
## This file defines the ICSNPP ANS1 C12.22 Zeek Script as defined in the specification
## IEEE Std 1703-2012, IEEE Standard for Local Area Network/Wide Area Network 
## (LAN/WAN) Node Communication Protocol to Complement the Utility Industry 
## End Device Data Tables.
##
## Payton Harmon & Hans Peterson, Idaho National Lab, June 2025
##
################################################################################

module C1222;

export {
    ## Log stream identifier.
    redef enum Log::ID += { 
        LOG_SUMMARY_LOG,
        LOG_AUTHENTICATION_VALUE_LOG,
        LOG_USER_INFORMATION_LOG,
        LOG_IDENTIFICATION_SERVICE_LOG,
        LOG_READ_WRITE_SERVICE_LOG,
        LOG_LOGON_SERVICE_LOG,
        LOG_WAIT_SERVICE_LOG,
        LOG_DEREG_REG_SERVICE_LOG,
        LOG_RESOLVE_SERVICE_LOG,
        LOG_TRACE_SERVICE_LOG,
        LOG_SERVICE_ERROR_LOG
	};


  global log_c1222: event(rec: summary_log);
  global log_policy_summary_log: Log::PolicyHook;
  global log_authentication_value_log: event(rec: authentication_value_log);
  global log_policy_authentication_value_log: Log::PolicyHook;
  global log_user_information_log: event(rec: user_information_log);
  global log_policy_user_information_log: Log::PolicyHook;
  global log_identification_service_log: event(rec: identification_service_log);
  global log_policy_identification_service_log: Log::PolicyHook;
  global log_read_write_service_log: event(rec: read_write_service_log);
  global log_policy_read_write_service_log: Log::PolicyHook;
  global log_logon_service_log: event(rec: logon_service_log);
  global log_policy_logon_service_log: Log::PolicyHook;
  global log_wait_service_log: event(rec: wait_service_log);
  global log_policy_wait_service_log: Log::PolicyHook;
  global log_dereg_reg_service_log: event(rec: dereg_reg_service_log);
  global log_policy_dereg_reg_service_log: Log::PolicyHook;
  global log_resolve_service_log: event(rec: resolve_service_log);
  global log_policy_resolve_service_log: Log::PolicyHook;
  global log_trace_service_log: event(rec: trace_service_log);
  global log_policy_trace_service_log: Log::PolicyHook;
  global log_service_error_log: event(rec: service_error_log);
  global log_policy_service_error_log: Log::PolicyHook;
}

redef record connection += {
    c1222_proto: string &optional;
    c1222_summary_log: summary_log &optional;
    c1222_authentication_value_log: authentication_value_log &optional;
    c1222_user_information_log: user_information_log &optional;
    c1222_identification_service_log: identification_service_log &optional;
    c1222_read_write_service_log: read_write_service_log &optional;
    c1222_logon_security_service_log: logon_service_log &optional;
    c1222_wait_service_log: wait_service_log &optional;
    c1222_dereg_reg_service_log: dereg_reg_service_log &optional;
    c1222_resolve_service_log: resolve_service_log &optional;
    c1222_trace_service_log: trace_service_log &optional;
    c1222_service_error_log: service_error_log &optional;
};

export {
    const c1222_ports_tcp: set[port] = { 1153/tcp } &redef;
    const c1222_ports_udp: set[port] = { 1153/udp } &redef;
}

global c1222_ports_str: string = getenv("ZEEK_C1222_PORTS");

function add_environment_ports()
    {
    if ( c1222_ports_str == "" )
        return;

    local custom_ports = split_string(c1222_ports_str, /,/);

    for ( port_idx in custom_ports )
        {
        local port_string = strip(custom_ports[port_idx]);

        if ( /^[0-9]{1,5}\/(tcp|udp)$/ !in port_string )
            {
            Reporter::warning(fmt("Ignoring invalid ZEEK_C1222_PORTS entry '%s'; expected NUMBER/tcp or NUMBER/udp", port_string));
            next;
            }

        local port_parts = split_string(port_string, /\//);
        local port_number = to_count(port_parts[0]);

        if ( port_number > 65535 )
            {
            Reporter::warning(fmt("Ignoring out-of-range ZEEK_C1222_PORTS entry '%s'", port_string));
            next;
            }

        if ( port_parts[1] == "tcp" )
            add c1222_ports_tcp[count_to_port(port_number, tcp)];
        else
            add c1222_ports_udp[count_to_port(port_number, udp)];
        }
    }

event zeek_init() &priority=5 {
    add_environment_ports();

    for ( p in c1222_ports_tcp )
        add likely_server_ports[p];

    for ( p in c1222_ports_udp )
        add likely_server_ports[p];

    Analyzer::register_for_ports(Analyzer::ANALYZER_C1222_TCP, c1222_ports_tcp);
    Analyzer::register_for_ports(Analyzer::ANALYZER_C1222_UDP, c1222_ports_udp);

	Log::create_stream(C1222::LOG_SUMMARY_LOG, 
						[$columns=summary_log, 
						$ev=log_c1222, 
						$path="c1222", 
						$policy=log_policy_summary_log]);

	Log::create_stream(C1222::LOG_AUTHENTICATION_VALUE_LOG, 
						[$columns=authentication_value_log, 
						$ev=log_authentication_value_log, 
						$path="c1222_authentication_value", 
						$policy=log_policy_authentication_value_log]);

    Log::create_stream(C1222::LOG_USER_INFORMATION_LOG, 
						[$columns=user_information_log, 
						$ev=log_user_information_log, 
						$path="c1222_user_information", 
						$policy=log_policy_user_information_log]);

    Log::create_stream(C1222::LOG_IDENTIFICATION_SERVICE_LOG, 
						[$columns=identification_service_log, 
						$ev=log_identification_service_log, 
						$path="c1222_identification_service", 
						$policy=log_policy_identification_service_log]);

    Log::create_stream(C1222::LOG_READ_WRITE_SERVICE_LOG, 
						[$columns=read_write_service_log, 
						$ev=log_read_write_service_log, 
						$path="c1222_read_write_service", 
						$policy=log_policy_read_write_service_log]);

    Log::create_stream(C1222::LOG_LOGON_SERVICE_LOG, 
						[$columns=logon_service_log, 
						$ev=log_logon_service_log, 
						$path="c1222_logon_security_service", 
						$policy=log_policy_logon_service_log]);

    Log::create_stream(C1222::LOG_WAIT_SERVICE_LOG, 
						[$columns=wait_service_log, 
						$ev=log_wait_service_log, 
						$path="c1222_wait_service", 
						$policy=log_policy_wait_service_log]);

    Log::create_stream(C1222::LOG_DEREG_REG_SERVICE_LOG, 
						[$columns=dereg_reg_service_log, 
						$ev=log_dereg_reg_service_log, 
						$path="c1222_dereg_reg_service", 
						$policy=log_policy_dereg_reg_service_log]);

    Log::create_stream(C1222::LOG_RESOLVE_SERVICE_LOG, 
						[$columns=resolve_service_log, 
						$ev=log_resolve_service_log, 
						$path="c1222_resolve_service", 
						$policy=log_policy_resolve_service_log]);

    Log::create_stream(C1222::LOG_TRACE_SERVICE_LOG, 
						[$columns=trace_service_log, 
						$ev=log_trace_service_log, 
						$path="c1222_trace_service", 
						$policy=log_policy_trace_service_log]);

    Log::create_stream(C1222::LOG_SERVICE_ERROR_LOG, 
						[$columns=service_error_log, 
						$ev=log_service_error_log, 
						$path="c1222_service_error", 
						$policy=log_policy_service_error_log]);
}


@if (Version::at_least("5.2.2"))
event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) {
  if ( atype == Analyzer::ANALYZER_C1222_TCP ) {
    info$c$c1222_proto = "tcp";
  } else if ( atype == Analyzer::ANALYZER_C1222_UDP ) {
    info$c$c1222_proto = "udp";
  }
}
@else
event analyzer_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5 {
  if ( atype == Analyzer::ANALYZER_C1222_TCP ) {
    c$c1222_proto = "tcp";
  } else if ( atype == Analyzer::ANALYZER_C1222_UDP ) {
    c$c1222_proto = "udp";
  }
}
@endif


function emit_c1222_summary_log(c: connection) {
    if (! c?$c1222_summary_log )
        return;
    Log::write(C1222::LOG_SUMMARY_LOG, c$c1222_summary_log);
    delete c$c1222_summary_log;
}

function emit_c1222_authentication_value_log(c: connection) {
    if (! c?$c1222_authentication_value_log )
        return;
    Log::write(C1222::LOG_AUTHENTICATION_VALUE_LOG, c$c1222_authentication_value_log);
    delete c$c1222_authentication_value_log;
}

function emit_c1222_user_information_log(c: connection) {
    if (! c?$c1222_user_information_log )
        return;
    Log::write(C1222::LOG_USER_INFORMATION_LOG, c$c1222_user_information_log);
    delete c$c1222_user_information_log;
}

function emit_c1222_identification_service_log(c: connection) {
    if (! c?$c1222_identification_service_log )
        return;
    Log::write(C1222::LOG_IDENTIFICATION_SERVICE_LOG, c$c1222_identification_service_log);
    delete c$c1222_identification_service_log;
}

function emit_c1222_read_write_service_log(c: connection) {
    if (! c?$c1222_read_write_service_log )
        return;
    Log::write(C1222::LOG_READ_WRITE_SERVICE_LOG, c$c1222_read_write_service_log);
    delete c$c1222_read_write_service_log;
}

function emit_c1222_logon_security_service_log(c: connection) {
    if (! c?$c1222_logon_security_service_log )
        return;
    Log::write(C1222::LOG_LOGON_SERVICE_LOG, c$c1222_logon_security_service_log);
    delete c$c1222_logon_security_service_log;
}

function emit_c1222_wait_service_log(c: connection) {
    if (! c?$c1222_wait_service_log )
        return;
    Log::write(C1222::LOG_WAIT_SERVICE_LOG, c$c1222_wait_service_log);
    delete c$c1222_wait_service_log;
}

function emit_c1222_dereg_reg_service_log(c: connection) {
    if (! c?$c1222_dereg_reg_service_log )
        return;
    Log::write(C1222::LOG_DEREG_REG_SERVICE_LOG, c$c1222_dereg_reg_service_log);
    delete c$c1222_dereg_reg_service_log;
}

function emit_c1222_resolve_service_log(c: connection) {
    if (! c?$c1222_resolve_service_log )
        return;
    Log::write(C1222::LOG_RESOLVE_SERVICE_LOG, c$c1222_resolve_service_log);
    delete c$c1222_resolve_service_log;
}

function emit_c1222_trace_service_log(c: connection) {
    if (! c?$c1222_trace_service_log )
        return;
    Log::write(C1222::LOG_TRACE_SERVICE_LOG, c$c1222_trace_service_log);
    delete c$c1222_trace_service_log;
}

function emit_c1222_service_error_log(c: connection) {
    if (! c?$c1222_service_error_log )
        return;
    Log::write(C1222::LOG_SERVICE_ERROR_LOG, c$c1222_service_error_log);
    delete c$c1222_service_error_log;
}
