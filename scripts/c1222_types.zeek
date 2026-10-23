module C1222;

export {

    # LOG OPTIONS -------------------------------------------------------------
    option log_summary = T;
    option log_authentication_value = F;
    option log_user_information = T;
    option log_identification_service = F;
    option log_read_write_service = F;
    option log_dereg_reg_service = F;
    option log_logon_service = F;
    option log_wait_service = F;
    option log_resolve_service = F;
    option log_trace_service = F;
    option log_service_error = T;


    # Record type containing the column fields of the summary c12.22 log.
    type summary_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        elements: vector of string &optional &log;
        is_encrypted_epsem: bool &optional &log;
        services: vector of string &log &optional;

        aso_context: string &optional &log;
        called_ap_title: string &optional &log;
        calling_ap_title: string &optional &log;
        calling_ae_qualifier: vector of string &optional &log;
        mechanism_name: string &optional &log;
        calling_auth_value: string &optional &log; #will list the mechanism name. Details in another log.
        called_ap_invocation_id: count &optional &log;
        calling_ap_invocation_id: count &optional &log;
    };

    # Record type containing the column fields of the summary c12.22 log.
    type authentication_value_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        authentication_mechanism: string &optional &log;
        indirect_reference: bool &optional &log;
        octet_aligned: string &optional &log;
        c1222_key_id: int &optional &log;
        c1222_iv: int &optional &log;
        c1221_ident: string &optional &log;
        c1221_req: string &optional &log;
        c1221_resp: string &optional &log;
    };

    # Record type containing the column fields of the summary c12.22 log.
    type user_information_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        indirect_reference_encoding: int &optional &log;
        padding: string &optional &log;
        mac: string &optional &log;
        epsem_control: vector of string &optional &log;
        ed_class: string &optional &log;
        encrypted_epsem: string &optional &log;
        services: vector of string &optional &log;
    };

    #Record type containing the column fields of the Identification service c12.22 log.
    type identification_service_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        req_resp: string &optional &log;
        standard: string &optional &log;
        version: int &optional &log;
        revision: int &optional &log;
        security_mechanism: string &optional &log;
        nbr_session_supported: bool &optional &log;
        sessionless_supported: bool &optional &log;
        device_class: string &optional &log;
        device_identity_format: int &optional &log;
        device_identity: string &optional &log;
    };

    #Record type containing the column fields of the Read Write service c12.22 log.
    type read_write_service_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        req_resp: string &optional &log;
        service_type: string &optional &log;
        table_id: int &optional &log;
        offset: count &optional &log;
        index: string &optional &log;
        element_count: int &optional &log;
        count_m: vector of int &optional &log;
        data: vector of string &optional &log;
        chksum: vector of int &optional &log;
        octet_count: int &optional &log;
    };

    #Record type containing the column fields of the Logon and Security service c12.22 log.
    type logon_service_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        req_resp: string &optional &log;
        service_type: string &optional &log;
        user_id: int &optional &log;
        password: string &optional &log;
        user: string &optional &log;
        session_idle_timeout: int &optional &log;
    };

    #Record type containing the column fields of the Wait service c12.22 log.
    type wait_service_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        req_resp: string &optional &log;
        time_s: int &optional &log;
    };

    #Record type containing the column fields of the (de)registration service c12.22 log.
    type dereg_reg_service_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        req_resp: string &optional &log;
        service_type: string &optional &log;
        node_type: vector of string &optional &log;
        connection_type: vector of string &optional &log;
        device_class: string &optional &log;
        ap_title: string &optional &log;
        electronic_serial_number: string &optional &log;
        native_address: string &optional &log;
        notification_pattern: string &optional &log;
        reg_period: count &optional &log;
        reg_delay: int &optional &log;
        reg_info: vector of string &optional &log;
    };

    #Record type containing the column fields of the resolve service c12.22 log.
    type resolve_service_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        req_resp: string &optional &log;
        ap_title: string &optional &log;
        local_address: string &optional &log;
    };

    #Record type containing the column fields of the trace service c12.22 log.
    type trace_service_log : record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        req_resp: string &optional &log;
        ap_titles: vector of string &optional &log;
    };

    #Record type containing the column fields of the service error c12.22 log.
    type service_error_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        service: string &optional &log;
        error_code: string &optional &log;
        rqtl_max_request_size: int &optional &log;
        rstl_max_response_size: int &optional &log;
        sigerr_resp: string &optional &log;
    };


}