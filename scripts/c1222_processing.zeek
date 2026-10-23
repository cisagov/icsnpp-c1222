module C1222;

# LOG HOOKS -------------------------------------------------------------

hook set_session_summary_log(c: connection) {
    if ( ! c?$c1222_summary_log )
        c$c1222_summary_log = summary_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_authentication_value_log(c: connection) {
    if ( ! c?$c1222_authentication_value_log )
        c$c1222_authentication_value_log = authentication_value_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_user_information_log(c: connection) {
    if ( ! c?$c1222_user_information_log )
        c$c1222_user_information_log = user_information_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_identification_service_log(c: connection) {
    if (! c?$c1222_identification_service_log)
        c$c1222_identification_service_log = identification_service_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_read_write_service_log(c: connection) {
    if (! c?$c1222_read_write_service_log)
        c$c1222_read_write_service_log = read_write_service_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_dereg_reg_service_log(c: connection) {
    if (! c?$c1222_dereg_reg_service_log)
        c$c1222_dereg_reg_service_log = dereg_reg_service_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_logon_service_log(c: connection) {
    if (! c?$c1222_logon_security_service_log)
        c$c1222_logon_security_service_log = logon_service_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_wait_service_log(c: connection) {
    if (! c?$c1222_wait_service_log)
        c$c1222_wait_service_log = wait_service_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_resolve_service_log(c: connection) {
    if (! c?$c1222_resolve_service_log)
        c$c1222_resolve_service_log = resolve_service_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_trace_service_log(c: connection) {
    if (! c?$c1222_trace_service_log)
        c$c1222_trace_service_log = trace_service_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_service_error_log(c: connection) {
    if (! c?$c1222_service_error_log)
        c$c1222_service_error_log = service_error_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

# HELP FUNCTIONS -------------------------------------------------------------

function getIdString(ID: Zeek_C1222::ID): string{
    local tag = ID$tag;
    local returnVal: string;
    switch tag {
        case C1222_ENUMS::IdentifierTags_UNIVERSAL:
            returnVal = ID$universalAptitleId$oidstring;
            break;
        case C1222_ENUMS::IdentifierTags_RELATIVE:
            returnVal = ID$relativeAptitleId$oidstring;
            break;
    }
    return returnVal;
}

function getServiceVectorLog(services: vector of Zeek_C1222::EpsemService): vector of string {
    local service_vector: vector of string;

    for (i, item in services) {
        service_vector += C1222_ENUMS::REQUEST_RESPONSE_CODES[item$service$serviceTag];
    }

    return service_vector;
}

# Convert the content bytes of an ASN.1 INTEGER (an AP invocation ID) to its value, read as big-endian
# unsigned to match Wireshark's c1222.*_AP_invocation_id fields. bytestring_to_count() only accepts 1, 2, 4
# or 8 byte strings, so the bytes are accumulated one at a time to handle any length up to 8.
function getInvocationId(id: string): count {
    local result: count = 0;

    for ( b in id )
        result = result * 256 + bytestring_to_count(b);

    return result;
}

# SUMMARY LOG -------------------------------------------------------------

event C1222::AscePdu(c: connection, is_orig: bool, ascepdu: Zeek_C1222::AscePdu) {
    hook set_session_summary_log(c);

    local info_summary_log = c$c1222_summary_log;

    #elements
    local element_vector: vector of string;

    for (i,element in ascepdu$elements){

        element_vector += C1222_ENUMS::ASCE_ELEMENT_TAGS[element$tag];

        switch element$tag {
            case C1222_ENUMS::AsceElementTags_APPLICATION_CONTEXT:
                local ASOID = element$applicationContext$asoContext;
                info_summary_log$aso_context = getIdString(ASOID);
                break;
            case C1222_ENUMS::AsceElementTags_CALLED_AP_TITLE:
                local calledApTitle = element$calledApTitle$apTitle;
                info_summary_log$called_ap_title = getIdString(calledApTitle);
                break;
            case C1222_ENUMS::AsceElementTags_CALLED_AP_INVOCATION_ID:
                if ( 0 < |element$calledApInvocationId$id| && |element$calledApInvocationId$id| <= 8 )
                    info_summary_log$called_ap_invocation_id = getInvocationId(element$calledApInvocationId$id);
                break;
            case C1222_ENUMS::AsceElementTags_CALLING_AP_TITLE:
                local callingApTitle = element$callingApTitle$apTitle;
                info_summary_log$calling_ap_title = getIdString(callingApTitle);
                break;
            case C1222_ENUMS::AsceElementTags_CALLING_APPLICATION_ENTITY_QUALIFIER:
                local qualifier_element: vector of string;
                local qualifier = element$callingApplicationEntityQualifier$callingAeQualifier;

                if(qualifier$TEST == T){
                    qualifier_element += "TEST";
                }
                if(qualifier$URGENT == T){
                    qualifier_element += "URGENT";
                }
                if(qualifier$NOTIFICATION == T){
                    qualifier_element += "NOTIFICATION";
                }
                if(qualifier?$RESERVED){
                    qualifier_element += fmt("RESERVED int:%s", qualifier$RESERVED);
                }

                info_summary_log$calling_ae_qualifier = qualifier_element;

                break;
            case C1222_ENUMS::AsceElementTags_CALLING_AP_INVOCATION_ID:
                if ( 0 < |element$callingApInvocationId$id| && |element$callingApInvocationId$id| <= 8 )
                    info_summary_log$calling_ap_invocation_id = getInvocationId(element$callingApInvocationId$id);
                break;
            case C1222_ENUMS::AsceElementTags_CALLING_AUTHENTICATION_VALUE:
                local authValueTag = element$callingAuthenticationValue$encodingTag;
                info_summary_log$calling_auth_value = C1222_ENUMS::ENCODING_TAGS[authValueTag];
                if (authValueTag == C1222_ENUMS::EncodingTags_ASN1){
                    local mechanismTag = element$callingAuthenticationValue$singleAsn1$mechanismTag;
                    info_summary_log$calling_auth_value = C1222_ENUMS::ENCODING_ASN1_TAGS[mechanismTag];
                }
                break;
            case C1222_ENUMS::AsceElementTags_MECHANISM_NAME:
                info_summary_log$mechanism_name = element$mechanismName$name$oidstring;
                break;
            default:
                break;
        }
    }

    info_summary_log$elements = element_vector;

    #encypted epsem
    local elementcount = |ascepdu$elements|;
    local securityMode = ascepdu$elements[elementcount -1]$userInformation$epsem$epsemControl$securityMode;

    if(securityMode == 2){
        info_summary_log$is_encrypted_epsem = T;
    }
    else{
        info_summary_log$is_encrypted_epsem = F;
    }

    #service codes
    if(ascepdu$elements[elementcount -1]$userInformation$epsem?$data){
        local services = ascepdu$elements[elementcount -1]$userInformation$epsem$data$data;
        local service_vector_log = getServiceVectorLog(services);

        info_summary_log$services = service_vector_log;
    }
    
}

# CALLING AUTH VALUE LOG -------------------------------------------------------------

event C1222::CallingAuthenticationValue(c: connection, is_orig: bool, callingauthenticationvalue: Zeek_C1222::CallingAuthenticationValue) {
	hook set_authentication_value_log(c);

    local auth_value_log = c$c1222_authentication_value_log;
    local auth_value = callingauthenticationvalue;

    #indirect ref
    if(auth_value$indirectReference?$c && auth_value$indirectReference$c == 0x00){
        auth_value_log$indirect_reference = T;
    }
    else{
        auth_value_log$indirect_reference = F;
    }

    #authentication_mechanism
    local authValueTag = auth_value$encodingTag;
    if(authValueTag == C1222_ENUMS::EncodingTags_OCTET){
        auth_value_log$authentication_mechanism = "OCTET_ALINGED";
        auth_value_log$octet_aligned = auth_value$octetAligned$octets;
    }
    else if (authValueTag == C1222_ENUMS::EncodingTags_ASN1){
        local mechanismTag = auth_value$singleAsn1$mechanismTag;
        if(mechanismTag == C1222_ENUMS::EncodingASN1Tags_C1222){
            auth_value_log$authentication_mechanism = "C12.22";
            auth_value_log$c1222_key_id = auth_value$singleAsn1$c1222Encoding$keyId$keyId;
            auth_value_log$c1222_iv = auth_value$singleAsn1$c1222Encoding$iv$iv;
        }
        else if(mechanismTag == C1222_ENUMS::EncodingASN1Tags_C1221){
            auth_value_log$authentication_mechanism = "C12.21";
            if(auth_value$singleAsn1$c1221Encoding$msg == C1222_ENUMS::EncodingC1221Tags_IDENT){
                auth_value_log$c1221_ident = auth_value$singleAsn1$c1221Encoding$authIdent$authService;
            }
            if(auth_value$singleAsn1$c1221Encoding$msg == C1222_ENUMS::EncodingC1221Tags_REQUEST){
                auth_value_log$c1221_req = auth_value$singleAsn1$c1221Encoding$authReq$authReq;
            }
            if(auth_value$singleAsn1$c1221Encoding$msg == C1222_ENUMS::EncodingC1221Tags_RESPONSE){
                auth_value_log$c1221_resp = auth_value$singleAsn1$c1221Encoding$authResp$authResp;
            }
        }
        else{
            auth_value_log$authentication_mechanism = "UNIMPLEMENTED";
        }
    }
    else{
        auth_value_log$authentication_mechanism = "UNKNOWN";
    }

}

# USER INFORMATION LOG -------------------------------------------------------------

event C1222::UserInformation(c: connection, is_orig: bool, userinformation: Zeek_C1222::UserInformation) {
    hook set_user_information_log(c);

    local user_info_log = c$c1222_user_information_log;
    local user_info_value = userinformation;

    if (user_info_value$indirectReference?$encoding) {
        user_info_log$indirect_reference_encoding = user_info_value$indirectReference$encoding;
    }

    if(user_info_value?$footer){
        if(user_info_value$footer?$padding){
            user_info_log$padding = user_info_value$footer$padding;
        }
        if(user_info_value$footer?$mac){
            user_info_log$mac = user_info_value$footer$mac;
        }
    }

    local epsem_ctr = userinformation$epsem$epsemControl;
    local epsem_ctr_str: vector of string;

    if(epsem_ctr$responseControl == 0){
        epsem_ctr_str += "RESPONSE_CONTROL_ALWAYS_RESPOND";
    }
    else if(epsem_ctr$responseControl == 1) {
        epsem_ctr_str += "RESPONSE_CONTROL_RESPOND_ON_EXCEPTION";
    }
    else if(epsem_ctr$responseControl == 2) {
        epsem_ctr_str += "RESPONSE_CONTROL_NEVER_RESPOND";
    }

    if(epsem_ctr$securityMode == 0){
        epsem_ctr_str += "SECURITY_MODE_CLEARTEXT";
    }
    else if(epsem_ctr$securityMode == 1){
        epsem_ctr_str += "SECURITY_MODE_CLEARTEXT_WITH_AUTHENTICATION";
    }
    else if(epsem_ctr$securityMode == 2){
        epsem_ctr_str += "SECURITY_MODE_CIPHERTEXT_WITH_AUTHENTICATION";
    }

    if(epsem_ctr$edClassIncluded == 1){
        epsem_ctr_str += "ED_CLASS_INCLUDED";
    }
    if(epsem_ctr$proxyServiceUsed == 1){
        epsem_ctr_str += "PROXY_SERVICE_USED";
    }
    if(epsem_ctr$recoverySession == 1){
        epsem_ctr_str += "RECOVERY_SESSION";
    }

    user_info_log$epsem_control = epsem_ctr_str;

    #ed class
    local edClassIncluded = user_info_value$epsem$epsemControl$edClassIncluded;

    if (edClassIncluded == 1) {
        user_info_log$ed_class = user_info_value$epsem$edClass;
    }

    #encypted epsem or services
    local securityMode = user_info_value$epsem$epsemControl$securityMode;

    if(securityMode == 2) { # it is encrypted
        user_info_log$encrypted_epsem = user_info_value$epsem$encryptedEpsem;
        #user_info_log$services = ; # can't get services unless decrypted
    }
    else {
        local services = user_info_value$epsem$data$data;
        user_info_log$services = getServiceVectorLog(services);
    }
}

# IDENT SERVICE RESPONSE -------------------------------------------------------------
event C1222::ResponseOkIdent(c: connection, is_orig: bool, ident: Zeek_C1222::ResponseOkIdent) {
    hook set_identification_service_log(c);

    local ident_log = c$c1222_identification_service_log;
    ident_log$req_resp = "Resp";
    
    #std
    local std_tag = ident$std;
    switch std_tag {
        case 0x00:
            ident_log$standard = "ANSI C12.18";
            break;
        case 0x01:
            ident_log$standard = "RESERVED";
            break;
        case 0x02:
            ident_log$standard = "ANSI C12.21";
            break;
        case 0x03:
            ident_log$standard = "ANSI C12.22";
            break;
        default:
            ident_log$standard = "RESERVED";
            break;
    }

    #version
    ident_log$version = ident$ver;
    #revision
    ident_log$revision = ident$rev;

    #features
    for (i,feature in ident$features){
        local feature_tag = feature$tag;
        switch feature_tag {
            case C1222_ENUMS::IdentFeatureTags_EOL:
                break;
            case C1222_ENUMS::IdentFeatureTags_SECURITY_MECHANISM:
                ident_log$security_mechanism = getIdString(feature$securityMechanism);
                break;
            case C1222_ENUMS::IdentFeatureTags_SESSION_CTRL:
                if(feature$sessionCtrl$sessionCtrl$nbrSessionSupported == 0){
                    ident_log$nbr_session_supported = F;
                }
                else{
                    ident_log$nbr_session_supported = T;
                }
                ident_log$sessionless_supported = feature$sessionCtrl$sessionCtrl$sessionlessSupported;
                break;
            case C1222_ENUMS::IdentFeatureTags_DEVICE_CLASS:
                ident_log$device_class = getIdString(feature$deviceClass);
                break;
            case C1222_ENUMS::IdentFeatureTags_DEVICE_IDENTITY:
                ident_log$device_identity_format = feature$deviceIdentity$format;
                ident_log$device_identity = feature$deviceIdentity$identification;
                break;                
        }
    }

}

# LOGON LOG -------------------------------------------------------------
#Logon Req
event C1222::LogonReq(c: connection, is_orig: bool, req: Zeek_C1222::LogonReq) {
    hook set_logon_service_log(c);

    local logon_log = c$c1222_logon_security_service_log;
    logon_log$req_resp = "Req";
    logon_log$service_type = "Logon";
    logon_log$user_id = req$userid;
    logon_log$user = req$user;
    logon_log$session_idle_timeout = req$reqSessionTimeout;
}

#Logon Resp
event C1222::LogonResp(c: connection, is_orig: bool, resp: Zeek_C1222::LogonResp) {
    hook set_logon_service_log(c);

    local logon_log = c$c1222_logon_security_service_log;
    logon_log$req_resp = "Resp";
    logon_log$service_type = "Logon";
    logon_log$session_idle_timeout = resp$respSessionTimeout;
}

#Security Req
event C1222::SecurityReq(c: connection, is_orig: bool, req: Zeek_C1222::SecurityReq) {
    hook set_logon_service_log(c);

    local logon_log = c$c1222_logon_security_service_log;
    logon_log$req_resp = "Req";
    logon_log$service_type = "Security";
    logon_log$password = req$password;

    if (req?$userid) {
        logon_log$user_id = req$userid;
    }
}

# READ / WRITE SERVICE EVENTS -------------------------------------------------------------

#ReadReqPRead
event C1222::ReadReqPRead(c: connection, is_orig: bool, req: Zeek_C1222::ReadReqPRead) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Req";
    read_write_log$service_type = "pread";
    read_write_log$table_id = req$tableid;

    # Display indices with decimals in between, ex: 3.1.1
    local index_str = "";
    for (i,indexN in req$index) {
        if (i > 0) {
            index_str += ".";
        }

        index_str += cat(indexN);
    }

    read_write_log$index = index_str;
    read_write_log$element_count = req$elementCount;
}

#ReadReqPReadOffset
event C1222::ReadReqPReadOffset(c: connection, is_orig: bool, req: Zeek_C1222::ReadReqPReadOffset) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Req";
    read_write_log$service_type = "pread-offset";
    read_write_log$table_id = req$tableid;
    read_write_log$offset = bytestring_to_count(req$offset);
    read_write_log$octet_count = req$octetCount;
}

#ReadRespOk
event C1222::ReadRespOk(c: connection, is_orig: bool, resp: Zeek_C1222::ReadRespOk) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Resp";
    read_write_log$service_type = "readresp-ok";

    local count_m_vector: vector of int;
    local data_vector: vector of string;
    local cksum_vector: vector of int;

    for (i,tableM in resp$tables) {
        count_m_vector += tableM$count_m;
        data_vector += tableM$data;
        cksum_vector += tableM$cksum;
    }

    if(resp?$extratables){
        for (i,extraTable in resp$extratables) {
            count_m_vector += extraTable$count_m;
            data_vector += extraTable$data;
            cksum_vector += extraTable$cksum;
        }
    }

    read_write_log$count_m = count_m_vector;
    read_write_log$data = data_vector;
    read_write_log$chksum = cksum_vector;
}

#WriteReqFull
event C1222::WriteReqFull(c: connection, is_orig: bool, req: Zeek_C1222::WriteReqFull) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Req";
    read_write_log$service_type = "full-write";
    read_write_log$table_id = req$tableid;


    local count_m_vector: vector of int;
    local data_vector: vector of string;
    local cksum_vector: vector of int;
    local tableVal = req$table_m;
    count_m_vector += tableVal$count_m;
    data_vector += tableVal$data;
    cksum_vector += tableVal$cksum;

    if (tableVal$count_m == 0xFFFF) { # extra table is valid
        local extraTable = req$extra;

        count_m_vector += extraTable$count_m;
        data_vector += extraTable$data;
        cksum_vector += extraTable$cksum; # TODO: Is adding the checksum acceptable here?
    }

    read_write_log$count_m = count_m_vector;
    read_write_log$data = data_vector;
    read_write_log$chksum = cksum_vector;
}

#WriteReqPWrite
event C1222::WriteReqPWrite(c: connection, is_orig: bool, req: Zeek_C1222::WriteReqPWrite) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Req";
    read_write_log$service_type = "pwrite";
    read_write_log$table_id = req$tableid;

    # Display indices with decimals in between, ex: 3.1.1
    local index_str = "";
    for (i,indexN in req$index) {
        if (i > 0) {
            index_str += ".";
        }

        index_str += cat(indexN);
    }

    read_write_log$index = index_str;

    local count_m_vector: vector of int;
    local data_vector: vector of string;
    local cksum_vector: vector of int;
    
    local tableVal = req$table_m;
    count_m_vector += tableVal$count_m;
    data_vector += tableVal$data;
    cksum_vector += tableVal$cksum;
    
    read_write_log$count_m = count_m_vector;
    read_write_log$data = data_vector;
    read_write_log$chksum = cksum_vector;
}

#WriteReqOffset
event C1222::WriteReqOffset(c: connection, is_orig: bool, req: Zeek_C1222::WriteReqOffset) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Req";
    read_write_log$service_type = "pwrite-offset";
    read_write_log$table_id = req$tableid;
    read_write_log$offset = bytestring_to_count(req$offset); 
    
    local count_m_vector: vector of int;
    local data_vector: vector of string;
    local cksum_vector: vector of int;

    local tableVal = req$table_m;
    count_m_vector += tableVal$count_m;
    data_vector += tableVal$data;
    cksum_vector += tableVal$cksum;

    read_write_log$count_m = count_m_vector;
    read_write_log$data = data_vector;
    read_write_log$chksum = cksum_vector;
}

# DEREGISTER / REGISTER SERVICE LOGS ------------------------------------------------------

event C1222::RegisterReq(c: connection, is_orig: bool, req: Zeek_C1222::RegisterReq) {
    hook set_dereg_reg_service_log(c);

    local dereg_reg_log = c$c1222_dereg_reg_service_log;
    dereg_reg_log$req_resp = "Req";
    dereg_reg_log$service_type = "register_req";

    local node_type = req$nodetype;
    local node_type_str: vector of string;

    if(node_type$relay == 1){
        node_type_str += "RELAY";
    }
    if(node_type$masterRelay == 1){
        node_type_str += "MASTER_RELAY";
    }
    if(node_type$host == 1){
        node_type_str += "HOST";
    }
    if(node_type$notificationHost == 1){
        node_type_str += "NOTIFICATION_HOST";
    }
    if(node_type$authenticationHost == 1){
        node_type_str += "AUTHENTICATION_HOST";
    }
    if(node_type$endDevice == 1){
        node_type_str += "END_DEVICE";
    }
    if(node_type$reserved == 1){
        node_type_str += "RESERVED";
    }
    if(node_type$myDomainPatternFlag == 1){
        node_type_str += "MY_DOMAIN_PATTERN_FLAG";
    }

    dereg_reg_log$node_type = node_type_str;

    local connection_type = req$connectiontype;
    local connection_type_str: vector of string;

    if(connection_type$broadcastAndMulticast == 1){
        connection_type_str += "BROADCAST_AND_MULTICAST";
    }
    if(connection_type$messageAcceptWindow == 1){
        connection_type_str += "MESSAGE_ACCEPT_WINDOW";
    }
    if(connection_type$playbackRejection == 1){
        connection_type_str += "PLAYBACK_REJECTION";
    }
    if(connection_type$reserved == 1){
        connection_type_str += "RESERVED";
    }
    if(connection_type$connectionlessMode == 1){
        connection_type_str += "CONNECTIONLESS_MODE";
    }
    if(connection_type$acceptConnectionless == 1){
        connection_type_str += "ACCEPT_CONNECTIONLESS";
    }
    if(connection_type$connectionMode == 1){
        connection_type_str += "CONNECTION_MODE";
    }
    if(connection_type$acceptConnections == 1){
        connection_type_str += "ACCEPT_CONNECTIONS";
    }

    dereg_reg_log$connection_type = connection_type_str;
    dereg_reg_log$device_class = req$deviceClass$oidstring;
    dereg_reg_log$ap_title = getIdString(req$apTitle);
    dereg_reg_log$electronic_serial_number = getIdString(req$electronicSerialNumber);
    dereg_reg_log$native_address = req$nativeAddress;
    dereg_reg_log$reg_period = bytestring_to_count(req$registrationPeriod);
    dereg_reg_log$notification_pattern = req$myDomainPattern$notifPattern;
}

event C1222::RegisterRespOk(c: connection, is_orig: bool, resp: Zeek_C1222::RegisterRespOk) {
    hook set_dereg_reg_service_log(c);

    local dereg_reg_log = c$c1222_dereg_reg_service_log;
    dereg_reg_log$req_resp = "Resp";
    dereg_reg_log$service_type = "register_resp_ok";

    dereg_reg_log$ap_title = getIdString(resp$apTitle);
    dereg_reg_log$reg_delay = resp$regDelay;
    dereg_reg_log$reg_period = bytestring_to_count(resp$regPeriod);

    local reg_info = resp$regInfo;
    local reg_info_str: vector of string;

    if(reg_info$directMessagingAvailable == 1){
        reg_info_str += "DIRECT_MESSAGING_AVAILABLE";
    }
    if(reg_info$messageAcceptanceWindowMode == 1){
        reg_info_str += "MESSAGE_ACCEPTANCE_WINDOW_MODE";
    }
    if(reg_info$playbackRejectionMode == 1){
        reg_info_str += "PLAYBACK_REJECTION_MODE";
    }
    if(reg_info$reserved == 1){
        reg_info_str += "RESERVED";
    }
    if(reg_info$connectionlessMode == 1){
        reg_info_str += "CONNECTIONLESS_MODE";
    }
    if(reg_info$acceptConnectionless == 1){
        reg_info_str += "ACCEPT_CONNECTIONLESS";
    }
    if(reg_info$connectionMode == 1){
        reg_info_str += "CONNECTION_MODE";
    }
    if(reg_info$acceptConnections == 1){
        reg_info_str += "ACCEPT_CONNECTIONS";
    }

    dereg_reg_log$reg_info = reg_info_str;
}

event C1222::DeregisterReq(c: connection, is_orig: bool, req: Zeek_C1222::DeregisterReq) {
    hook set_dereg_reg_service_log(c);

    local dereg_reg_log = c$c1222_dereg_reg_service_log;
    dereg_reg_log$req_resp = "Req";
    dereg_reg_log$service_type = "deregister_req";
    dereg_reg_log$ap_title = getIdString(req$apTitle);
}

# WAIT SERVICE LOG ------------------------------------------------------
#Wait Req
event C1222::WaitReq(c: connection, is_orig: bool, req: Zeek_C1222::WaitReq) {
    hook set_wait_service_log(c);

    local wait_log = c$c1222_wait_service_log;
    wait_log$req_resp = "Req";
    wait_log$time_s = req$timeis;
}

# RESOLVE SERVICE LOG ------------------------------------------------------
event C1222::ResolveReq(c: connection, is_orig: bool, req: Zeek_C1222::ResolveReq) {

    hook set_resolve_service_log(c);

    local resolve_log = c$c1222_resolve_service_log;
    resolve_log$req_resp = "Req";
    resolve_log$ap_title = getIdString(req$apTitle);

}

event C1222::ResolveRespOk(c: connection, is_orig: bool, resp: Zeek_C1222::ResolveRespOk) {

    hook set_resolve_service_log(c);

    local resolve_log = c$c1222_resolve_service_log;
    resolve_log$req_resp = "Resp";
    resolve_log$local_address = resp$localAddr;

}

# SERVICE ERROR LOG ------------------------------------------------------
event C1222::ResponseNok(c: connection, is_orig: bool, error_record: Zeek_C1222::ResponseNok) {
    # ERROR LOG

    hook set_service_error_log(c);

    local error_log = c$c1222_service_error_log;
    error_log$service = C1222_ENUMS::REQUEST_RESPONSE_CODES[error_record$command];
    error_log$error_code = C1222_ENUMS::REQUEST_RESPONSE_CODES[error_record$code_zeek];
    if(error_record?$maxRequestSize){
        error_log$rqtl_max_request_size = error_record$maxRequestSize;
    }
    if(error_record?$maxResponseSize){
        error_log$rstl_max_response_size = error_record$maxResponseSize;
    }
    if(error_record?$sigerrResp){
        error_log$sigerr_resp = error_record$sigerrResp;
    }

    # TRACE LOG

    if(error_record?$trace){
        local traceObj = error_record$trace;

        hook set_trace_service_log(c);

        local trace_log = c$c1222_trace_service_log;
        trace_log$req_resp = "Resp";

        for (i,traceN in traceObj$trace){    
            trace_log$ap_titles += getIdString(traceN);
        }
    }
}

# SHARED EVENTS------------------------------------------------------
#Service Requests
event C1222::Service(c: connection, is_orig: bool, serviceType: Zeek_C1222::Service){
    local service = serviceType$serviceTag;

    #Ident Req
    if(service == C1222_ENUMS::RequestResponseCodes_IDENT){
        hook set_identification_service_log(c);
        local ident_log = c$c1222_identification_service_log;
        ident_log$req_resp = "Req";
    }
    else if(service == C1222_ENUMS::RequestResponseCodes_PREADDEFAULT){
        hook set_read_write_service_log(c);
        c$c1222_read_write_service_log$req_resp = "Req";
        c$c1222_read_write_service_log$service_type = "pread-default";
    }
    else if(service == C1222_ENUMS::RequestResponseCodes_FULLREAD){
        hook set_read_write_service_log(c);
        c$c1222_read_write_service_log$req_resp = "Req";
        c$c1222_read_write_service_log$service_type = "full-read";
        c$c1222_read_write_service_log$table_id = serviceType$fullread;
    }
    else if(service == C1222_ENUMS::RequestResponseCodes_TRACE){
        hook set_trace_service_log(c);
        local traceObj = serviceType$trace;
        local trace_log = c$c1222_trace_service_log;
        trace_log$req_resp = "Req";

        local trace_vector: vector of string;
        for (i,traceN in traceObj$trace){    
            trace_vector += getIdString(traceN);
        }
        trace_log$ap_titles = trace_vector;
    }
}

#General Response Ok
event C1222::ResponseOk(c: connection, is_orig: bool, resp: Zeek_C1222::ResponseOk) {
    #TRACE
    if (resp$command == C1222_ENUMS::RequestResponseCodes_TRACE) {
        local traceObj = resp$trace;

        hook set_trace_service_log(c);

        local trace_log = c$c1222_trace_service_log;
        trace_log$req_resp = "Resp";

        local trace_vector: vector of string;
        for (i,traceN in traceObj$trace){    
            trace_vector += getIdString(traceN);
        }
        trace_log$ap_titles = trace_vector;
    }
    #DEREGISTER
    else if (resp$command == C1222_ENUMS::RequestResponseCodes_DEREGISTER) {
        hook set_dereg_reg_service_log(c);

        local dereg_reg_log = c$c1222_dereg_reg_service_log;
        dereg_reg_log$req_resp = "Resp";
        dereg_reg_log$service_type = "deregister_resp_ok";
    }
    #WAIT
    else if (resp$command == C1222_ENUMS::RequestResponseCodes_WAIT) {
        hook set_wait_service_log(c);

        local wait_log = c$c1222_wait_service_log;
        wait_log$req_resp = "Resp";
    }
    #SECURITY
    else if (resp$command == C1222_ENUMS::RequestResponseCodes_SECURITY) {
        hook set_logon_service_log(c);

        local logon_log = c$c1222_logon_security_service_log;
        logon_log$req_resp = "Resp";
        logon_log$service_type = "Security";
    }
}

#END SERVICE
event C1222::EndService(c: connection, is_orig: bool){
    if(log_identification_service == T){
        C1222::emit_c1222_identification_service_log(c);
    }
    if(log_read_write_service == T){
        C1222::emit_c1222_read_write_service_log(c);
    }
    if(log_logon_service == T){
        C1222::emit_c1222_logon_security_service_log(c);
    }
    if(log_wait_service == T){
        C1222::emit_c1222_wait_service_log(c);
    }
    if(log_dereg_reg_service == T){
        C1222::emit_c1222_dereg_reg_service_log(c);
    }
    if(log_trace_service == T){
        C1222::emit_c1222_trace_service_log(c);
    }
    if(log_resolve_service == T){
        C1222::emit_c1222_resolve_service_log(c);
    }
}

#END PACKET
event C1222::EndPacket(c: connection, is_orig: bool) {
    if(log_summary == T){
        C1222::emit_c1222_summary_log(c);
    }
    if(log_authentication_value == T){
        emit_c1222_authentication_value_log(c);
    }
    if(log_user_information == T){
        emit_c1222_user_information_log(c);
    }
    if(log_service_error == T){
        emit_c1222_service_error_log(c);
    }
}