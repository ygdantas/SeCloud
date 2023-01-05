%% -------------------------------------------------------------------------- %%
%%             debugging: #show PREDICATE/NUMBER_OF_PARAMETERS
%% -------------------------------------------------------------------------- %%
%#show security_pattern/6.
%#show xsecurity_pattern/6.
% #show gateway/1.
%#show recommended_security_pattern/5.
%#show test_recommended_security_pattern/3.


%#show security_intent/5.
%#show mitigated_by/3.
%#show asset/1.
%#show public/1.
%#show mit_by/3.
%#show secPat_simple/4.
%#show mesh_participant/2.
%#show security_intent/5.


% === Outputs needed by AF3 Plugin  ===
#show secPat/7.
#show mitigated_by/3.
#show assumption/3.
#show cloud_security_configuration/3.
#show new_task_openidconnect/1.
#show new_signal_openidconnect/2.
#show application_requirement/3.
#show infrastructure_requirement/3.

%#show mitigated_by_test/4.
mitigated_by_test(THREAT,PAT,IDPAT,elem(CP1,CP2)) :- 
  mitigated_by(IDTS,_,IDPAT), 
  get_pattern_name(IDPAT,PAT),
  get_threat_from_threat_scenario(IDTS,THREAT),
  security_pattern(IDPAT,PAT,elem(CP1,CP2),_,_,_).

mitigated_by_test(THREAT,PAT,IDPAT,elem(CP1,CP2)) :- 
  mitigated_by(IDTS,_,IDPAT), 
  get_pattern_name(IDPAT,PAT),
  get_threat_from_threat_scenario(IDTS,THREAT),
  security_pattern(IDPAT,PAT,elem(CP1,CP2,_,_),_,_,_).

mitigated_by_test(THREAT,PAT,IDPAT,elem(CP1,CP2)) :- 
  mitigated_by(IDTS,_,IDPAT), 
  get_pattern_name(IDPAT,PAT),
  get_threat_from_threat_scenario(IDTS,THREAT),
  security_pattern(IDPAT,PAT,elem(CP1,CP2,_),_,_,_).


get_pattern_name(IDPAT,PAT) :- security_pattern(IDPAT,PAT,_,_,_,_).

% ======== Security reasoning principles ========
nmitigated(IDTS) :- threat_scenario(IDTS,_,_,_,_),
                    not mitigated(IDTS).

% threat is mitigated if a pattern has been applied (mitigated_by(ID_THREAT,_,PATTERN_ID).
mitigated(IDTS) :- mitigated_by(IDTS,_,_).

%#show no_application_requirement_due_to_infrastructure_task/3.

no_application_requirement_due_to_infrastructure_task(ID,REQUIREMENT,elem(CP)) :-
    assumption(ID,REQUIREMENT,elem(CP)),
    infrastructure_task(CP),
    security_pattern(ID,PAT,_,_,_,_),
    PAT != tls.
 
no_application_requirement_due_to_infrastructure_task(ID,REQUIREMENT,elem(CP1,CP2)) :-
    assumption(ID,REQUIREMENT,elem(CP1,CP2)),
    is_infrastructure_task(CP1,CP2),
    security_pattern(ID,PAT,_,_,_,_),
    PAT != tls.

infrastructure_requirement(ID,REQUIREMENT,ELEM) :-
    no_application_requirement_due_to_infrastructure_task(ID,REQUIREMENT,ELEM).

% ======== Security architecture patterns ========

%% -------------------------------------------------------------------------- %%
%%                         Authorization
%% -------------------------------------------------------------------------- %%
% https://fast-dds.docs.eprosima.com/en/latest/fastdds/security/access_control_plugin/access_control_plugin.html#access-permissions
% Betty H. C. Cheng 1 , Bradley Doherty, Nicholas Polanco, Matthew Pasco. Security Patterns for Connected and Automated Automotive Systems
%% security_intent(authorization,attack_surface(internal_interface),
%%     property(integrity),threat(elevation_of_privilege),type(prevention)).

% === Authorization: Instantiation ===
security_pattern(ID,authorization,elem(CP1,MONITOR),INP,INT,OUT) :-
        xsecurity_pattern(ID,authorization,elem(CP1,MONITOR),INP,INT,OUT).


authorization(ID,CP1,MONITOR) :- security_pattern(ID,authorization,elem(CP1,MONITOR),INP,INT,OUT).

secPat(ID,authorization,CP1,0,0,1,no) :-
 security_pattern(ID,authorization,elem(CP1,MONITOR),INP,INT,OUT).

% === Authorization pattern: Assumptions/Requirements ===   
assumption(ID,the_entity_has_implemented_a_monitor,elem(CP1,MONITOR)) :-
        security_pattern(ID,authorization,elem(CP1,MONITOR),INP,INT,OUT).

assumption(ID,the_monitor_has_defined_authorization_policy_to_check_if_incoming_request_to_entity_is_authorized,elem(MONITOR,CP1)) :-
        security_pattern(ID,authorization,elem(CP1,MONITOR),INP,INT,OUT).

assumption(ID,the_monitor_has_the_previleges_of_the_entity,elem(MONITOR,CP1)) :-
        security_pattern(ID,authorization,elem(CP1,MONITOR),INP,INT,OUT).

% === Authorization pattern: Security argumentation ===
mitigated_by(IDTS,CLIENT,IDPT) :- security_pattern(IDPT,authorization,elem(CLIENT,MONITOR),_,_,_),
                                  recommended_security_pattern(authorization,IDTS,IDAT,CLIENT,SERVER). 

%% mitigated_by(IDTS,CP1,IDPT) :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,ATTACK_TYPE,ASSET),
%%                                damage_scenario(ASSET,PROPERTY_TYPE,_),
%%                                get_attack_path_from_threat_scenario(IDTS,IDAT),
%%                                attack_path(IDAT,CP1,CP2,MESSAGE,ASSET),                                    
%%                                security_pattern(IDPT,authorization,elem(CP1,MONITOR),INP,INT,OUT),
%%                                attack_action2attack_surface(THREAT_DESCRIPTION,ATTACK_SURFACE),
%%                                security_intent(authorization,ATTACK_SURFACE,PROPERTY_TYPE,ATTACK_TYPE,PAT_TYPE).

%% -------------------------------------------------------------------------- %%
%%                         OAuth
%% -------------------------------------------------------------------------- %%
% https://istio.io/latest/docs/tasks/security/authorization/authz-jwt/
%% security_intent(oAuth,attack_surface(external_interface),
%%     property(integrity),threat(elevation_of_privilege),type(prevention)).


% === OAuth: Instantiation ===
security_pattern(ID,oAuth,elem(CP1,CP2),INP,INT,OUT) :-
        xsecurity_pattern(ID,oAuth,elem(CP1,CP2),INP,INT,OUT).

secPat(ID,oAuth,CP1,0,0,1,no) :-
 security_pattern(ID,oAuth,elem(CP1,CP2),INP,INT,OUT).

% === OAuth: Assumptions/Requirements ===
%% assumption(ID,has_verified_the_identity_token_by_origin,elem(MONITOR,CP1)) :-
%%  security_pattern(ID,oAuth,elem(CP1,MONITOR),INP,INT,OUT).

% === OAuth: Security argumentation ===
mitigated_by(IDTS,CLIENT,IDPT) :- security_pattern(IDPT,oAuth,elem(CLIENT,SERVER),_,_,_),
                                  recommended_security_pattern(oAuth,IDTS,IDAT,CLIENT,SERVER). 

%% mitigated_by(IDTS,PUBLIC,IDPT) :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,ATTACK_TYPE,ASSET),
%%                                damage_scenario(ASSET,PROPERTY_TYPE,_),
%%                                attack_action2attack_surface(THREAT_DESCRIPTION,ATTACK_SURFACE),
%%                                get_attack_path_from_threat_scenario(IDTS,IDAT),
%%                                get_attack_surface_from_attack_path(IDAT,PUBLIC),
%%                                public(PUBLIC),
%%                                task_output_port(PUBLIC,PUBLIC_PORT),
%%                                signal_with_ports(ID,PUBLIC_PORT,PUBLIC,SERVER_PORT,SERVER),
%%                                security_pattern(IDPT,oAuth,elem(PUBLIC,SERVER),INP,INT,OUT),
%%                                security_intent(oAuth,ATTACK_SURFACE,PROPERTY_TYPE,ATTACK_TYPE,PAT_TYPE).

%% -------------------------------------------------------------------------- %%
%%                         JWT Token
%% -------------------------------------------------------------------------- %%
% https://istio.io/latest/docs/tasks/security/authorization/authz-jwt/
%% security_intent(jwtToken,attack_surface(internal_interface),
%%     property(integrity),threat(spoofing),type(prevention)).


% === JWT Token: Instantiation ===
security_pattern(ID,jwtToken,elem(CP1,MONITOR),INP,INT,OUT) :-
        xsecurity_pattern(ID,jwtToken,elem(CP1,MONITOR),INP,INT,OUT).

secPat(ID,jwtToken,CP1,0,0,1,no) :-
 security_pattern(ID,jwtToken,elem(CP1,MONITOR),INP,INT,OUT).

% === JWT Token: Assumptions/Requirements ===

assumption(ID,has_verified_the_identity_token_by_origin,elem(MONITOR,CP1)) :-
 security_pattern(ID,jwtToken,elem(CP1,MONITOR),INP,INT,OUT).

% === JWT Token: Technical/Infrasutrcture Assumptions/Requirements ===

infrastructure_requirement(ID,has_verified_the_identity_token_by_origin,elem(MONITOR,CP1)) :-
 security_pattern(ID,jwtToken,elem(CP1,MONITOR),INP,INT,OUT).

% === Authorization JWT Token: Security argumentation ===
mitigated_by(IDTS,CLIENT,IDPT) :- security_pattern(IDPT,jwtToken,elem(CLIENT,MONITOR),_,_,_),
                                  recommended_security_pattern(jwtToken,IDTS,IDAT,CLIENT,SERVER).

%% mitigated_by(IDTS,CP1,IDPT) :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,ATTACK_TYPE,ASSET),
%%                                damage_scenario(ASSET,PROPERTY_TYPE,_),
%%                                get_attack_path_from_threat_scenario(IDTS,IDAT),
%%                                attack_path(IDAT,CP1,CP2,MESSAGE,ASSET),                                    
%%                                security_pattern(IDPT,jwtToken,elem(CP1,MONITOR),INP,INT,OUT),
%%                                attack_action2attack_surface(THREAT_DESCRIPTION,ATTACK_SURFACE),
%%                                security_intent(jwtToken,ATTACK_SURFACE,PROPERTY_TYPE,ATTACK_TYPE,PAT_TYPE).

%% mitigated_by(IDTS,PUBLIC,IDPT) :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,ATTACK_TYPE,ASSET),
%%                                damage_scenario(ASSET,PROPERTY_TYPE,_),
%%                                attack_action2attack_surface(THREAT_DESCRIPTION,ATTACK_SURFACE),
%%                                get_attack_path_from_threat_scenario(IDTS,IDAT),
%%                                get_attack_surface_from_attack_path(IDAT,PUBLIC),
%%                                public(PUBLIC),
%%                                task_output_port(PUBLIC,PUBLIC_PORT),
%%                                signal_with_ports(ID,PUBLIC_PORT,PUBLIC,SERVER_PORT,SERVER),
%%                                security_pattern(IDPT,jwtToken,elem(PUBLIC,SERVER),INP,INT,OUT),
%%                                security_intent(jwtToken,ATTACK_SURFACE,PROPERTY_TYPE,ATTACK_TYPE,PAT_TYPE).


%% -------------------------------------------------------------------------- %%
%%                                TLS Authentication
%% -------------------------------------------------------------------------- %%
% security_intent(PATTERN_NAME,ATTACK_SURFACE,SECURITY_PROPERTY,THREAT_TYPE,PATTERN_TYPE).
%% PATTERN_NAME specifies the name of the pattern
%% ATTACK_SURFACE specifies the type of attack surface suitable to apply the pattern
%% SECURITY_PROPERTY specifies the cyber security property satisfied by the pattern
%% THREAT_TYPE specifies the type of threat (STRIDE) 
%% PATTERN_TYPE specifies the type of pattern (mitigation, detection or prevention)
security_intent(tls,attack_surface(external_interface),
    property(authenticity,integrity),threat(spoofing,tampering),type(prevention)).

% === Mutual Authentication pattern: Instantiation ===
security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT) :-
  xsecurity_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

secPat(ID,tls,CLIENT,0,0,0,no) :- 
 security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

cloud_security_configuration(tls,possesses_a_tls_certificate,SERVER) :-
   security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT).

% === TLS: Assumptions/Requirements ===

%% a TLS certificate installed on its origin server
assumption(ID,has_installed_a_TLS_certificate_issued_by_a_trustworthy_certification_authority_to_communicate_with_destination,elem(SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

assumption(ID,has_received_the_server_TLS_certificate_signed_by_a_trustworthy_certification_authority,elem(CLIENT,SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

assumption(ID,has_verified_the_server_TLS_certificate_with_public_key_of_certification_authority,elem(CLIENT,SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

assumption(ID,has_created_a_symmetric_encryption_key_with_server_public_key,elem(CLIENT,SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

assumption(ID,has_encrypted_data_in_transit_using_the_created_symmetric_encryption_key,elem(CLIENT,SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

assumption(ID,has_encrypted_data_in_transit_using_the_created_symmetric_encryption_key,elem(SERVER,CLIENT)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

% === TLS: Technical/Infrasutrcture Assumptions/Requirements ===

application_requirement(tls,has_installed_a_TLS_certificate_issued_by_a_trustworthy_certification_authority_to_communicate_with_destination,elem(SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT),
    not infrastructure_task(SERVER).

application_requirement(ID,has_verified_the_server_TLS_certificate_with_public_key_of_certification_authority,elem(CLIENT,SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

no_application_requirement_due_to_infrastructure_task(tls,has_installed_a_TLS_certificate_issued_by_a_trustworthy_certification_authority_to_communicate_with_destination,elem(SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT),
    infrastructure_task(SERVER).

infrastructure_requirement(ID,has_received_the_server_TLS_certificate_signed_by_a_trustworthy_certification_authority,elem(CLIENT,SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT).

infrastructure_requirement(ID,has_received_the_server_TLS_certificate_signed_by_a_trustworthy_certification_authority,elem(CLIENT,SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT).



infrastructure_requirement(ID,has_created_a_symmetric_encryption_key_with_server_public_key,elem(CLIENT,SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

infrastructure_requirement(ID,has_created_a_symmetric_encryption_key_with_server_public_key,elem(CLIENT,SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 


infrastructure_requirement(ID,has_encrypted_data_in_transit_using_the_created_symmetric_encryption_key,elem(CLIENT,SERVER)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

infrastructure_requirement(ID,has_encrypted_data_in_transit_using_the_created_symmetric_encryption_key,elem(SERVER,CLIENT)) :-
    security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 


% === TLS: Security argumentation ===

% only mitigates spoofing threat contains a path from SERVER to CLIENT
% tls is 1-way authentication only

%% mitigated_by(IDTS,CLIENT,IDPT) :- security_pattern(IDPT,tls,elem(CLIENT,SERVER),_,_,_),
%%                                   recommended_security_pattern(tls,IDTS,IDAT,CLIENT,SERVER). 

mitigated_by(IDTS,CLIENT,IDPT)   :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,tampering,ASSET),
                                    damage_scenario(ASSET,PROPERTY_TYPE,_),
                                    attack_action2attack_surface(THREAT_DESCRIPTION,external_interface),
                                    recommended_security_pattern(tls,IDTS,IDAT,CLIENT,SERVER), 
                                    security_pattern(IDPT,tls,elem(CLIENT,SERVER),_,_,_),
                                    security_intent(tls,external_interface,PROPERTY_TYPE,tampering,PAT_TYPE).
%% -------------------------------------------------------------------------- %%
%%                         Mutual Authentication
%% -------------------------------------------------------------------------- %%
% https://www.figiefa.eu/wp-content/uploads/Security-Concept-for-an-Open-Telematics-Platform_2017_09.pdf
% https://www.youtube.com/watch?v=YnV-vDnOMKE&t=4890s&ab_channel=AutomotiveSecurityResearchGroup

%% Mutual authentication is when two sides of a communications channel verify each other's identity.

% security_intent(PATTERN_NAME,ATTACK_SURFACE,SECURITY_PROPERTY,THREAT_TYPE,PATTERN_TYPE).
%% PATTERN_NAME specifies the name of the pattern
%% ATTACK_SURFACE specifies the type of attack surface suitable to apply the pattern
%% SECURITY_PROPERTY specifies the cyber security property satisfied by the pattern
%% THREAT_TYPE specifies the type of threat (STRIDE) 
%% PATTERN_TYPE specifies the type of pattern (mitigation, detection or prevention)
security_intent(mutualAuthentication,attack_surface(external_interface,internal_interface),
    property(authenticity,integrity,authorization),threat(spoofing,tampering,elevation_of_privilege),type(prevention)).

% === Mutual Authentication pattern: Instantiation ===
security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),INP,INT,OUT) :-
  xsecurity_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),INP,INT,OUT). 

secPat(ID,mutualAuthentication,ID,0,0,0,no) :- 
 security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),INP,INT,OUT),
 mitigated_by(_,_,ID). 


% === Mutual Authentication pattern: Assumptions/Requirements ===

% both client and server shall implement the mTLS authentication
assumption(ID,has_implemented_mutual_TLS_authentication_to_communicate_with_destination,elem(SERVER,CLIENT)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

assumption(ID,has_implemented_mutual_TLS_authentication_to_communicate_with_destination,elem(CLIENT,SERVER)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

assumption(ID,has_received_the_client_digital_certificate_information_signed_by_a_trustworthy_certification_authority,elem(SERVER,CLIENT)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

assumption(ID,has_received_the_server_digital_certificate_information_signed_by_a_trustworthy_certification_authority,elem(CLIENT,SERVER)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

assumption(ID,has_authorized_client_actions,elem(SERVER,CLIENT)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

assumption(ID,is_authorized_to_publish,elem(CLIENT,TOPIC)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
    publisher(CLIENT,TOPIC).

assumption(ID,is_authorized_to_publish,elem(SERVER,TOPIC)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
    publisher(SERVER,TOPIC).

assumption(ID,is_authorized_to_subscribe,elem(CLIENT,TOPIC)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
    subscriber(CLIENT,TOPIC).

assumption(ID,is_authorized_to_subscribe,elem(SERVER,TOPIC)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
    subscriber(SERVER,TOPIC).

% the key distribution is done over a secure channel
assumption(ID,keys_of_the_entity_are_distributed_over_secure_channel,elem(CLIENT,SERVER)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

assumption(ID,has_verified_the_client_digital_certificate_with_public_key_of_certification_authority,elem(SERVER,CLIENT)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

assumption(ID,has_verified_the_server_digital_certificate_with_public_key_of_certification_authority,elem(CLIENT,SERVER)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

% === Mutual Authentication pattern: Technical/Infrasutrcture Assumptions/Requirements ===

application_requirement(ID,has_implemented_mutual_TLS_authentication_to_communicate_with_destination,elem(SERVER,CLIENT)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
    not no_application_requirement_due_to_infrastructure_task(ID,has_implemented_mutual_TLS_authentication_to_communicate_with_destination,elem(SERVER,CLIENT)).    


application_requirement(ID,has_implemented_mutual_TLS_authentication_to_communicate_with_destination,elem(CLIENT,SERVER)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
    not no_application_requirement_due_to_infrastructure_task(ID,has_implemented_mutual_TLS_authentication_to_communicate_with_destination,elem(CLIENT,SERVER)).    

application_requirement(ID,has_verified_the_client_digital_certificate_with_public_key_of_certification_authority,elem(SERVER,CLIENT)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

application_requirement(ID,has_verified_the_server_digital_certificate_with_public_key_of_certification_authority,elem(CLIENT,SERVER)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

infrastructure_requirement(ID,has_authorized_client_actions,elem(SERVER,CLIENT)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

infrastructure_requirement(ID,has_received_the_client_digital_certificate_information_signed_by_a_trustworthy_certification_authority,elem(SERVER,CLIENT)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

infrastructure_requirement(ID,has_received_the_server_digital_certificate_information_signed_by_a_trustworthy_certification_authority,elem(CLIENT,SERVER)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).




infrastructure_requirement(ID,keys_of_the_entity_are_distributed_over_secure_channel,elem(CLIENT,SERVER)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_).

infrastructure_requirement(ID,is_authorized_to_publish,elem(CLIENT,TOPIC)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
    publisher(CLIENT,TOPIC).

infrastructure_requirement(ID,is_authorized_to_publish,elem(SERVER,TOPIC)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
    publisher(SERVER,TOPIC).

infrastructure_requirement(ID,is_authorized_to_subscribe,elem(CLIENT,TOPIC)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
    subscriber(CLIENT,TOPIC).

infrastructure_requirement(ID,is_authorized_to_subscribe,elem(SERVER,TOPIC)) :-
    security_pattern(ID,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
    subscriber(SERVER,TOPIC).



% === Mutual Authentication pattern: Security argumentation ===
%% mitigated_by(IDTS,CLIENT,IDPT) :- security_pattern(IDPT,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
%%                                   recommended_security_pattern(mutualAuthentication,IDTS,IDAT,CLIENT,SERVER). 

%% mitigated_by(IDTS,SERVER,IDPT) :- security_pattern(IDPT,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
%%                                   mitigated_by(IDTS,CLIENT,IDPT),  
                                  %% recommended_security_pattern(mutualAuthentication,IDTS,IDAT,SERVER,CLIENT). 

mitigated_by(IDTS,CLIENT,IDPT) :- recommended_security_pattern(mutualAuthentication,IDTS,IDAT,CLIENT,SERVER),
                                  get_next_no_gateway_element_in_path(CLIENT,SERVER,ELEM),
                                  security_pattern(IDPT,mutualAuthentication,elem(CLIENT,ELEM),_,_,_),
                                  security_intent(mutualAuthentication,ATTACK_SURFACE,PROPERTY_TYPE,ATTACK_TYPE,PAT_TYPE),
                                  threat_scenario(IDTS,THREAT_DESCRIPTION,_,THREAT_TYPE_STRIDE,ASSET),
                                  attack_action2attack_surface(THREAT_DESCRIPTION,ATTACK_SURFACE),
                                  damage_scenario(ASSET,PROPERTY_TYPE,_),
                                  get_attack_path_from_threat_scenario(IDTS,IDAT),
                                  attack_path(IDAT,CLIENT,SERVER,MESSAGE,ASSET).                                  

mitigated_by(IDTS,CLIENT,IDPT) :- recommended_security_pattern(mutualAuthentication,IDTS,IDAT,SERVER,CLIENT),
                                  get_next_no_gateway_element_in_path(CLIENT,SERVER,ELEM),
                                  security_pattern(IDPT,mutualAuthentication,elem(CLIENT,ELEM),_,_,_),
                                  security_intent(mutualAuthentication,ATTACK_SURFACE,PROPERTY_TYPE,ATTACK_TYPE,PAT_TYPE),
                                  threat_scenario(IDTS,THREAT_DESCRIPTION,_,THREAT_TYPE_STRIDE,ASSET),
                                  attack_action2attack_surface(THREAT_DESCRIPTION,ATTACK_SURFACE),
                                  damage_scenario(ASSET,PROPERTY_TYPE,_),
                                  get_attack_path_from_threat_scenario(IDTS,IDAT),
                                  attack_path(IDAT,SERVER,CLIENT,MESSAGE,ASSET).


mitigated_by(IDTS,CLIENT,IDPT) :- recommended_security_pattern(mutualAuthentication,IDTS,IDAT,CLIENT,SERVER),
                                  get_next_no_gateway_element_in_path(CLIENT,SERVER,ELEM),
                                  security_pattern(IDPT,mutualAuthentication,elem(CLIENT,ELEM),_,_,_),
                                  security_intent(mutualAuthentication,ATTACK_SURFACE,PROPERTY_TYPE,ATTACK_TYPE,PAT_TYPE),
                                  threat_scenario(IDTS,THREAT_DESCRIPTION,_,THREAT_TYPE_STRIDE,ASSET),
                                  attack_action2attack_surface(THREAT_DESCRIPTION,ATTACK_SURFACE),
                                  damage_scenario(ASSET,PROPERTY_TYPE,_),
                                  get_attack_path_from_threat_scenario(IDTS,IDAT),
                                  get_attack_surface_from_attack_path(IDAT,CLIENT),
                                  public(CLIENT).

get_next_no_gateway_element_in_path(CP1,CP2,CP2) :-
  recommended_security_pattern(_,_,_,CP1,CP2),
  task(CP1),
  task(CP2),
  not gateway(CP2),
  CP1 != CP2.

get_next_no_gateway_element_in_path(CP1,CP2,CP3) :-
  recommended_security_pattern(_,_,_,CP1,CP2),
  task(CP1),
  task(CP2),
  task(CP3),
  gateway(CP2),
  signal_with_ports(_,_,CP2,_,CP3),
  CP1 != CP3.


%% mitigated_by(IDTS,CLIENT,IDPT) :- security_pattern(IDPT,mutualAuthentication,elem(CLIENT,SERVER),_,_,_),
%%                                   recommended_security_pattern(mutualAuthentication,IDTS,IDAT,SERVER,CLIENT),
%%                                   security_intent(mutualAuthentication,ATTACK_SURFACE,PROPERTY_TYPE,ATTACK_TYPE,PAT_TYPE),
%%                                   threat_scenario(IDTS,THREAT_DESCRIPTION,_,THREAT_TYPE_STRIDE,ASSET),
%%                                   attack_action2attack_surface(THREAT_DESCRIPTION,ATTACK_SURFACE),
%%                                   damage_scenario(ASSET,PROPERTY_TYPE,_),
%%                                   get_attack_path_from_threat_scenario(IDTS,IDAT),
%%                                   attack_path(IDAT,SERVER,CLIENT,MESSAGE,ASSET).  


%% -------------------------------------------------------------------------- %%
%%                           Service Mesh - istio 
%% -------------------------------------------------------------------------- %%
% https://istio.io/latest/docs/reference/config/security/authorization-policy/

% security_intent(PATTERN_NAME,ATTACK_SURFACE,SECURITY_PROPERTY,THREAT_TYPE,PATTERN_TYPE).
%% PATTERN_NAME specifies the name of the pattern
%% ATTACK_SURFACE specifies the type of attack surface suitable to apply the pattern
%% SECURITY_PROPERTY specifies the cyber security property satisfied by the pattern
%% THREAT_TYPE specifies the type of threat (STRIDE) 
%% PATTERN_TYPE specifies the type of pattern (mitigation, detection or prevention)
security_intent(istioServiceMesh,attack_surface(external_interface,internal_interface),
    property(authenticity,integrity,authorization),threat(spoofing,tampering,elevation_of_privilege),type(prevention)).


% === istio Service Mesh : Instantiation ===
security_pattern(ID,istioServiceMesh,elem(CLIENT,SERVER,PROXY_CLIENT,PROXY_SERVER),INP,INT,OUT) :-
  xsecurity_pattern(ID,istioServiceMesh,elem(CLIENT,SERVER,PROXY_CLIENT,PROXY_SERVER),INP,INT,OUT).
%  not mesh_participant(_,X),
%  task(X).


secPat(ID,istioServiceMesh,not_applicable,0,0,2,no) :- 
 xsecurity_pattern(ID,istioServiceMesh,elem(CLIENT,SERVER,PROXY_CLIENT,PROXY_SERVER),INP,INT,OUT).

mesh_participant(istioServiceMesh,CP) :-
 mesh_participant(IDPAT,CP),
 xsecurity_pattern(IDPAT,istioServiceMesh,_,_,_,_).



mesh_participant(ID,CLIENT) :-
 xsecurity_pattern(ID,istioServiceMesh,elem(CLIENT,SERVER,PROXY_CLIENT,PROXY_SERVER),INP,INT,OUT),
 not public(CLIENT),
 not gateway(SERVER).


mesh_participant(ID,SERVER) :-
 xsecurity_pattern(ID,istioServiceMesh,elem(CLIENT,SERVER,PROXY_CLIENT,PROXY_SERVER),INP,INT,OUT),
 not public(SERVER).
% not gateway(SERVER).


is_in_the_mesh(CP) :-
  mesh_participant(_,CP).

mesh_participant(IDPAT,CLIENT) :-
       xsecurity_pattern(IDPAT,istioServiceMesh,elem(CLIENT,SERVER,_,_),_,_,_),
       security_pattern(IDPAT,istioServiceMesh,_,_,_,_),
       not is_in_the_mesh(CLIENT),
       not public(CLIENT),
       not gateway(SERVER).

mesh_participant(IDPAT,SERVER) :-
       xsecurity_pattern(IDPAT,istioServiceMesh,elem(CLIENT,SERVER,_,_),_,_,_),
       security_pattern(IDPAT,istioServiceMesh,_,_,_,_),
       not is_in_the_mesh(SERVER),
       not public(SERVER).
%       not gateway(SERVER).


cloud_security_configuration(istioServiceMesh,is_part_of_istio_service_mesh,PARTICIPANT) :-
 mesh_participant(istioServiceMesh,PARTICIPANT).

% === istio Service Mesh: Assumptions/Requirements === 
assumption(ID,has_been_added_to_mesh,elem(PARTICIPANT)) :-
    security_pattern(ID,istioServiceMesh,_,_,_,_),
    mesh_participant(istioServiceMesh,PARTICIPANT).

assumption(ID,is_authorized_to_publish,elem(PARTICIPANT,TOPIC)) :-
    security_pattern(ID,istioServiceMesh,_,_,_,_),
    mesh_participant(istioServiceMesh,PARTICIPANT),
    publisher(PARTICIPANT,TOPIC).

assumption(ID,is_authorized_to_subscribe,elem(PARTICIPANT,TOPIC)) :-
    security_pattern(ID,istioServiceMesh,_,_,_,_),
    mesh_participant(istioServiceMesh,PARTICIPANT),
    subscriber(PARTICIPANT,TOPIC).

% https://git.fortiss.org/rtaphm-lufo/rtaphm-code/-/blob/master/deployment/kubernetes/istio/policies/internal-communication.yaml
assumption(ID,has_written_authorization_policy_to_communicate_with_destination,elem(PARTICIPANT,PARTICIPANT2)) :-
    security_pattern(ID,istioServiceMesh,elem(_,_,_,_),_,_,_),
    mesh_participant(istioServiceMesh,PARTICIPANT),
    signal_with_ports(SIGNAL,_,PARTICIPANT,_,PARTICIPANT2),
    mesh_participant(istioServiceMesh,PARTICIPANT2).

% === istio Service Mesh: Technical/Infrasutrcture Assumptions/Requirements ===
infrastructure_requirement(ID,has_written_authorization_policy_to_communicate_with_destination,elem(PARTICIPANT,PARTICIPANT2)) :-
    security_pattern(ID,istioServiceMesh,elem(_,_,_,_),_,_,_),
    mesh_participant(istioServiceMesh,PARTICIPANT),
    signal_with_ports(SIGNAL,_,PARTICIPANT,_,PARTICIPANT2),
    mesh_participant(istioServiceMesh,PARTICIPANT2).

infrastructure_requirement(ID,is_authorized_to_publish,elem(PARTICIPANT,TOPIC)) :-
    security_pattern(ID,istioServiceMesh,_,_,_,_),
    mesh_participant(istioServiceMesh,PARTICIPANT),
    publisher(PARTICIPANT,TOPIC).

infrastructure_requirement(ID,is_authorized_to_subscribe,elem(PARTICIPANT,TOPIC)) :-
    security_pattern(ID,istioServiceMesh,_,_,_,_),
    mesh_participant(istioServiceMesh,PARTICIPANT),
    subscriber(PARTICIPANT,TOPIC).

%% mesh_participant(istioServiceMesh,"Task_CA_Postgres_ID_10271"). 
%% mesh_participant(istioServiceMesh,"Task_CA_ID_10255").
%% %signal_with_ports("Signal ca_output1→cadb_inputSignal_ca_output1_cadb_input_ID_10414","ca_output1_ID_10267","Task_CA_ID_10255","cadb_input_ID_10275","Task_CA_Postgres_ID_10271").
%% signal_with_ports(ID,_,"Task_CA_ID_10255",_,"Task_CA_Postgres_ID_10271").


infrastructure_requirement(ID,has_been_added_to_mesh,elem(PARTICIPANT)) :-
    security_pattern(ID,istioServiceMesh,_,_,_,_),
    mesh_participant(istioServiceMesh,PARTICIPANT).

% === istio Service Mesh: Security argumentation ===
%% mitigated_by(IDTS,CLIENT,IDPT) :- security_pattern(IDPT,istioServiceMesh,elem(CLIENT,SERVER,_,_),_,_,_),
%%                                   recommended_security_pattern(istioServiceMesh,IDTS,IDAT,CLIENT,SERVER). 


mitigated_by(IDTS,CLIENT,IDPT) :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,ATTACK_TYPE,ASSET),
                                  damage_scenario(ASSET,PROPERTY_TYPE,_),
                                  attack_action2attack_surface(THREAT_DESCRIPTION,internal_interface),
                                  recommended_security_pattern(istioServiceMesh,IDTS,IDAT,CLIENT,SERVER),
                                  get_next_no_gateway_element_in_path(CLIENT,SERVER,ELEM),                                 
                                  xsecurity_pattern(IDPT,istioServiceMesh,elem(CLIENT,ELEM,_,_),_,_,_),
                                  mesh_participant(IDPT,CLIENT),
                                  mesh_participant(IDPT,ELEM),
                                  security_intent(istioServiceMesh,internal_interface,PROPERTY_TYPE,ATTACK_TYPE,PAT_TYPE).

mitigated_by(IDTS,CLIENT,IDPT)   :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,elevation_of_privilege,ASSET),
                                    damage_scenario(ASSET,PROPERTY_TYPE,_),
                                    attack_action2attack_surface(THREAT_DESCRIPTION,external_interface),
                                    recommended_security_pattern(istioServiceMesh,IDTS,IDAT,CLIENT,SERVER),
                                    get_next_no_gateway_element_in_path(CLIENT,SERVER,ELEM), 
                                    xsecurity_pattern(IDPT,istioServiceMesh,elem(CLIENT,ELEM,_,_),_,_,_),
                                    mesh_participant(istioServiceMesh,ELEM),
                                    security_intent(istioServiceMesh,external_interface,PROPERTY_TYPE,elevation_of_privilege,PAT_TYPE),
                                    security_pattern(IDPAT1,openIdConnect,elem(CLIENT,ELEM,_),_,_,_),
                                    security_pattern(IDPAT2,tls,elem(CLIENT,SERVER),_,_,_).                           

%% -------------------------------------------------------------------------- %%
%%                         Open Policy Agent (OPA)
%% -------------------------------------------------------------------------- %%
% https://istio.io/latest/docs/reference/config/security/authorization-policy/

% security_intent(PATTERN_NAME,ATTACK_SURFACE,SECURITY_PROPERTY,THREAT_TYPE,PATTERN_TYPE).
%% PATTERN_NAME specifies the name of the pattern
%% ATTACK_SURFACE specifies the type of attack surface suitable to apply the pattern
%% SECURITY_PROPERTY specifies the cyber security property satisfied by the pattern
%% THREAT_TYPE specifies the type of threat (STRIDE) 
%% PATTERN_TYPE specifies the type of pattern (mitigation, detection or prevention)
%% security_intent(openPolicyAgent,attack_surface(internal_interface),
%%     property(integrity),threat(elevation_of_privilege),type(prevention)).

% === Open Policy Agent: Instantiation ===
security_pattern(ID,openPolicyAgent,elem(CP1,MONITOR),INP,INT,OUT) :-
  xsecurity_pattern(ID,openPolicyAgent,elem(CP1,MONITOR),INP,INT,OUT). 

secPat(ID,openPolicyAgent,CP1,0,0,1,no) :- 
 security_pattern(ID,openPolicyAgent,elem(CP1,MONITOR),INP,INT,OUT). 

% === Open Policy Agent: Assumptions/Requirements ===

assumption(ID,has_defined_istio_authorization_policy_to_check_if_incoming_request_to_entity_is_authorized,elem(MONITOR,CP1)) :-
        security_pattern(ID,openPolicyAgent,elem(CP1,MONITOR),INP,INT,OUT). 

assumption(ID,has_deployed_the_OPA_Envoy_plugin,elem(CP1)) :-
        security_pattern(ID,openPolicyAgent,elem(CP1,MONITOR),INP,INT,OUT). 

assumption(ID,is_authorized_to_publish,elem(CP1,TOPIC)) :-
    security_pattern(ID,openPolicyAgent,elem(CP1,MONITOR),INP,INT,OUT),
    publisher(CP1,TOPIC).

assumption(ID,is_authorized_to_subscribe,elem(CP1,TOPIC)) :-
    security_pattern(ID,openPolicyAgent,elem(CP1,MONITOR),INP,INT,OUT),
    subscriber(CP1,TOPIC).


% === Open Policy Agent: Technical/Infrasutrcture Assumptions/Requirements ===

application_requirement(ID,has_deployed_the_OPA_Envoy_plugin,elem(CP1)) :-
        security_pattern(ID,openPolicyAgent,elem(CP1,MONITOR),INP,INT,OUT),
        not no_application_requirement_due_to_infrastructure_task(ID,has_deployed_the_OPA_Envoy_plugin,elem(CP1)). 

infrastructure_requirement(ID,has_defined_istio_authorization_policy_to_check_if_incoming_request_to_entity_is_authorized,elem(MONITOR,CP1)) :-
        security_pattern(ID,openPolicyAgent,elem(CP1,MONITOR),INP,INT,OUT). 


infrastructure_requirement(ID,is_authorized_to_publish,elem(CP1,TOPIC)) :-
    security_pattern(ID,openPolicyAgent,elem(CP1,MONITOR),INP,INT,OUT),
    publisher(CP1,TOPIC).

infrastructure_requirement(ID,is_authorized_to_subscribe,elem(CP1,TOPIC)) :-
    security_pattern(ID,openPolicyAgent,elem(CP1,MONITOR),INP,INT,OUT),
    subscriber(CP1,TOPIC).


% === Open Policy Agent: Security argumentation ===
mitigated_by(IDTS,CLIENT,IDPT) :- security_pattern(IDPT,openPolicyAgent,elem(CLIENT,MONITOR),_,_,_),
                                  recommended_security_pattern(openPolicyAgent,IDTS,IDAT,CLIENT,SERVER).

%% -------------------------------------------------------------------------- %%
%%                         OpenId Connect
%% -------------------------------------------------------------------------- %%
% https://openid.net/connect/

% security_intent(PATTERN_NAME,ATTACK_SURFACE,SECURITY_PROPERTY,THREAT_TYPE,PATTERN_TYPE).
%% PATTERN_NAME specifies the name of the pattern
%% ATTACK_SURFACE specifies the type of attack surface suitable to apply the pattern
%% SECURITY_PROPERTY specifies the cyber security property satisfied by the pattern
%% THREAT_TYPE specifies the type of threat (STRIDE) 
%% PATTERN_TYPE specifies the type of pattern (mitigation, detection or prevention)
%% security_intent(openIdConnect,attack_surface(external_interface,internal_interface),
%%     property(integrity),threat(spoofing),type(prevention)).
security_intent(openIdConnect,attack_surface(external_interface),
    property(authenticity),threat(spoofing),type(prevention)).


% === OpenId Connect: Instantiation ===
security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT) :-
  xsecurity_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT). 

secPat(CP1,openIdConnect,CP1,0,0,2,no) :- 
 security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT).

% === OpenId Connect: Assumptions/Requirements ===
assumption(ID,communication_between_entities_are_encrypted,elem(CP1,CP2)) :-
    security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT).
 
assumption(ID,communication_between_entities_are_encrypted,elem(CP1,OpenIdServer)) :-
    security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT).

assumption(ID,has_obtained_credentials_from_OpenID_Connect_Server,elem(CP1,OpenIdServer)) :-
    security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT).

assumption(ID,is_authorized_to_publish,elem(CP1,TOPIC)) :-
    security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT),
    publisher(CP1,TOPIC).

assumption(ID,is_authorized_to_subscribe,elem(CP1,TOPIC)) :-
    security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT),
    subscriber(CP1,TOPIC).

% === OpenId Connect: Technical/Infrasutrcture Assumptions/Requirements ===

application_requirement(ID,communication_between_entities_are_encrypted,elem(CP1,CP2)) :-
    security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT),
    not no_application_requirement_due_to_infrastructure_task(ID,communication_between_entities_are_encrypted,elem(CP1,CP2)).

application_requirement(ID,communication_between_entities_are_encrypted,elem(CP1,OpenIdServer)) :-
    security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT),
    not no_application_requirement_due_to_infrastructure_task(ID,communication_between_entities_are_encrypted,elem(CP1,OpenIdServer)).

infrastructure_requirement(ID,has_obtained_credentials_from_OpenID_Connect_Server,elem(CP1,OpenIdServer)) :-
    security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT). 

infrastructure_requirement(ID,is_authorized_to_publish,elem(CP1,TOPIC)) :-
    security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT),
    publisher(CP1,TOPIC).

infrastructure_requirement(ID,is_authorized_to_subscribe,elem(CP1,TOPIC)) :-
    security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT),
    subscriber(CP1,TOPIC).

% === OpenId Connect: Instantiation ===

new_task_openidconnect("openIDConnectServer") :- 
  security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT).

new_signal_openidconnect("openIDConnectServer",CP1) :- security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT).



% === OpenId Connect: Security argumentation ===

mitigated_by(IDTS,CLIENT,IDPT)   :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,ATTACK_TYPE,ASSET),
                                 damage_scenario(ASSET,PROPERTY_TYPE,_),
                                 attack_action2attack_surface(THREAT_DESCRIPTION,internal_interface),
                                 recommended_security_pattern(openIdConnect,IDTS,IDAT,CLIENT,SERVER),
                                 get_next_no_gateway_element_in_path(CLIENT,SERVER,ELEM),                                
                                 security_pattern(IDPT,openIdConnect,elem(CLIENT,ELEM,_),_,_,_),
                                 security_intent(openIdConnect,internal_interface,PROPERTY_TYPE,ATTACK_TYPE,PAT_TYPE).

mitigated_by(IDTS,CLIENT,IDPT) :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,spoofing,ASSET),
                                  damage_scenario(ASSET,PROPERTY_TYPE,_),
                                  attack_action2attack_surface(THREAT_DESCRIPTION,external_interface),
                                  recommended_security_pattern(openIdConnect,IDTS,IDAT,CLIENT,SERVER),
                                  get_next_no_gateway_element_in_path(CLIENT,SERVER,ELEM),
                                  security_pattern(IDPT,openIdConnect,elem(CLIENT,ELEM,_),_,_,_),
                                  security_intent(openIdConnect,external_interface,PROPERTY_TYPE,spoofing,PAT_TYPE),
                                  xsecurity_pattern(IDPAT1,istioServiceMesh,_,_,_,_),
                                  mesh_participant(IDPAT1,ELEM),
                                  security_pattern(IDPAT2,tls,elem(CLIENT,SERVER),_,_,_).                                    

%% #show mitigated_by_opid/4.
%% mitigated_by_opid(IDPT,THREAT,CLIENT,IDTS) :- mitigated_by(IDTS,CLIENT,IDPT),
%%                                               security_pattern(IDPT,openIdConnect,_,_,_,_),
%%                                               get_threat_from_threat_scenario(IDTS,THREAT).   


%% -------------------------------------------------------------------------- %%
%%                         Cilium
%% -------------------------------------------------------------------------- %%
% https://cilium.io/get-started/
% security_intent(PATTERN_NAME,ATTACK_SURFACE,SECURITY_PROPERTY,THREAT_TYPE,PATTERN_TYPE).
%% PATTERN_NAME specifies the name of the pattern
%% ATTACK_SURFACE specifies the type of attack surface suitable to apply the pattern
%% SECURITY_PROPERTY specifies the cyber security property satisfied by the pattern
%% THREAT_TYPE specifies the type of threat (STRIDE) 
%% PATTERN_TYPE specifies the type of pattern (mitigation, detection or prevention)
security_intent(cilium,attack_surface(internal_interface),
    property(authenticity,integrity,authorization),threat(spoofing,tampering,elevation_of_privilege),type(prevention)).

% === Cilium: Instantiation ===
security_pattern(ID,cilium,elem(CP1,CP2),INP,INT,OUT) :-
  xsecurity_pattern(ID,cilium,elem(CP1,CP2),INP,INT,OUT). 

%secPat(ID,cilium,CP1,0,0,1,no) :-
secPat(ID,cilium,not_applicable,0,0,1,no) :-
 security_pattern(ID,cilium,elem(CP1,CP2),INP,INT,OUT).

% === Cilium: Assumptions/Requirements ===
%% assumption(ID,has_encrypted_data_in_transit_using_IPsec_to_communicate_with_destination,elem(CP1,CP2)) :-
%%     xsecurity_pattern(ID,cilium,elem(CP1,CP2),INP,INT,OUT).

%% assumption(ID,has_encrypted_data_in_transit_using_IPsec_to_communicate_with_destination,elem(CP2,CP1)) :-
%%     xsecurity_pattern(ID,cilium,elem(CP1,CP2),INP,INT,OUT).

assumption(ID,is_authorized_to_publish,elem(CP1,TOPIC)) :-
    xsecurity_pattern(ID,cilium,elem(CP1,CP2),INP,INT,OUT),
    publisher(CP1,TOPIC).

assumption(ID,is_authorized_to_subscribe,elem(CP1,TOPIC)) :-
    xsecurity_pattern(ID,cilium,elem(CP1,CP2),INP,INT,OUT),
    subscriber(CP1,TOPIC).


% === Cilium: Technical/Infrasutrcture Assumptions/Requirements ===

%% application_requirement(ID,has_encrypted_data_in_transit_using_IPsec_to_communicate_with_destination,elem(CP1,CP2)) :-
%%     xsecurity_pattern(ID,cilium,elem(CP1,CP2),INP,INT,OUT),
%%     not no_application_requirement_due_to_infrastructure_task(ID,has_encrypted_data_in_transit_using_IPsec_to_communicate_with_destination,elem(CP1,CP2)).


%% application_requirement(ID,has_encrypted_data_in_transit_using_IPsec_to_communicate_with_destination,elem(CP2,CP1)) :-
%%     xsecurity_pattern(ID,cilium,elem(CP1,CP2),INP,INT,OUT),
%%     not no_application_requirement_due_to_infrastructure_task(ID,has_encrypted_data_in_transit_using_IPsec_to_communicate_with_destination,elem(CP2,CP1)).

infrastructure_requirement(ID,is_authorized_to_publish,elem(CP1,TOPIC)) :-
    xsecurity_pattern(ID,cilium,elem(CP1,CP2),INP,INT,OUT),
    publisher(CP1,TOPIC).

infrastructure_requirement(ID,is_authorized_to_subscribe,elem(CP1,TOPIC)) :-
    xsecurity_pattern(ID,cilium,elem(CP1,CP2),INP,INT,OUT),
    subscriber(CP1,TOPIC).

% === Cilium: Security argumentation ===
mitigated_by(IDTS,CLIENT,IDPT) :- xsecurity_pattern(IDPT,cilium,elem(CLIENT,SERVER),_,_,_),
                                  recommended_security_pattern(cilium,IDTS,IDAT,CLIENT,SERVER).

%% -------------------------------------------------------------------------- %%
%%               Security architecture pattern exploration
%% -------------------------------------------------------------------------- %%

%% %% %%%%%%% Authorization JWT Token (jwtToken) %%%%%%%
xsecurity_pattern(id_security_pattern(jwtToken,PUBLIC,SERVER),jwtToken,elem(PUBLIC,SERVER),nuINPUTS,nuINTERNAL,nuOUTPUTS)
    :- recommended_security_pattern(jwtToken,IDTS,IDAT,PUBLIC,SERVER),
       security_pattern(IDPT1,openIdConnect,elem(PUBLIC,_,_),_,_,_).

%% %%%%%%% Mutual Authentication pattern (mtls) %%%%%%%
xsecurity_pattern(id_security_pattern(mtls,CP1,CP2),mutualAuthentication,elem(CP1,CP2),nuINPUTS,nuINTERNAL,nuOUTPUTS)
    :- recommended_security_pattern(mutualAuthentication,IDTS,IDAT,CP1,X),
       get_next_no_gateway_element_in_path(CP1,X,CP2).

%%%%% TLS (tls) %%%%%%%
%% instantiates for outside attack paths
xsecurity_pattern(id_security_pattern(tls,PUBLIC,SERVER),tls,elem(PUBLIC,SERVER),nuINPUTS,nuINTERNAL,nuOUTPUTS)
    :- recommended_security_pattern(tls,IDTS,IDAT,PUBLIC,SERVER).  

%%%%%%% Service Mesh - istio (sMesh) %%%%%%%
xsecurity_pattern(istioServiceMesh,istioServiceMesh,elem(CP1,CP2,proxy(CP1),proxy(CP2)),nuINPUTS,nuINTERNAL,nuOUTPUTS)
    :- recommended_security_pattern(istioServiceMesh,IDTS,IDAT,CP1,X),
       get_next_no_gateway_element_in_path(CP1,X,CP2).

%% %%%%%%% Open Policy Agent (opa) %%%%%%%
xsecurity_pattern(id_security_pattern(opa,CP1),openPolicyAgent,elem(CP1,authorization_service(CP1_NAME)),nuINPUTS,nuINTERNAL,nuOUTPUTS)
    :- recommended_security_pattern(openPolicyAgent,IDTS,IDAT,CP1,CP2),
       getComponentName(CP1,CP1_NAME).       

     
%%%%%%% OpenId Connect (openidc) %%%%%%%
xsecurity_pattern(id_security_pattern(openidc,CP1,CP2),openIdConnect,elem(CP1,CP2,openIdServer(CP1)),nuINPUTS,nuINTERNAL,nuOUTPUTS)
    :- recommended_security_pattern(openIdConnect,IDTS,IDAT,CP1,X),
       get_next_no_gateway_element_in_path(CP1,X,CP2).

%% %%%%%%% Cilium (cilium) %%%%%%%
%% %% instantiates for inside attack paths
%xsecurity_pattern(id_security_pattern(cilium,CP1,CP2),cilium,elem(CP1,CP2),nuINPUTS,nuINTERNAL,nuOUTPUTS)
xsecurity_pattern(cilium,cilium,elem(CP1,CP2),nuINPUTS,nuINTERNAL,nuOUTPUTS)
    :- recommended_security_pattern(cilium,IDTS,IDAT,CP1,CP2).


% computes potential security patterns for addressing threat scenarios - internal interface
{ recommended_security_pattern(PAT,IDTS,IDAT,CP1,CP2) : 
  security_intent(PAT,internal_interface,PROPERTY_TYPE,THREAT_TYPE_STRIDE,PAT_TYPE),
   damage_scenario(ASSET,PROPERTY_TYPE,_)
  } = 1
     :- 
     threat_scenario(IDTS,THREAT_DESCRIPTION,_,THREAT_TYPE_STRIDE,ASSET),
     attack_action2attack_surface(THREAT_DESCRIPTION,internal_interface),
     get_attack_path_from_threat_scenario(IDTS,IDAT),
     attack_path(IDAT,CP1,CP2,MESSAGE,ASSET).

 % computes potential security patterns for addressing threat scenarios - external interface [insider intruder]
 { recommended_security_pattern(PAT,IDTS,IDAT,CP1,CP2) : 
     security_intent(PAT,external_interface,PROPERTY_TYPE,THREAT_TYPE_STRIDE,PAT_TYPE),
     damage_scenario(ASSET,PROPERTY_TYPE,_) } = 1
     :- 
     threat_scenario(IDTS,THREAT_DESCRIPTION,_,THREAT_TYPE_STRIDE,ASSET),
     attack_action2attack_surface(THREAT_DESCRIPTION,external_interface),
     get_attack_path_from_threat_scenario(IDTS,IDAT),
     attack_path(IDAT,CP1,CP2,MESSAGE,ASSET).

%     damage_scenario(ASSET,PROPERTY_TYPE,_),

%% % computes potential security patterns for addressing threat scenarios - external interface [outsider intruder]
 { recommended_security_pattern(PAT,IDTS,IDAT,PUBLIC,SERVER) : 
     security_intent(PAT,external_interface,PROPERTY_TYPE,THREAT_TYPE_STRIDE,PAT_TYPE),
     damage_scenario(ASSET,PROPERTY_TYPE,_)
  } = 1
     :- 
     threat_scenario(IDTS,THREAT_DESCRIPTION,_,THREAT_TYPE_STRIDE,ASSET),
     attack_action2attack_surface(THREAT_DESCRIPTION,external_interface),
     get_attack_path_from_threat_scenario(IDTS,IDAT),
     get_attack_surface_from_attack_path(IDAT,PUBLIC),
     public(PUBLIC),
     task_output_port(PUBLIC,PUBLIC_PORT),
     signal_with_ports(IDSIGNAL,PUBLIC_PORT,PUBLIC,SERVER_PORT,SERVER),
     @isPortMember(SERVER_PORT, IDAT) != false.    
%% -------------------------------------------------------------------------- %%
%%                                  Constraints
%% -------------------------------------------------------------------------- %%


%% Constraint 1) invalid solution: threat scenario not addressed
:- nmitigated(IDTS).

%% Constraint 2) invalid solution: two patterns for addressing the same threat scenario
:- mitigated_by(IDTS1,_,IDPT1),
    mitigated_by(IDTS2,_,IDPT2),
    security_pattern(IDPAT1,PAT1,_,_,_,_),
    security_pattern(IDPAT2,PAT2,_,_,_,_),
    get_threat_from_threat_scenario(IDTS1,THREAT),
    get_attack_path_from_threat_scenario(IDTS2,THREAT),   
    PAT1 != PAT2,
    IDPAT1 != IDPAT2,
    IDTS1 == IDTS2.


%% Constraint 3) invalid solution: mtls and tls for the same client and server
 :- security_pattern(IDPAT1,mutualAuthentication,elem(CLIENT,_),_,_,_), 
    security_pattern(IDPAT2,tls,elem(CLIENT,_),_,_,_).

%% Constraint 4) invalid solution: mtls for a public element
 :- security_pattern(IDPAT1,mutualAuthentication,elem(CLIENT,SERVER),_,_,_), 
    public(CLIENT).


%% Constraint 5) invalid solution: two common security patterns addressing different threat scenarios
%% %% %% %% % intended outcome: recommend only 1 security pattern for addressing the same type of threat scenarios.
 :-  mitigated_by(IDTS1,_,IDPAT1), 
     mitigated_by(IDTS2,_,IDPAT2), 
     get_attack_path_from_threat_scenario(IDTS1,IDAT1),
     get_attack_path_from_threat_scenario(IDTS2,IDAT2),
     security_pattern(IDPAT1,PAT1,_,_,_,_), 
     security_pattern(IDPAT2,PAT2,_,_,_,_), 
     IDPAT1 != IDPAT2,
     PAT1 != PAT2,
 %    recommended_common_pattern(PAT1,PAT2).
     threat_scenario(IDTS1,THREAT_DESCRIPTION1,_,THREAT_TYPE_STRIDE1,ASSET1),
     attack_action2attack_surface(THREAT_DESCRIPTION1,internal_interface),   
     threat_scenario(IDTS2,THREAT_DESCRIPTION2,_,THREAT_TYPE_STRIDE2,ASSET2),
     attack_action2attack_surface(THREAT_DESCRIPTION2,internal_interface),
     security_intent(PAT1,internal_interface,PROPERTY_TYPE,ATTACK_TYPE,_),
     security_intent(PAT2,internal_interface,PROPERTY_TYPE,ATTACK_TYPE,_).     


%% #show get_as_from_attack_path/3.
%% get_as_from_attack_path(AS,CP1,CP2) :-
%%  attack_path(IDAT,CP1,CP2,MESSAGE,ASSET),
%%  get_attack_surface_type(ASSET,AS). 


% NEW TEST!
%% :- mitigated_by(IDTS1,_,IDPT1),
%%    mitigated_by(IDTS2,_,IDPT2),
%%    get_pattern_name(IDPT1,PAT1),
%%    get_pattern_name(IDPT2,PAT2),
%%    get_attack_path_from_threat_scenario(IDTS1,IDAP),
%%    get_attack_path_from_threat_scenario(IDTS2,IDAP),
%%    recommended_security_pattern(PAT1,IDTS1,IDAT,_,_),
%%    recommended_security_pattern(PAT1,IDTS2,IDAT,_,_),   
%%    PAT1 != PAT2,
%%    IDTS1 != IDTS2.



%% #show test_constraint/1.
%% test_constraint(PAT) :- recommended_security_pattern(PAT,IDTS,IDAT,_,_),
%%               get_threat_from_threat_scenario(IDTS,THREAT),
%%               not mitigated_by_test(THREAT,PAT,_,_).


%% recommended_security_pattern(cilium,
%%     id_ts("sb_output_kafka_ID_9979",elevation_of_privilege,id_ap("Task_SB_Postgres_ID_9981","Task_SB_ID_9967","sb_output_kafka_ID_9979")),
%%     id_ap("Task_SB_Postgres_ID_9981","Task_SB_ID_9967","sb_output_kafka_ID_9979"),
%%     "Task_SB_Postgres_ID_9981","Task_SB_ID_9967"). 

%% recommended_security_pattern(cilium,id_ts("sb_output_db_ID_9977",elevation_of_privilege,id_ap("Task_SB_Postgres_ID_9981","Task_SB_ID_9967","sb_output_db_ID_9977")),
%%     id_ap("Task_SB_Postgres_ID_9981","Task_SB_ID_9967","sb_output_db_ID_9977"),
%%     "Task_SB_Postgres_ID_9981","Task_SB_ID_9967"). 

%%   mitigated_by(IDTS,_,IDPAT), 
%%   get_pattern_name(IDPAT,PAT),
%%   get_threat_from_threat_scenario(IDTS,THREAT),
%%   security_pattern(IDPAT,PAT,elem(CP1,CP2),_,_,_).


%% mitigated_by_test(THREAT,PAT,IDPAT,elem(CP1,CP2))



%% % ensure that only valid mapping for threat to cybersecurity properties are valid
%% :- security_intent(_,_,THREAT,SECURITY_PROPERTY,_),
%%    valid_threat2security_property(THREAT,SECURITY_PROPERTY).

%% %% %% % computes recommended patterns with the same signature (i.e., security intent)
%% recommended_common_pattern(PAT1,PAT2) :- 
%%   recommended_security_pattern(PAT1,_,_,_,_),
%%   recommended_security_pattern(PAT2,_,_,_,_),    
%%   security_intent(PAT1,internal_interface,PROPERTY_TYPE,ATTACK_TYPE,_),
%%   security_intent(PAT2,internal_interface,PROPERTY_TYPE,ATTACK_TYPE,_),
%%   PAT1 != PAT2.




%% :- mitigated_by(IDTS1,_,IDPT1),
%%    mitigated_by(IDTS2,_,IDPT2),
%%    security_pattern(IDPAT1,PAT1,_,_,_,_),
%%    security_pattern(IDPAT2,PAT2,_,_,_,_),
%%    get_threat_from_threat_scenario(IDTS1,THREAT),
%%    get_attack_path_from_threat_scenario(IDTS2,THREAT),   
%%    PAT1 != PAT2,
%%    IDPAT1 != IDPAT2,
%%    IDTS1 == IDTS2.

%% %% % recommended pattern for a threat has been instantiated 
%% pattern_instantiated_to_mitigate_threat_scenario(PAT,IDTS) :-
%%  recommended_security_pattern(PAT,IDTS,_,_,_),
%%  security_pattern(IDPAT,PAT,_,_,_,_),
%%  mitigated_by(IDTS,_,IDPAT),
%%  PAT != istioServiceMesh.

%% pattern_instantiated_to_mitigate_threat_scenario(PAT,IDTS) :-
%%  recommended_security_pattern(PAT,IDTS,_,_,_),
%%  security_pattern(IDPAT,istioServiceMesh,_,_,_,_),
%%  mitigated_by(IDTS,_,istioServiceMesh).

%% %% %% %% % invalid solution: potential recommended pattern for a threat is not instantiated 
%% #show test/1.
%% test(PAT) :- recommended_security_pattern(PAT,IDTS,_,_,_),
%%    not pattern_instantiated_to_mitigate_threat_scenario(PAT,IDTS).




%% % invalid solution: tls instantiations from server to client and client to server [this is mutualAuthentication]
%% :- security_pattern(IDPAT1,tls,elem(SERVER,CLIENT),_,_,_),
%%    security_pattern(IDPAT2,tls,elem(CLIENT,SERVER),_,_,_).

%% % invalid solution: both istio (service mesh) and mtls for addressing threats @ internal interface
%% :- security_pattern(IDPAT1,istioServiceMesh,elem(_,_,_,_),_,_,_), 
%%    security_pattern(IDPAT2,mutualAuthentication,elem(_,_),_,_,_),
%%    mitigated_by(IDTS1,_,IDPAT1),
%%    mitigated_by(IDTS2,_,IDPAT2),
%%    threat_scenario(IDTS1,THREAT_DESCRIPTION1,_,THREAT_TYPE_STRIDE1,ASSET1),
%%    attack_action2attack_surface(THREAT_DESCRIPTION1,internal_interface),   
%%    threat_scenario(IDTS2,THREAT_DESCRIPTION2,_,THREAT_TYPE_STRIDE2,ASSET2),
%%    attack_action2attack_surface(THREAT_DESCRIPTION2,internal_interface).

%% % invalid solution: both tls and mtls, where mtls is required for a public component
%% :- security_pattern(IDPAT1,tls,elem(CP1,_),_,_,_), 
%%    security_pattern(IDPAT2,mutualAuthentication,elem(CP2,_),_,_,_),
%%    mitigated_by(IDTS1,_,IDPAT1),
%%    mitigated_by(IDTS2,_,IDPAT2),
%%    threat_scenario(IDTS1,THREAT_DESCRIPTION1,_,THREAT_TYPE_STRIDE1,ASSET1),
%%    attack_action2attack_surface(THREAT_DESCRIPTION1,external_interface),   
%%    threat_scenario(IDTS2,THREAT_DESCRIPTION2,_,THREAT_TYPE_STRIDE2,ASSET2),
%%    attack_action2attack_surface(THREAT_DESCRIPTION2,external_interface),
%%    public(CP2).

%% %% % invalid solution: both istio (service mesh) and cilium for addressing threats @ internal interface
%% :- security_pattern(IDPAT1,istioServiceMesh,elem(_,_,_,_),_,_,_), 
%%    security_pattern(IDPAT2,cilium,elem(_,_),_,_,_),
%%    mitigated_by(IDTS1,_,IDPAT1),
%%    mitigated_by(IDTS2,_,IDPAT2),
%%    threat_scenario(IDTS1,THREAT_DESCRIPTION1,_,THREAT_TYPE_STRIDE1,ASSET1),
%%    attack_action2attack_surface(THREAT_DESCRIPTION1,internal_interface),   
%%    threat_scenario(IDTS2,THREAT_DESCRIPTION2,_,THREAT_TYPE_STRIDE2,ASSET2),
%%    attack_action2attack_surface(THREAT_DESCRIPTION2,internal_interface).

%% %% % invalid solution: both cilium and mtls for addressing threats @ internal interface
%% :- security_pattern(IDPAT1,mutualAuthentication,elem(_,_),_,_,_), 
%%    security_pattern(IDPAT2,cilium,elem(_,_),_,_,_),
%%    mitigated_by(IDTS1,_,IDPAT1),
%%    mitigated_by(IDTS2,_,IDPAT2),
%%    threat_scenario(IDTS1,THREAT_DESCRIPTION1,_,THREAT_TYPE_STRIDE1,ASSET1),
%%    attack_action2attack_surface(THREAT_DESCRIPTION1,internal_interface),   
%%    threat_scenario(IDTS2,THREAT_DESCRIPTION2,_,THREAT_TYPE_STRIDE2,ASSET2),
%%    attack_action2attack_surface(THREAT_DESCRIPTION2,internal_interface).


















%% #show diff_pattern_same_ts/4.
%% diff_pattern_same_ts(IDPAT1,IDPAT2,THREAT,IDTS1) 
%% :- mitigated_by(IDTS1,_,IDPT1),
%%    mitigated_by(IDTS2,_,IDPT2),
%%    IDPAT1 != IDPAT2,
%%    security_pattern(IDPAT1,PAT1,_,_,_,_),
%%    security_pattern(IDPAT2,PAT2,_,_,_,_),
%%    PAT1 != PAT2,
%%    get_threat_from_threat_scenario(IDTS1,THREAT),
%%    get_attack_path_from_threat_scenario(IDTS2,THREAT),
%%    IDTS1 == IDTS2.






%% :- security_pattern(_,cilium,_,_,_,_), 
%%    security_pattern(_,openPolicyAgent,_,_,_,_).

%% :- security_pattern(_,istioServiceMesh,_,_,_,_), 
%%    security_pattern(_,openPolicyAgent,_,_,_,_),
%%    mesh_participant(istioServiceMesh,CP1),
%%    mesh_participant(istioServiceMesh,CP2),
%%    not attack_path_to_gateway(_,CP1,CP2).   


%#show mesh_participant/2.
%% %#show test_mitigated_by/2.
%% %% test_mitigated_by(PAT,IDTS) :- mitigated_by(IDTS,_,PAT).

%% %% :- security_pattern(_,cilium,elem(CP1,CP2),_,_,_),
%% %%    attack_path_to_gateway(_,CP1,CP2).

%% %% :- security_pattern(_,cilium,elem(_,_),_,_,_),
%% %%    xsecurity_pattern(_,istioServiceMesh,elem(CP1,CP2,_,_),_,_,_),
%% %%  %  mesh_participant(istioServiceMesh,CP1),
%% %% %   mesh_participant(istioServiceMesh,CP2),
%% %%    not attack_path_to_gateway(_,CP1,CP2).







% =================== TEST =====================
%% %#show test_mitigated_by/3.

%% % ------------------ openIDConnect ----------------

%% test_security_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT) :-
%%   test_xsecurity_pattern(ID,openIdConnect,elem(CP1,CP2,OpenIdServer),INP,INT,OUT). 


%% test_xsecurity_pattern(id_security_pattern(openidc,PUBLIC,SERVER),openIdConnect,elem(PUBLIC,SERVER,openIdServer(PUBLIC)),nuINPUTS,nuINTERNAL,nuOUTPUTS)
%%     :- outside_recommended_security_pattern(openIdConnect,IDTS,IDAT,PUBLIC,SERVER).


%% test_mitigated_by(IDTS,CLIENT,IDPT)   :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,spoofing,ASSET),
%%                                  damage_scenario(ASSET,PROPERTY_TYPE,_),
%%                                  attack_action2attack_surface(THREAT_DESCRIPTION,external_interface),
%%                                  outside_recommended_security_pattern(openIdConnect,IDTS,IDAT,CLIENT,SERVER), 
%%                                  test_security_pattern(IDPT,openIdConnect,elem(CLIENT,SERVER,_),_,_,_),
%%                                  security_intent(openIdConnect,external_interface,PROPERTY_TYPE,spoofing,PAT_TYPE),
%%                                  test_security_pattern(IDPAT1,istioServiceMesh,elem(_,_,_,_),_,_,_),
%%                                  test_mesh_participant(IDPAT1,SERVER),
%%                                  test_security_pattern(IDPAT2,tls,elem(CLIENT,SERVER),_,_,_).                                    


%% % ------------------ istioServiceMesh ----------------

%% test_security_pattern(IDPAT,istioServiceMesh,elem(CLIENT,SERVER,PROXY_CLIENT,PROXY_SERVER),INP,INT,OUT)
%% :- test_xsecurity_pattern(IDPAT,istioServiceMesh,elem(CLIENT,SERVER,PROXY_CLIENT,PROXY_SERVER),INP,INT,OUT).

%% test_mesh_participant(istioServiceMesh,CP) :-
%%  mesh_participant(IDPAT,CP),
%%  test_xsecurity_pattern(IDPAT,istioServiceMesh,_,_,_,_).



%% test_mesh_participant(ID,CLIENT) :-
%%  test_xsecurity_pattern(ID,istioServiceMesh,elem(CLIENT,SERVER,PROXY_CLIENT,PROXY_SERVER),INP,INT,OUT),
%%  not public(CLIENT),
%%   not gateway(SERVER).


%% test_mesh_participant(ID,SERVER) :-
%%  test_xsecurity_pattern(ID,istioServiceMesh,elem(CLIENT,SERVER,PROXY_CLIENT,PROXY_SERVER),INP,INT,OUT),
%%  not public(SERVER).

%% test_mesh_participant(IDPAT,CLIENT) :-
%%        test_xsecurity_pattern(IDPAT,istioServiceMesh,elem(CLIENT,SERVER,_,_),_,_,_),
%%        test_security_pattern(IDPAT,istioServiceMesh,_,_,_,_),
%%        not test_is_in_the_mesh(CLIENT),
%%        not public(CLIENT),
%%        not gateway(SERVER).

%% test_mesh_participant(IDPAT,SERVER) :-
%%        test_xsecurity_pattern(IDPAT,istioServiceMesh,elem(CLIENT,SERVER,_,_),_,_,_),
%%        test_security_pattern(IDPAT,istioServiceMesh,_,_,_,_),
%%        not test_is_in_the_mesh(SERVER),
%%        not public(SERVER).

%% test_is_in_the_mesh(CP) :-
%%   test_mesh_participant(_,CP).

%% test_xsecurity_pattern(istioServiceMesh,istioServiceMesh,elem(CP1,CP2,proxy(CP1),proxy(CP2)),nuINPUTS,nuINTERNAL,nuOUTPUTS)
%%     :- outside_recommended_security_pattern(istioServiceMesh,IDTS,IDAT,CP1,CP2).

%% test_mitigated_by(IDTS,CLIENT,IDPT)   :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,elevation_of_privilege,ASSET),
%%                                  damage_scenario(ASSET,PROPERTY_TYPE,_),
%%                                  attack_action2attack_surface(THREAT_DESCRIPTION,external_interface),
%%                                  outside_recommended_security_pattern(istioServiceMesh,IDTS,IDAT,CLIENT,SERVER), 
%%                                  test_xsecurity_pattern(IDPT,istioServiceMesh,elem(CLIENT,SERVER,_,_),_,_,_),
%%                                  test_mesh_participant(IDPT,SERVER),
%%                                  security_intent(istioServiceMesh,external_interface,PROPERTY_TYPE,elevation_of_privilege,PAT_TYPE),
%%                                  test_security_pattern(IDPAT1,openIdConnect,elem(CLIENT,SERVER,_),_,_,_),
%%                                  test_security_pattern(IDPAT2,tls,elem(CLIENT,SERVER),_,_,_).

%% % ------------------ TLS ----------------
%% test_security_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT) :-
%%   test_xsecurity_pattern(ID,tls,elem(CLIENT,SERVER),INP,INT,OUT). 

%% test_mitigated_by(IDTS,CLIENT,IDPT)   :- threat_scenario(IDTS,THREAT_DESCRIPTION,_,tampering,ASSET),
%%                                     damage_scenario(ASSET,PROPERTY_TYPE,_),
%%                                     attack_action2attack_surface(THREAT_DESCRIPTION,external_interface),
%%                                     outside_recommended_security_pattern(tls,IDTS,IDAT,CLIENT,SERVER), 
%%                                     test_security_pattern(IDPT,tls,elem(CLIENT,SERVER),_,_,_),
%%                                     security_intent(tls,external_interface,PROPERTY_TYPE,tampering,PAT_TYPE).


%% test_xsecurity_pattern(id_security_pattern(tls,PUBLIC,SERVER),tls,elem(PUBLIC,SERVER),nuINPUTS,nuINTERNAL,nuOUTPUTS)
%%     :- outside_recommended_security_pattern(tls,IDTS,IDAT,PUBLIC,SERVER).  


%% %#show outside_recommended_security_pattern/5.
%% outside_recommended_security_pattern(PAT,IDTS,IDAT,CP1,CP2) :-
%%     security_intent(PAT,external_interface,PROPERTY_TYPE,THREAT_TYPE_STRIDE,PAT_TYPE),
%%     threat_scenario(IDTS,THREAT_DESCRIPTION,_,THREAT_TYPE_STRIDE,ASSET),
%%     attack_action2attack_surface(THREAT_DESCRIPTION,ATTACK_SURFACE),
%%     damage_scenario(ASSET,PROPERTY_TYPE,_),
%%     get_attack_path_from_threat_scenario(IDTS,IDAT),
%%     attack_path(IDAT,CP1,CP2,MESSAGE,ASSET).

% =================== END OF TEST =====================




%% -------------------------------------------------------------------------- %%
%%                       valid pattern combinations
%% -------------------------------------------------------------------------- %%

%%%%%%%%%%%% insider %%%%%%%%%%%%

%% serviceMesh (spoofing, tampering) + openPolicyAgent (elevation_of_privilege)
%% openIdConnect (spoofing, tampering) + openPolicyAgent (elevation_of_privilege)
%% mutualAuthentication (spoofing, tampering) + authorization (elevation_of_privilege)
%% openIdConnect (spoofing, tampering) + jwtToken(elevation_of_privilege)

%%%%%%%%%%%% outsider %%%%%%%%%%%%
%% [DELETE] mutualAuthentication (spoofing, tampering) + jwtToken(elevation_of_privilege)
%% mutualAuthentication (spoofing, tampering) + OAUTH (elevation_of_privilege) 
%% tls(spoofing, tampering) + openIdConnect(spoofing) + 
%%     serviceMesh_authz(elevation_of_privilege) + serviceMesh(spoofing, tampering)

% mutual exclusive
%% serviceMesh_istio (spoofing,tampering,elevation_of_privilege [authz])
%% serviceMesh_linkerd(spoofing,tampering) 