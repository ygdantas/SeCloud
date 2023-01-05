%% -------------------------------------------------------------------------- %%
%%             debugging: #show PREDICATE/NUMBER_OF_PARAMETERS
%% -------------------------------------------------------------------------- %%

%#show attack_path/5.
%#show damage_scenario/3.
%#show threat_scenario/5.
%#show get_attack_surface_type/2.
%% #show public/1.
%% #show get_attack_surface_from_attack_path/2.
%#show attack_path_insider/7.
%#show get_attack_surface_from_attack_path/2.
%#show get_attack_path_from_threat_scenario/2.

% === Outputs needed by AF3 Plugin  ===
#show threat_scenario/5.


%% asset(PORT) :-
%%   asset_af3(CP),
%%   get_sub_component_with_task(CP,CP1),
%%   task(TASK),
%%   allocation(CP1,TASK),
%%   task_output_port(TASK,PORT). 

asset(TASK) :-
  asset_af3(CP),
  get_sub_component_with_task(CP,CP1),
  task(TASK),
  allocation(CP1,TASK),
  task_output_port(TASK,PORT). 



get_attack_surface_type(FROM,external_interface) :- attack_path(ID_AT,FROM,ASSET),
                                                    public(FROM).

get_attack_surface_type(ASSET,external_interface) :- attack_path(ID_AT,CP1,CP2,_,ASSET),
                                                     port(ASSET),
                                                     is_external_interface(CP1,CP2).

get_attack_surface_type(ASSET,internal_interface) :- attack_path(ID_AT,CP1,CP2,_,ASSET),
                                                     port(ASSET),
                                                     not is_external_interface(CP1,CP2).

get_attack_surface_type(ASSET,external_interface) :- attack_path(ID_AT,CP1,ASSET,_,ASSET),
                                                     is_external_interface(CP1,ASSET).

get_attack_surface_type(ASSET,internal_interface) :- attack_path(ID_AT,CP1,ASSET,_,ASSET),
                                                     not is_external_interface(CP1,ASSET).  

is_external_interface(CP1,CP2) :- gateway(CP1), task(CP2).
is_external_interface(CP1,CP2) :- gateway(CP2), task(CP1).
is_external_interface(CP1,CP2) :- 
  signal_with_ports(_,_,CP2,_,GW),
  gateway(GW),
  task(CP1).
  

defines_threat(internal_interface,authenticity,spoofing).
defines_threat(internal_interface,integrity,tampering).
defines_threat(internal_interface,authorization,elevation_of_privilege).
%defines_threat(internal_interface,availability,denial_of_service).

defines_threat(external_interface,authenticity,spoofing).
defines_threat(external_interface,integrity,tampering).
defines_threat(external_interface,authorization,elevation_of_privilege).
%defines_threat(external_interface,availability,denial_of_service).



% defines attack action/description
attack_surface_threat_type2attack_action(internal_interface,tampering,attacker_tampers_with_input_at_the_C2C_interface).
attack_surface_threat_type2attack_action(internal_interface,elevation_of_privilege,attacker_gains_elevated_access_to_resources_and_sends_malicious_input_to_C2C_interface).
attack_surface_threat_type2attack_action(internal_interface,spoofing,attacker_spoofs_input_at_the_C2C_interface).
attack_surface_threat_type2attack_action(internal_interface,denial_of_service,attacker_exhausts_system_resources_from_component).

attack_surface_threat_type2attack_action(external_interface,spoofing,attacker_enters_malicious_input_at_the_network_interface).
attack_surface_threat_type2attack_action(external_interface,tampering,attacker_tampers_with_input_at_the_network_interface).
attack_surface_threat_type2attack_action(external_interface,elevation_of_privilege,attacker_gains_elevated_access_to_resources_and_sends_malicious_input_at_the_network_interface).
attack_surface_threat_type2attack_action(external_interface,denial_of_service,attacker_exhausts_system_resources_from_network_interface).



attack_action2attack_surface(attacker_tampers_with_input_at_the_C2C_interface,internal_interface).
attack_action2attack_surface(attacker_gains_elevated_access_to_resources_and_sends_malicious_input_to_C2C_interface,internal_interface).
attack_action2attack_surface(attacker_spoofs_input_at_the_C2C_interface,internal_interface).
attack_action2attack_surface(attacker_exhausts_system_resources_from_component,internal_interface).

attack_action2attack_surface(attacker_enters_malicious_input_at_the_network_interface,external_interface).
attack_action2attack_surface(attacker_gains_elevated_access_to_resources_and_sends_malicious_input_at_the_network_interface,external_interface).
attack_action2attack_surface(attacker_tampers_with_input_at_the_network_interface,external_interface).
attack_action2attack_surface(attacker_exhausts_system_resources_from_network_interface,external_interface).

% relevant security properties
relevant_security_property(integrity).
relevant_security_property(authenticity).
relevant_security_property(authorization).

damage_scenario(ASSET,SECURITY_PROPERTY,tbd_by_user) :- asset(ASSET),
                                                        relevant_security_property(SECURITY_PROPERTY).  
% insider intruder
threat_scenario(id_ts(ASSET,THREAT_TYPE_STRIDE,ID_AT),THREAT_DESCRIPTION,FROM_PORT,THREAT_TYPE_STRIDE,ASSET) :-
    damage_scenario(ASSET,SECURITY_PROPERTY,_),
    attack_path(ID_AT,FROM,TARGET,TOPIC,ASSET),
    task_output_port(FROM,FROM_PORT),
    signal_with_ports(SIGNAL,FROM_PORT,FROM,TARGET_PORT,TARGET),
    get_attack_surface_type(ASSET,ATTACK_SURFACE_DESCRIPTION),
    defines_threat(ATTACK_SURFACE,SECURITY_PROPERTY,THREAT_TYPE_STRIDE),
    attack_surface_threat_type2attack_action(ATTACK_SURFACE_DESCRIPTION,THREAT_TYPE_STRIDE,THREAT_DESCRIPTION).


% outsider intruder
threat_scenario(id_ts(ASSET,THREAT_TYPE_STRIDE,ID_AT),THREAT_DESCRIPTION,FROM_PORT,THREAT_TYPE_STRIDE,ASSET) :-
    damage_scenario(ASSET,SECURITY_PROPERTY,_),
    attack_path(ID_AT,FROM_PORT,ASSET),
    task_output_port(FROM,FROM_PORT),
    public(FROM),
    get_attack_surface_type(FROM_PORT,ATTACK_SURFACE_TYPE),
    defines_threat(ATTACK_SURFACE_TYPE,SECURITY_PROPERTY,THREAT_TYPE_STRIDE),
    attack_surface_threat_type2attack_action(ATTACK_SURFACE_TYPE,THREAT_TYPE_STRIDE,THREAT_DESCRIPTION).