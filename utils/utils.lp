% a logical component is a software element
software(CP) :- component(CP).

% a task is a software element
software(CP) :- task(CP).

software(CP) :- component(CP),
            task(TASK),
            allocation(CP,TASK),
            ecu(ECU),
            allocation(TASK,ECU).

% ecu and network interfaces are hardware units
hardware(SRS) :- sensor(SRS).
hardware(ECU) :- ecu(ECU).
hardware(NET) :- network(NET).
hardware(CLUSTER) :- cluster(CLUSTER).

ecu_port(CLUSTER) :- cluster(CLUSTER,PORT).
ecu_port(CLUSTER) :- cluster(CLUSTER,PORT).


hardware_port(X,Y) :- sensor_port(X,Y).
hardware_port(X,Y) :- ecu_port(X,Y).
hardware_port(X,Y) :- network_port(X,Y).
hardware_port(X,Y) :- cluster_port(X,Y).

% === Get Safety functions ===

%% Safety Pattern
getSafPatName(IDPAT,PAT) :-  safety_pattern(IDPAT,PAT,_,_,_,_).


getSafPatTarget(IDPAT,TARGET) :- safety_pattern(IDPAT,PAT,elem(TARGET,REDUNDANCY,CHECKER),_,_,_).
getSafPatRedundancy(IDPAT,REDUNDANCY) :- safety_pattern(IDPAT,PAT,elem(TARGET,REDUNDANCY,CHECKER),_,_,_).

getSafPatTarget(IDPAT,TARGET) :- safety_pattern(IDPAT,_,elem(TARGET,REDUNDANCY1,REDUNDANCY2,CHECKER),_,_,_).
getSafPatRedundancy(IDPAT,REDUNDANCY1) :- safety_pattern(IDPAT,_,elem(TARGET,REDUNDANCY1,REDUNDANCY2,CHECKER),_,_,_).
getSafPatRedundancy(IDPAT,REDUNDANCY2) :- safety_pattern(IDPAT,_,elem(TARGET,REDUNDANCY1,REDUNDANCY2,CHECKER),_,_,_).


getSafPatTarget(IDPAT,TARGET) :- safety_pattern(IDPAT,_,elem(TARGET,REDUNDANCY1,REDUNDANCY2,_,_,_,CHECKER),_,_,_).
getSafPatRedundancy(IDPAT,REDUNDANCY1) :- safety_pattern(IDPAT,_,elem(TARGET,REDUNDANCY1,REDUNDANCY2,_,_,_,CHECKER),_,_,_).
getSafPatRedundancy(IDPAT,REDUNDANCY2) :- safety_pattern(IDPAT,_,elem(TARGET,REDUNDANCY1,REDUNDANCY2,_,_,_,CHECKER),_,_,_).


getSafPatChecker(IDPAT,CHECKER) :- safety_pattern(IDPAT,PAT,elem(_,_,CHECKER),_,_,_).
getSafPatChecker(IDPAT,CHECKER) :- safety_pattern(IDPAT,tripleModularRedundancy,elem(TARGET,REDUNDANCY1,REDUNDANCY2,CHECKER),_,_,_).
getSafPatChecker(IDPAT,CHECKER) :- safety_pattern(IDPAT,acceptanceVoting,elem(TARGET,REDUNDANCY1,REDUNDANCY2,_,_,_,CHECKER),_,_,_).
getSafPatChecker(IDPAT,TESTER1) :- safety_pattern(IDPAT,acceptanceVoting,elem(TARGET,REDUNDANCY1,REDUNDANCY2,TESTER1,TESTER2,TESTER3,_),_,_,_).
getSafPatChecker(IDPAT,TESTER2) :- safety_pattern(IDPAT,acceptanceVoting,elem(TARGET,REDUNDANCY1,REDUNDANCY2,TESTER1,TESTER2,TESTER3,_),_,_,_).
getSafPatChecker(IDPAT,TESTER3) :- safety_pattern(IDPAT,acceptanceVoting,elem(TARGET,REDUNDANCY1,REDUNDANCY2,TESTER1,TESTER2,TESTER3,_),_,_,_). 
getSafPatChecker(IDPAT,CHECKER) :- safety_pattern(IDPAT,monitorActuator,elem(TARGET,CHECKER),_,_,_).


homogeneous_duplex(IDPAT,PR,SE,FD) :- safety_pattern(IDPAT,homogeneousDuplex,elem(PR,SE,FD),_,_,_).
heterogeneous_duplex(IDPAT,PR,SE,FD) :- safety_pattern(IDPAT,heterogeneousDuplex,elem(PR,SE,FD),_,_,_).
simplex_architecture(IDPAT,PR,SE,MONITOR) :- safety_pattern(IDPAT,simplexArchitecture,elem(PR,SE,MONITOR),_,_,_).
triple_modular_redundancy(IDPAT,PR,SE,TE,VOTER) :- safety_pattern(IDPAT,tripleModularRedundancy,elem(PR,SE,TE,VOTER),_,_,_).
heterogeneous_triple_modular_redundancy(IDPAT,PR,SE,TE,VOTER) :- safety_pattern(IDPAT,heterogeneousTripleModularRedundancy,elem(PR,SE,TE,VOTER),_,_,_).
acceptance_voting(IDPAT,PR,SE,TE,TESTER1,TESTER2,TESTER3,VOTER) :- safety_pattern(IDPAT,acceptanceVoting,elem(PR,SE,TE,TESTER1,TESTER2,TESTER3,VOTER),_,_,_).




getSafPatTarget(IDPAT,TARGET) :- safety_pattern(IDPAT,monitorActuator,elem(TARGET,CHECKER),_,_,_).

getSafPatFaultType(IDPAT,FT_TYPE) :-  safety_pattern(IDPAT,PAT,_,_,_,_),
                          safetyIntent(PAT,FT_TYPE,FL_TYPE,ASIL,PAT_TYPE).

getSafPatFailureType(IDPAT,FL_TYPE) :-  safety_pattern(IDPAT,PAT,_,_,_,_),
                            safetyIntent(PAT,FT_TYPE,FL_TYPE,ASIL,PAT_TYPE).

getSafPatASIL(IDPAT,ASIL) :-  safety_pattern(IDPAT,PAT,_,_,_,_),
                  safetyIntent(PAT,FT_TYPE,FL_TYPE,ASIL,PAT_TYPE).

getSafPatType(IDPAT,PAT_TYPE) :-  safety_pattern(IDPAT,PAT,_,_,_,_),
                      safetyIntent(PAT,FT_TYPE,FL_TYPE,ASIL,PAT_TYPE).

%% Hazard
getHazardSev(IDHZ,SEV) :- hazard(IDHZ,SEV,EXP,CTL) .
getHazardExp(IDHZ,EXP) :- hazard(IDHZ,SEV,EXP,CTL) .
getHazardCtl(IDHZ,CTL) :- hazard(IDHZ,SEV,EXP,CTL) .
getHazardASIL(IDHZ,ASIL) :- hazard(IDHZ, SEV,EXP,CTL), asil(IDHZ,ASIL).

%% Fault
get_fault_type(IDFT,hardware) :- fault(IDFT,ELEMENT),
                   hardware(ELEMENT).

get_fault_type(IDFT,software) :- fault(IDFT,ELEMENT),
                   software(ELEMENT).
%% Safety intent
getSafIntentHWSWType(PAT,PAT_HWSW) :- safety_intent(PAT,PAT_HWSW,PAT_FAILTYPE,PAT_ASIL,PAT_TYPE).
getSafIntentFailureType(PAT,PAT_FAILTYPE) :- safety_intent(PAT,PAT_HWSW,PAT_FAILTYPE,PAT_ASIL,PAT_TYPE).
getSafIntentASIL(PAT,PAT_ASIL) :- safety_intent(PAT,PAT_HWSW,PAT_FAILTYPE,PAT_ASIL,PAT_TYPE).
getSafIntentPatType(PAT,PAT_TYPE) :- safety_intent(PAT,PAT_HWSW,PAT_FAILTYPE,PAT_ASIL,PAT_TYPE).

is_redundancy_pattern_component(REDUNDANCY,PATTERN) :- getSafPatRedundancy(IDPAT,REDUNDANCY), 
                                                       safety_pattern(IDPAT,PATTERN,elem(TARGET,_,_),_,_,_).

is_redundancy_pattern_component(REDUNDANCY,PATTERN) :- getSafPatRedundancy(IDPAT,REDUNDANCY), 
                                                       safety_pattern(IDPAT,PATTERN,elem(TARGET,_,_,_),_,_,_).

is_redundancy_pattern_component(REDUNDANCY,PATTERN) :- getSafPatRedundancy(IDPAT,REDUNDANCY), 
                                                       safety_pattern(IDPAT,PATTERN,elem(TARGET,_),_,_,_).

is_redundancy_pattern_component(REDUNDANCY,PATTERN) :- getSafPatRedundancy(IDPAT,REDUNDANCY), 
                                                       safety_pattern(IDPAT,PATTERN,elem(TARGET,_,_,_,_,_,_),_,_,_).


is_checker_pattern_component(CHECKER,PATTERN) :- getSafPatChecker(IDPAT,CHECKER), 
                                                 safety_pattern(IDPAT,PATTERN,elem(TARGET,_,_),_,_,_).

is_checker_pattern_component(CHECKER,PATTERN) :- getSafPatChecker(IDPAT,CHECKER), 
                                                 safety_pattern(IDPAT,PATTERN,elem(TARGET,_,_,_),_,_,_).

is_checker_pattern_component(CHECKER,PATTERN) :- getSafPatChecker(IDPAT,CHECKER), 
                                                 safety_pattern(IDPAT,PATTERN,elem(TARGET,_),_,_,_).

is_checker_pattern_component(CHECKER,PATTERN) :- getSafPatChecker(IDPAT,CHECKER), 
                                                 safety_pattern(IDPAT,PATTERN,elem(TARGET,_,_,_,_,_,_),_,_,_).

is_primary_or_redundant_pattern_component(CP,IDPT) :-
  getPrimary(CP,IDPT).

is_primary_or_redundant_pattern_component(CP,IDPT) :-
  getSecondary(CP,IDPT).

is_primary_or_redundant_pattern_component(CP,IDPT) :-
  getTertiary(CP,IDPT).
  
is_pattern_component(TARGET) :- safety_pattern(_,_,elem(TARGET,_,_),_,_,_).
is_pattern_component(TARGET) :- safety_pattern(_,tripleModularRedundancy,elem(TARGET,_,_,_),_,_,_).
is_pattern_component(TARGET) :- safety_pattern(_,monitorActuator,elem(TARGET,_),_,_,_).
is_pattern_component(TARGET) :- safety_pattern(_,acceptanceVoting,elem(TARGET,_,_,_,_,_,_),_,_,_).

is_heterogeneous_pattern(heterogeneousDuplex).
is_heterogeneous_pattern(simplexArchitecture).
is_heterogeneous_pattern(heterogeneousTripleModularRedundancy).
is_heterogeneous_pattern(acceptanceVoting).

getPrimary(COMPONENT,IDPT) :- 
  is_pattern_component_baseline(COMPONENT,IDPT,_,primary).

getSecondary(COMPONENT,IDPT) :- 
  is_pattern_component_baseline(COMPONENT,IDPT,_,secondary).

getTertiary(COMPONENT,IDPT) :- 
  is_pattern_component_baseline(COMPONENT,IDPT,_,tertiary).


is_soa_component(CP) :- subscriber(CP,_).
is_soa_component(CP) :- publisher(CP,_).

%% Security related

get_attack_type(ASSET,ATTACK_TYPE) :- threat_scenario_to_af3(ASSET,ATTACK_TYPE).

get_asset_type(ASSET,software) :- asset_software(ASSET).
get_asset_type(ASSET,data) :- asset_data(ASSET).
get_asset_type(ASSET,hardware) :- asset_hardware(ASSET).


is_subscriber(CP) :- subscriber(CP,_).

has_child_component_subscriber(CP,TOPIC) :- subscriber(CP,TOPIC),
                            sub_component(SUB_CP,CP),
                            subscriber(SUB_CP,TOPIC).

get_child_subscriber_topic(CP,TOPIC,CHILD) :- subscriber(CP,TOPIC),
                          sub_component(SUB_CP,CP),
                          subscriber(SUB_CP,TOPIC),
                          sub_component(CHILD,SUB_CP),
                          subscriber(CHILD,TOPIC).


get_child_subscriber_topic(CP,TOPIC,CHILD) :- subscriber(CP,TOPIC),
                          sub_component(CHILD,CP),
                          subscriber(CHILD,TOPIC),
                          not has_child_component_subscriber(CHILD,TOPIC).


has_child_component_publisher(CP,TOPIC) :- publisher(CP,TOPIC),
                           sub_component(SUB_CP,CP),
                           publisher(SUB_CP,TOPIC).


get_child_publisher_topic(CP,TOPIC,CHILD) :- publisher(CP,TOPIC),
                         sub_component(SUB_CP,CP),
                         publisher(SUB_CP,TOPIC),
                         sub_component(CHILD,SUB_CP),
                         publisher(CHILD,TOPIC).                     

get_child_publisher_topic(CP,TOPIC,CHILD) :- publisher(CP,TOPIC),
                         sub_component(CHILD,CP),
                         publisher(CHILD,TOPIC),
                         not has_child_component_publisher(CHILD,TOPIC).


get_hazard_description(ID,DESCRIPTION) :- hazard_af3(ID,SEV,EXP,CTL,DESCRIPTION).


has_fault(ELEMENT) :- fault(_,ELEMENT).


% allocation of input port from the logical architecture into input ports of the platform architecture
allocation(INPUT_PORT,INPUT_TRANSCEIVER) :- channel_with_ports(ID,OUTPUT_PORT,CP1,INPUT_PORT,CP2),
                            allocation(INPUT_PORT,INPUT_TASK),
                            allocation(INPUT_TASK,INPUT_TRANSCEIVER).

% allocation of output port from the logical architecture into output ports of the platform architecture
allocation(OUTPUT_PORT,OUTPUT_TRANSCEIVER) :- channel_with_ports(ID,OUTPUT_PORT,CP1,INPUT_PORT,CP2),
                              allocation(OUTPUT_PORT,OUTPUT_TASK),
                              allocation(OUTPUT_TASK,OUTPUT_TRANSCEIVER).

% allocation of logical components into hardware units
allocation(CP,ECU) :- component(CP),
            task(TASK),
            allocation(CP,TASK),
            ecu(ECU),
            allocation(TASK,ECU),
            component(SUB_CP),
            not has_subcomponent(SUB_CP,CP).

% allocation of logical components into hardware units
allocation(CP,ECU) :- component(CP),
            sub_component(SUB_CP,CP),
            task(TASK),
            allocation(SUB_CP,TASK),
            ecu(ECU),
            allocation(TASK,ECU).

allocation_LA_PA(CP,ECU) :- allocation(CP,ECU), component(CP), ecu(ECU).            

has_subcomponent(SUB_CP,CP) :- component(CP),
                   component(SUB_CP),
                   sub_component(SUB_CP,CP).



getComponentName(NAME_ID,NAME) :- component(NAME_ID), component_verbose(NAME_ID,NAME,ID).
getComponentName(NAME_ID,NAME_ID) :- component(NAME_ID), not has_component_verbose(NAME_ID).
getComponentName(NAME_ID,NAME_ID) :- task(NAME_ID), not has_component_verbose(NAME_ID).
getComponentID(NAME_ID,ID) :- component(NAME_ID), component_verbose(NAME_ID,NAME,ID). 

has_component_verbose(NAME_ID) :- component_verbose(NAME_ID,_,_).

% derive a channel from channel_with_ports 
channel(ID,CP1,CP2) :- channel_with_ports(ID,PORT1,CP1,PORT2,CP2).
transmission(ID,CP1,CP2) :- transmission_with_ports(ID,PORT1,CP1,PORT2,CP2).

% channels in the platform architecture are bidirectional
transmission_with_ports(ID,PORT2,CP2,PORT1,CP1) :- transmission_with_ports(ID,PORT1,CP1,PORT2,CP2), 
                             hardware(CP1), hardware(CP2).              




topic(TOPIC) :- publisher(PUB,TOPIC).
topic(TOPIC) :- subscriber(SUB,TOPIC).
topic(TOPIC) :- topic_member(TOPIC,MEMBER).

get_threat_from_threat_scenario(IDTS,THREAT_TYPE_STRIDE) :- threat_scenario(IDTS,THREAT_DESCRIPTION,FROM,THREAT_TYPE_STRIDE,ASSET).
get_attack_source_from_threat_scenario(IDTS,FROM) :- threat_scenario(IDTS,THREAT_DESCRIPTION,FROM,THREAT_TYPE_STRIDE,ASSET).

get_asset_from_threat_scenario(IDTS,ASSET) :- threat_scenario(IDTS,_,_,_,ASSET).

get_attack_path_from_threat_scenario(id_ts(ASSET,ATTACK_TYPE,ID_AT),ID_AT) :-
  threat_scenario(id_ts(ASSET,ATTACK_TYPE,ID_AT),_,_,_,_),
  attack_path(ID_AT,_,_),
  asset(ASSET).


get_attack_path_from_threat_scenario(id_ts(ASSET,ATTACK_TYPE,ID_AT),ID_AT) :-
  threat_scenario(id_ts(ASSET,ATTACK_TYPE,ID_AT),_,_,_,_),
  attack_path(ID_AT,_,_,_,_),
  asset(ASSET).

get_attack_surface_from_attack_path(ID_AT,ATTACK_SURFACE) :-
  attack_path(ID_AT,FROM_PORT,ASSET),
  hardware_port(ATTACK_SURFACE,FROM_PORT).

get_attack_surface_from_attack_path(ID_AT,ATTACK_SURFACE) :-
  attack_path(ID_AT,ATTACK_SURFACE,TARGET,TARGET_TOPIC,ASSET),
  component(ATTACK_SURFACE),
  component(TARGET),
  topic(TARGET_TOPIC),
  asset(ASSET).

get_attack_surface_from_attack_path(ID_AT,ATTACK_SURFACE) :-
  attack_path(ID_AT,ATTACK_SURFACE,TARGET,ASSET),
  component(ATTACK_SURFACE),
  component(TARGET),
  asset(ASSET).

get_attack_surface_from_attack_path(ID_AT,ATTACK_SURFACE) :-
  attack_path(ID_AT,ATTACK_SURFACE_PORT,ASSET),
  component_output_port(ATTACK_SURFACE,ATTACK_SURFACE_PORT,_),
  component(ATTACK_SURFACE).


get_attack_surface_from_attack_path(ID_AT,ATTACK_SURFACE) :-
  attack_path(ID_AT,ATTACK_SURFACE_PORT,ASSET),
  task_output_port(ATTACK_SURFACE,ATTACK_SURFACE_PORT),
  task(ATTACK_SURFACE).

link_loss_scenario_and_threat_scenario(IDLS,IDTS) :-
   loss_scenario(IDLS,FROM,ASSET,FAILURE_MODE,HAZARD),
   asset(ASSET), 
   threat_scenario(IDTS,_,_,_,ASSET),
   get_asset_from_threat_scenario(IDTS,ASSET).

link_loss_scenario_and_threat_scenario(IDLS,IDTS) :-
   loss_scenario(IDLS,ASSET,TOPIC,FAILURE_MODE,HAZARD),
   asset(ASSET), 
   threat_scenario(IDTS,_,_,_,ASSET),
   get_asset_from_threat_scenario(IDTS,ASSET).



security_intent(PATTERN,ATTACK_SURFACE,PROPERTY,THREAT,TYPE) :- security_intent(PATTERN,LIST_ATTACK_SURFACE,LIST_PROPERTY,LIST_THREAT,LIST_TYPE),
                         get_attack_surface_security_intent(PATTERN,LIST_ATTACK_SURFACE,ATTACK_SURFACE),
                         get_property_security_intent(PATTERN,LIST_PROPERTY,PROPERTY),
                         get_threat_security_intent(PATTERN,LIST_THREAT,THREAT),
                         get_type_security_intent(PATTERN,LIST_TYPE,TYPE),
                         not invalid_map_security_property_threat(PROPERTY,THREAT).


invalid_map_security_property_threat(integrity,spoofing).
invalid_map_security_property_threat(integrity,elevation_of_privilege).

invalid_map_security_property_threat(authorization,tampering).
invalid_map_security_property_threat(authorization,spoofing).


invalid_map_security_property_threat(authenticity,tampering).
invalid_map_security_property_threat(authenticity,elevation_of_privilege).


invalid_map_security_property_threat(integrity,denial_of_service).
invalid_map_security_property_threat(availability,tampering).
invalid_map_security_property_threat(availability,spoofing).
invalid_map_security_property_threat(availability,repudiation).
invalid_map_security_property_threat(availability,elevation_of_privilege).




get_attack_surface_security_intent(PATTERN,attack_surface(X), X) :- security_intent(PATTERN,attack_surface(X),_,_,_).
get_attack_surface_security_intent(PATTERN,attack_surface(X,Y), X) :- security_intent(PATTERN,attack_surface(X,Y),_,_,_).
get_attack_surface_security_intent(PATTERN,attack_surface(X,Y), Y) :- security_intent(PATTERN,attack_surface(X,Y),_,_,_).
get_attack_surface_security_intent(PATTERN,attack_surface(X,Y,Z), X) :- security_intent(PATTERN,attack_surface(X,Y,Z),_,_,_).
get_attack_surface_security_intent(PATTERN,attack_surface(X,Y,Z), Y) :- security_intent(PATTERN,attack_surface(X,Y,Z),_,_,_).
get_attack_surface_security_intent(PATTERN,attack_surface(X,Y,Z), Z) :- security_intent(PATTERN,attack_surface(X,Y,Z),_,_,_).

get_property_security_intent(PATTERN,property(X), X) :- security_intent(PATTERN,_,property(X),_,_).
get_property_security_intent(PATTERN,property(X,Y), X) :- security_intent(PATTERN,_,property(X,Y),_,_).
get_property_security_intent(PATTERN,property(X,Y), Y) :- security_intent(PATTERN,_,property(X,Y),_,_).
get_property_security_intent(PATTERN,property(X,Y,Z), X) :- security_intent(PATTERN,_,property(X,Y,Z),_,_).
get_property_security_intent(PATTERN,property(X,Y,Z), Y) :- security_intent(PATTERN,_,property(X,Y,Z),_,_).
get_property_security_intent(PATTERN,property(X,Y,Z), Z) :- security_intent(PATTERN,_,property(X,Y,Z),_,_).

get_threat_security_intent(PATTERN,threat(X), X) :- security_intent(PATTERN,_,_,threat(X),_).
get_threat_security_intent(PATTERN,threat(X,Y), X) :- security_intent(PATTERN,_,_,threat(X,Y),_).
get_threat_security_intent(PATTERN,threat(X,Y), Y) :- security_intent(PATTERN,_,_,threat(X,Y),_).
get_threat_security_intent(PATTERN,threat(X,Y,Z), X) :- security_intent(PATTERN,_,_,threat(X,Y,Z),_).
get_threat_security_intent(PATTERN,threat(X,Y,Z), Y) :- security_intent(PATTERN,_,_,threat(X,Y,Z),_).
get_threat_security_intent(PATTERN,threat(X,Y,Z), Z) :- security_intent(PATTERN,_,_,threat(X,Y,Z),_).

get_type_security_intent(PATTERN,type(X), X) :- security_intent(PATTERN,_,_,_,type(X)).
get_type_security_intent(PATTERN,type(X,Y), X) :- security_intent(PATTERN,_,_,_,type(X,Y)).
get_type_security_intent(PATTERN,type(X,Y), Y) :- security_intent(PATTERN,_,_,_,type(X,Y)).
get_type_security_intent(PATTERN,type(X,Y,Z), X) :- security_intent(PATTERN,_,_,_,type(X,Y,Z)).
get_type_security_intent(PATTERN,type(X,Y,Z), Y) :- security_intent(PATTERN,_,_,_,type(X,Y,Z)).
get_type_security_intent(PATTERN,type(X,Y,Z), Z) :- security_intent(PATTERN,_,_,_,type(X,Y,Z)).



get_attack_surface_firewall_pattern(id_pat(fwp,ATTACK_SURFACE,GATEWAY),ATTACK_SURFACE) :- 
  xsecurity_pattern(id_pat(fwp,ATTACK_SURFACE,GATEWAY),firewall,elem(FW,HW1,_),_,_,_).

asset_software(PORT) :- 
  asset(PORT),
  component_input_port(CP,PORT,_). 

asset_software(PORT) :- 
  asset(PORT),
  component_output_port(CP,PORT,_). 

asset_data(CH) :- 
  asset(CH),
  channel_with_ports(CH,_,_,_,_).

asset_software(PORT) :- 
  asset(PORT),
  task_input_port(CP,PORT). 

asset_software(PORT) :- 
  asset(PORT),
  task_output_port(CP,PORT). 

asset_data(CH) :- 
  asset(CH),
  signal_with_ports(CH,_,_,_,_).


% defines when two security architecture patterns have the same signature (security intent)
%% common_pattern(PAT1,PAT2) :- 
%%   threat_scenario(IDTS,THREAT_DESCRIPTION,_,ATTACK_TYPE,ASSET),
%%   damage_scenario(ASSET,PROPERTY_TYPE,_),
%%   get_attack_path_from_threat_scenario(IDTS,IDAT),
%%   attack_path(IDAT,CP1,CP2,MESSAGE,ASSET),
%%   component(CP1), component(CP2),
%%   attack_action2attack_surface(THREAT_DESCRIPTION,ATTACK_SURFACE),
%%   security_intent(PAT1,ATTACK_SURFACE,PROPERTY_TYPE,ATTACK_TYPE,_),
%%   security_intent(PAT2,ATTACK_SURFACE,PROPERTY_TYPE,ATTACK_TYPE,_),
%%   PAT1 != PAT2.  

% if an element is public - its input and output ports are also public
public(PORT) :- 
  public(ELEM),
  not port(ELEM),
  component_input_port(ELEM,PORT,_).

public(PORT) :- 
  public(ELEM),
  not port(ELEM),
  component_output_port(ELEM,PORT,_).

public(PORT) :- 
  public(ELEM),
  not port(ELEM),
  task_input_port(ELEM,PORT).

public(PORT) :- 
  public(ELEM),
  not port(ELEM),
  task_output_port(ELEM,PORT).


get_sub_component_with_task(CP1,CP1) :-
  component(CP1),
  task(TASK),
  allocation(CP1,TASK).


get_sub_component_with_task(CP1,CP2) :-
  component(CP1),
  task(TASK),
  not allocation(CP1,TASK),
  sub_component(CP2,CP1),
  allocation(CP2,TASK).

get_sub_component_with_task(CP1,CP3) :-
  component(CP1),
  task(TASK),
  not allocation(CP1,TASK),
  sub_component(CP2,CP1),
  not allocation(CP2,TASK),
  sub_component(CP3,CP2),
  allocation(CP2,TASK).


%% -------------------------------------------------------------------------- %%
%%                           Lua functions
%% -------------------------------------------------------------------------- %%

#script (lua)
clingo = require("clingo")
F = clingo.Function

function isPortMember(port, path)
  if path.name == "nil" then
    return F("false")
  end
  if path.name == "cons" then
    local other_port = path.arguments[1]
    local tail = path.arguments[4]
    if port == other_port then
      return F("true")
    else
      return isPortMember(port, tail)
    end
  end
end
#end.

#script (lua)
clingo = require("clingo")
F = clingo.Function

function isComponentMember(hw, path)
  if path.name == "nil" then
    return F("false")
  end
  if path.name == "cons" then
    local other_hw = path.arguments[2]
    local tail = path.arguments[4]
    if hw == other_hw then
      return F("true")
    else
      return isComponentMember(hw, tail)
    end
  end
end
#end.


#script (lua)
clingo = require("clingo")
F = clingo.Function

function subList(hw1,hw2,tmp_source,path)
  if path.name == "nil" then
    return F("false")
  end
  if path.name == "cons" then
    local first = path.arguments[1]
    local tail = path.arguments[4]
    if( (hw1 == tmp_source and hw2 == first)) then
      return F("true")
    else
      return subList(hw1, hw2, first, tail)
    end
  end
end
#end.

%% Returns the position of a member in the attack path
#script (lua)
clingo = require("clingo")
F = clingo.Function

function positionOfMember(hw1,path)
  if path.name == "nil" then
    return F("false")
  end
  if path.name == "cons" then
    local hw_in_path = path.arguments[2]
    local hw_in_counter = path.arguments[3]
    local tail = path.arguments[4]
    if( (hw1 == hw_in_path)) then
      return hw_in_counter
    else
      return positionOfMember(hw1,tail)
    end
  end
end
#end.

%% Returns the position of a hardware port in the attack path
#script (lua)
clingo = require("clingo")
F = clingo.Function

function getPositionInPathFromHWPort(hw_port,path)
  if path.name == "nil" then
    return F("false")
  end
  if path.name == "cons" then
    local hw_port_in_path = path.arguments[1]
    local hw_port_position_in_path = path.arguments[3]
    local tail = path.arguments[4]
    if( (hw_port_in_path == hw_port)) then
      return hw_port_position_in_path
    else
      return getPositionInPathFromHWPort(hw_port,tail)
    end
  end
end
#end.

%% Returns the hardware port of a particular position
#script (lua)
clingo = require("clingo")
F = clingo.Function

function getHWPortInPathFromPosition(hw_position,path)
  if path.name == "nil" then
    return F("false")
  end
  if path.name == "cons" then
    local hw_port_in_path = path.arguments[1]  
    local hw_port_position_in_path = path.arguments[3]
    local tail = path.arguments[4]
    if( (hw_port_position_in_path == hw_position)) then
      return hw_port_in_path
    else
      return getHWPortInPathFromPosition(hw_position,tail)
    end
  end
end
#end.



%% Returns true if a hardware unit is in the attack path
#script (lua)
clingo = require("clingo")
F = clingo.Function

function member(hw1,path)
  if path.name == "nil" then
    return F("false")
  end
  if path.name == "cons" then
    local hw_in_path = path.arguments[2]
    local hw_in_counter = path.arguments[3]
    local tail = path.arguments[4]
    if( (hw1 == hw_in_path)) then
      return F("true")
    else
      return member(hw1,tail)
    end
  end
end
#end.

#script (lua)
clingo = require("clingo")
F = clingo.Function

function length(path,len)
  if path.name == "nil" then
    return 0
  end
  if path.name == "cons" then
    local len = path.arguments[3]
      return len
  end
end
#end.

%% Returns the last common hardware unit between two attack paths
#script (lua)
clingo = require("clingo")
F = clingo.Function

function commomHWinPath(path1,path2,common)
  if ((path1.name == "nil" or path2.name == "nil")) then
    return common
  end
  if path1.name == "cons" then
    local hw_path1 = path1.arguments[2]
    local hw_path2 = path2.arguments[2]
    local tail_path1 = path1.arguments[4]
    local tail_path2 = path2.arguments[4]
    if(hw_path1 == hw_path2) then
        return commomHWinPath(tail_path1,tail_path2,hw_path1)
    else
        return common      
    end
  end
end
#end.


%% Returns the position of the last common hardware unit between two attack paths
#script (lua)
clingo = require("clingo")
F = clingo.Function

function commomPositionHWinPath(path1,path2,counter)
  if ((path1.name == "nil" or path2.name == "nil")) then
    return counter
  end
  if path1.name == "cons" then
    local hw_path1 = path1.arguments[2]
    local hw_path2 = path2.arguments[2]
    local tail_path1 = path1.arguments[4]
    local tail_path2 = path2.arguments[4]
    local counter_path1 = path1.arguments[3]
    if(hw_path1 == hw_path2) then
        return commomPositionHWinPath(tail_path1,tail_path2,counter_path1)
    else
        return counter      
    end
  end
end
#end.

