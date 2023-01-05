% mapping of ASIL assigned in AutoFOCUS3 to SafPat (arch_element_asil)
arch_element_asil(ID,nspec) :- cpASILaf3(ID,"5"). % architecture element ID is "5" denotes that the ASIL of architecture element ID has not been assigned
arch_element_asil(ID,d) :- cpASILaf3(ID,"4"). % architecture element ID is "4" denotes that architecture element has been assigned to ASIL D
arch_element_asil(ID,c) :- cpASILaf3(ID,"3"). % architecture element ID is "3" denotes that architecture element has been assigned to ASIL C
arch_element_asil(ID,b) :- cpASILaf3(ID,"2"). % architecture element ID is "2" denotes that architecture element has been assigned to ASIL B
arch_element_asil(ID,a) :- cpASILaf3(ID,"1"). % architecture element ID is "1" denotes that architecture element has been assigned to ASIL A
arch_element_asil(ID,qm) :- cpASILaf3(ID,"0"). % architecture element ID is "0" denotes that architecture element has been assigned to QM

% mapping of safety artifacts from af3 to safpat

% mapping of safety measure type
map_safety_measure_type_from_af3("FAULT_DETECTION",fault_detection).
map_safety_measure_type_from_af3("FAULT_TOLERANT",fault_tolerant).

safety_measure_type(IDSG,TYPE,IDHZ) :- safety_measure_type_af3(IDSG,TYPE_AF3,IDHZ),
                                       map_safety_measure_type_from_af3(TYPE_AF3,TYPE).


% mapping of hazards to safpat
hazard(ID,NEW_SEV,NEW_EXP,NEW_CTL) :- hazard_af3(ID,SEV,EXP,CTL,_), 
                                      map_hazard_from_af3(SEV,NEW_SEV), 
                                      map_hazard_from_af3(EXP,NEW_EXP), 
                                      map_hazard_from_af3(CTL,NEW_CTL).

hazard(ID,NEW_SEV,NEW_EXP,NEW_CTL) :- hazard_af3(ID,SEV,EXP,CTL), 
                                      map_hazard_from_af3(SEV,NEW_SEV), 
                                      map_hazard_from_af3(EXP,NEW_EXP), 
                                      map_hazard_from_af3(CTL,NEW_CTL).

%% hazard_af3("hz_118482","SEVERITY_3","EXPOSURE_4","CONTROLLABILITY_3","Test").
%% loss_scenario_af3("ls_118483_localization_ID_114419_FAILURE_ERRONEOUS_topic__apollo__localization__pose",
%%  "localization_ID_114419",
%%  "topic__apollo__localization__pose",
%%  "FAILURE_ERRONEOUS","hz_118482").


map_hazard_from_af3("SEVERITY_3",s3).
map_hazard_from_af3("SEVERITY_2",s2).
map_hazard_from_af3("SEVERITY_1",s1).
map_hazard_from_af3("SEVERITY_0",s0).
map_hazard_from_af3("EXPOSURE_4",e4).
map_hazard_from_af3("EXPOSURE_3",e3).
map_hazard_from_af3("EXPOSURE_2",e2).
map_hazard_from_af3("EXPOSURE_1",e1).
map_hazard_from_af3("EXPOSURE_0",e0).
map_hazard_from_af3("CONTROLLABILITY_3",c3).
map_hazard_from_af3("CONTROLLABILITY_2",c2).
map_hazard_from_af3("CONTROLLABILITY_1",c1).
map_hazard_from_af3("CONTROLLABILITY_0",c0).


% mapping of loss scenarios to safpat
loss_scenario(ID,CP,TOPIC,NEW_FAILURE_MODE,HZ) :- 
  loss_scenario_af3(ID,CP,TOPIC,FAILURE_MODE,HZ), 
  map_failure_mode_from_af3(FAILURE_MODE,NEW_FAILURE_MODE),
  publisher(CP,TOPIC).

loss_scenario_verbose(ID,FROM_CP,TO_CP,TOPIC,NEW_FAILURE_MODE,HZ) :- 
  loss_scenario_af3(ID,FROM_CP,TO_CP,TOPIC,FAILURE_MODE,HZ), 
  map_failure_mode_from_af3(FAILURE_MODE,NEW_FAILURE_MODE).


map_failure_mode_from_af3("FAILURE_LOSS",loss).
map_failure_mode_from_af3("FAILURE_ERRONEOUS",erroneous).


has_safety_pattern_baseline(CP,NEW_FAILURE_MODE) :- has_safety_pattern_af3(CP,FAILURE_MODE), map_failure_mode_from_af3(FAILURE_MODE,NEW_FAILURE_MODE).


% non-safety-critical topics - hardcoded from a manual analysis in the af3 model
non_safety_critical("topic__apollo_task").
non_safety_critical("topic__apollo__routing__request").
non_safety_critical("topic__apollo__routing__response").


is_pattern_component_baseline(CP,PATTERN_ID,ADAPTED_PATTERN_NAME,ADAPTED_CP_ROLE) :-
  is_pattern_component_baseline_af3(CP,PATTERN_ID,PATTERN_NAME,CP_ROLE),
  adapt_pattern_name(PATTERN_NAME,ADAPTED_PATTERN_NAME),
  adapt_component_role(CP_ROLE,ADAPTED_CP_ROLE).


adapt_pattern_name("heterogeneousDuplex",heterogeneousDuplex).
adapt_pattern_name("homogeneousDuplex",homogeneousDuplex).
adapt_pattern_name("monitorActuator",monitorActuator).
adapt_pattern_name("simplexArchitecture",simplexArchitecture).
adapt_pattern_name("heterogeneousTripleModularRedundancy",heterogeneousTripleModularRedundancy). 
adapt_pattern_name("acceptanceVoting",acceptanceVoting).  
adapt_pattern_name("no_identified_pattern",no_identified_pattern).

adapt_component_role("primary",primary).
adapt_component_role("secondary",secondary).
adapt_component_role("tertiary",tertiary).
adapt_component_role("monitor",monitor).
adapt_component_role("voter",voter).
adapt_component_role("no_identified_pattern_role",no_identified_pattern_role).


% following af3 allocation: component to task after a safety pattern was applied
allocation(CP,ECU) :- component(CP),
                      ecu(ECU),
                      sub_component(CP,PARENT),
                      is_pattern_component_baseline(PARENT,_,_,_),
                      not allocation(CP,TASK),
                      task(TASK),
                      allocation(PARENT,ECU).


component(NAME_ID) :- component_verbose(NAME_ID,NAME,ID).
component(CP) :- component_input_port(CP,_,_).
component(CP) :- component_output_port(CP,_,_).

input_port(PORT) :- component_input_port(CP,PORT,_).
output_port(PORT) :- component_output_port(CP,PORT,_).

port(PORT) :- input_port(PORT).
port(PORT) :- output_port(PORT).

topic(TOPIC) :- component_input_port(CP,PORT,TOPIC).
topic(TOPIC) :- component_output_port(CP,PORT,TOPIC).

input_port(PORT) :- task_input_port(TASK,PORT).
output_port(PORT) :- task_output_port(TASK,PORT).



% a task is public if the task is allocated to a public ECU
public(TASK) :-
 task(TASK),
 ecu(ECU),
 public(ECU),
 allocation(TASK,ECU).

% a task is public if the partition (where the task is allocated) is allocated to a public ECU
public(TASK) :-
 task(TASK),
 partition(PART),
 allocation(TASK,PART),
 ecu(ECU),
 public(ECU),
 allocation(PART,ECU).

% a task is a gateway if the partition (where the task is allocated) is allocated to a gateway ECU
 gateway(TASK) :-
   task(TASK),
   partition(PART),
   allocation(TASK,PART),
   ecu(ECU),
   gateway(ECU),
   allocation(PART,ECU).

% a task is a gateway if the task is allocated to a gateway ECU
 gateway(TASK) :-
   task(TASK),
   ecu(ECU),
   gateway(ECU),
   allocation(TASK,ECU).

% an ECU is internal (private) if the ECU is neither public nor a gateway
internal(ECU) :-
 ecu(ECU),
 not public(ECU),
 not gateway(ECU).

% a task is internal (private) if the task is allocated to an internal ECU
internal(TASK) :-
 task(TASK),
 ecu(ECU),
 internal(ECU),
 allocation(TASK,ECU).

infrastructure_task(TASK) :-
  task(TASK),
  gateway(TASK).


is_infrastructure_task(TASK1,TASK2) :-
  infrastructure_task(TASK1),
  task(TASK1),
  task(TASK2).

is_infrastructure_task(TASK1,TASK2) :-
  infrastructure_task(TASK2),
  task(TASK2),
  task(TASK1).

subscriber(TASK,TOPIC) :-
 component(CP),
 subscriber(CP,TOPIC),
 task(TASK),
 allocation(CP,TASK).

publisher(TASK,TOPIC) :-
 component(CP),
 publisher(CP,TOPIC),
 task(TASK),
 allocation(CP,TASK).

% HACK
%% allocation(TASK,ECU) :- 
%%   task(TASK),
%%   not has_allocation_task_partition(TASK),
%%   ecu(ECU),
%%   public(ECU).

%% has_allocation_task_partition(TASK) :-
%%   task(TASK),
%%   partition(PART),
%%   allocation(TASK,PART).   
