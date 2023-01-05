%% -------------------------------------------------------------------------- %%
%%            outsider intruder reachability rules and attack path rules
%% -------------------------------------------------------------------------- %%

%#show path/4.
%#show attack_path_outsider/3.
%#show attack_path/3.

% === Outputs needed by AF3 Plugin  ===
#show attack_path_outsider/3.

% base case: output port of an asset is in the path
path(cons(ASSET_PORT, ASSET, 0, nil), ASSET_PORT, ASSET, 0) :- 
                         asset(ASSET),
                         task_output_port(ASSET,ASSET_PORT),
                         reachable(ASSET,ASSET_PORT).


%% Condition 1: get the input port from the current component in the path
path(cons(CP_INPUT_PORT, CP, I+1, Id), CP_INPUT_PORT, ASSET, I+1) :- 
   I >= 0,
   path(Id, CP_OUTPUT_PORT, ASSET, I),
   task_output_port(CP,CP_OUTPUT_PORT),
   task_input_port(CP,CP_INPUT_PORT),   
   task_output_port(CP1,CP1_OUTPUT_PORT),
   signal_with_ports(IDCH,CP1_OUTPUT_PORT,CP1,CP_INPUT_PORT,CP),
   reachable(CP,CP_INPUT_PORT),
   @isComponentMember(CP1, Id) == false. 
%   @isHWUnitMember(HW_UNIT, Id) == false. % no loops on path

%% Condition 2: if the current port of the component has a channel to a port already included in the path, take another port from the same component
path(cons(CP1_PORT_OTHER, CP1, I+1, Id), CP1_PORT_OTHER, ASSET, I+1) :- 
   I > 0,
   path(Id, CP1_PORT, ASSET, I),
   task_input_port(CP1,CP1_PORT),
   task_output_port(CP2,CP2_PORT),
   reachable(CP2,CP2_PORT),
   signal_with_ports(IDCH1,CP2_PORT,CP2,CP1_PORT,CP1),   
   @isPortMember(CP2_PORT, Id) == true,
   task_input_port(CP1,CP1_PORT_OTHER),
   task_output_port(CP3,CP3_PORT),
   reachable(CP3,CP3_PORT),
   reachable(CP1,CP1_PORT_OTHER),
   signal_with_ports(IDCH2,CP3_PORT,CP3,CP1_PORT_OTHER,CP1),
%   not path_enters_component(Id),
   @isPortMember(CP1_PORT_OTHER, Id) == false,
   @isPortMember(CP3_PORT, Id) == false. % no loops on path   

%% Condition 3: if the current port of the component has a channel not included in the path, take the output port of the next component 
path(cons(CP2_PORT, CP2, I+1, Id), CP2_PORT, ASSET, I+1) :- 
   I > 0,
   path(Id, CP1_PORT, ASSET, I),
   task_input_port(CP1,CP1_PORT),
   task_output_port(CP2,CP2_PORT),
   reachable(CP2,CP2_PORT),
   signal_with_ports(IDCH1,CP2_PORT,CP2,CP1_PORT,CP1),   
   @isComponentMember(CP2, Id) == false.          

% Path begins by going inside a component, i.e. it looks like this:
%     +---------                       
%     |    +----
%     o----o---->
%     |    +----
%     +----------
path_enters_component(Id) :-
  path(Id, _, _, _),
  Id == cons(_, Unit1, _, Id2),
  Id2 == cons(_, Unit2, _, _),
  sub_component(Unit2, Unit1).


  % Computes attach paths from public elements to assets, identified as cons-lists,
% where e.g. [x1, x2, x3] is represented by cons(x1, cons(x2, cons(x3, nil)))
attack_path(Id, PUBLIC_PORT, ASSET) :- 
  public(PUBLIC_PORT),
  task_output_port(PUBLIC,PUBLIC_PORT),
  signal_with_ports(SIGNAL,PUBLIC_PORT,PUBLIC,_,_),
  path(Id, PUBLIC_PORT, ASSET, _).

% attack_path_outsider is relevant for af3
attack_path_outsider(Id, PUBLIC_PORT, ASSET) :- 
  public(PUBLIC_PORT),
  task_output_port(PUBLIC,PUBLIC_PORT),
  signal_with_ports(SIGNAL,PUBLIC_PORT,PUBLIC,_,_),  
  path(Id, PUBLIC_PORT, ASSET, _).
