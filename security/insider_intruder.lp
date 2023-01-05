%% -------------------------------------------------------------------------- %%
%%            insider intruder reachability rules and attack path rules
%% -------------------------------------------------------------------------- %%
%#show attack_path/5.

% === Outputs needed by AF3 Plugin  ===
#show attack_path_insider/7.

% Our intruder model is based on:
%% https://www.cs.odu.edu/~mukka/cs775s12/Presentations/papers/Oleshchuk.pdf



% Intruder model: Intruder may learn about all disclosed data in a communication channel; Intruder may do what she likes with the learned data. 
%% asset: communication channel
%% attack_path(id_ap(SOURCE,DEST,ASSET),SOURCE,DEST,data(SOURCE),ASSET) :-
%%   asset(ASSET),
%%   reachable(ASSET),
%%   task_output_port(SOURCE,SOURCE_PORT),
%%   task_input_port(DEST,DEST_PORT),
%%   signal_with_ports(ASSET,SOURCE_PORT,SOURCE,DEST_PORT,DEST),
%% %  not same_container(SOURCE,DEST),
%%   reachable(SOURCE,SOURCE_PORT),
%%   reachable(DEST,DEST_PORT),
%%   not gateway(SOURCE),
%%   not gateway(DEST).

% Intruder model: Intruder may masquerade (i.e., pretend to be) as a port of a component.
%% asset: output port of a component
attack_path(id_ap(SOURCE,ASSET),SOURCE,ASSET,data(SOURCE),ASSET) :-
  asset(ASSET),
  task(SOURCE),
  task(ASSET),
  task_output_port(SOURCE,SRC_PORT),
  task_input_port(ASSET,ASSET_PORT),
%  task_output_port(ASSET,ASSET_PORT),
  signal_with_ports(ID,SRC_PORT,SOURCE,ASSET_PORT,ASSET),  
  reachable(SOURCE,SRC_PORT),
  reachable(ASSET,ASSET_PORT).  
%  reachable(DEST,ASSET).
%% %  not gateway(SOURCE).

%% attack_path(id_ap(SOURCE,DEST,ASSET),SOURCE,DEST,data(SOURCE),ASSET) :-
%%   asset(ASSET),
%%   task(SOURCE),
%%   task(DEST),
%%   task_output_port(SOURCE,ASSET),
%%   task_input_port(DEST,DEST_PORT),
%%  % not same_container(SOURCE,DEST),
%%   signal_with_ports(ID,ASSET,SOURCE,DEST_PORT,DEST),
%%   reachable(SOURCE,ASSET),
%%   reachable(DEST,DEST_PORT), 
%%   not gateway(SOURCE).
%%   %% not gateway(DEST).

% attack_path_insider is relevant for af3
attack_path_insider(ID,OUTPUT_SOURCE,SOURCE,INPUT_TARGET,TARGET,DATA,ASSET) :-
     attack_path(ID,SOURCE,TARGET,DATA,ASSET),
     task_output_port(SOURCE,OUTPUT_SOURCE),
     task_input_port(TARGET,INPUT_TARGET),
     signal_with_ports(SIGNAL,OUTPUT_SOURCE,SOURCE,INPUT_TARGET,TARGET).
