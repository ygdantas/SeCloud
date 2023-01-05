%#show reachable/2.

% We consider the classical intruder model: Dolev-Yao Intruder
% Everything is reachable
reachable(CP,PORT) :- port(PORT), component_input_port(CP,PORT,_).
reachable(CP,PORT) :- port(PORT), component_output_port(CP,PORT,_).
reachable(CH) :- channel_with_ports(CH,_,_,_,_).
reachable(CP,PORT) :- public(CP), component_input_port(CP,PORT,_).
reachable(CP,PORT) :- public(CP), component_output_port(CP,PORT,_).

reachable(TASK,PORT) :- port(PORT), task_input_port(TASK,PORT).
reachable(TASK,PORT) :- port(PORT), task_output_port(TASK,PORT).