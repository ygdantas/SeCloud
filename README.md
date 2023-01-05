# SeCloud

SeCloud is an engine for hardening cloud architectures with security measures. SeCloud has been implemented in clingo, a logic programming language based on the Answer Set Programming paradigm.

## Instructions for running SeCloud

The following command runs SeCloud to recommend security measures for addressing threat scenarios.

clingo example/cloud.lp m2m/af3.lp utils/utils.lp security/security_artifacts.lp security/intruder_reachability.lp security/outsider_intruder.lp security/insider_intruder.lp security/security.lp -n 0

