# SeCloud

SeCloud is an engine for hardening cloud architectures with security measures. SeCloud has been implemented in clingo, a logic programming language based on the Answer Set Programming paradigm.

## Setup

The instructions listed in this file have been tested in a Linux operating system (Ubuntu 18.04 desktop 64-bit).

You can install clingo with the following command

```
sudo apt install gringo
```

## Instructions for running SeCloud

The following command runs SeCloud to compute threat scenarios and attack paths.
```
clingo example/cloud.lp m2m/af3.lp utils/utils.lp security/security_artifacts.lp security/intruder_reachability.lp security/outsider_intruder.lp security/insider_intruder.lp -n 0
```

The following command runs SeCloud to recommend security measures for addressing threat scenarios.
```
clingo example/cloud.lp m2m/af3.lp utils/utils.lp security/security_artifacts.lp security/intruder_reachability.lp security/outsider_intruder.lp security/insider_intruder.lp security/security.lp -n 0
```
