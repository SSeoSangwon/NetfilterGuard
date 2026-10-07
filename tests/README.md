# Validation

Runtime validation is designed to run inside an isolated Linux network namespace rather than against a public or production network.

The recommended path is:

```bash
make
sudo ./scripts/run_isolated_validation.sh
```

The script creates a temporary `veth` pair and a network namespace, loads NetfilterGuard only for the host-side test interface, generates bounded TCP/UDP/SYN traffic from the namespace, records `/proc/netfilter_guard` snapshots, and removes the namespace and module on exit.

Required tools:

```bash
sudo apt update
sudo apt install -y hping3 iproute2
```

The validation script uses only the private `10.200.0.0/24` test link that it creates locally. It does not send test traffic to an Internet address.
