# SNS IPsec VPN extractor

Reads the IPsec VPN configuration of a Stormshield SNS firewall and writes a JSON file prepared for import into Stormshield Management Center (SMC).

It combines two sources: the list of active tunnels read over SSH, and the peer settings (IKE and IPsec profiles) read through the firewall's SSL API.

## Requirements

- Python 3.8 or later
- Network access to the firewall: SSH (port 22) and the administration port (443 by default)
- An administrator account on the firewall
- `paramiko`, and Stormshield's `stormshield.sns.sslclient` library

```bash
pip install paramiko stormshield.sns.sslclient
```

## Usage

```bash
python sns_vpn_extractor.py --host <firewall-ip> --user <admin-user>
```

The password is asked interactively. A `--password` option exists for scripted runs; prefer the prompt, since a password on the command line ends up in the shell history.

## Output

The result is printed to the console and saved as `vpn_config_smc.json`:

- `firewall_source`: the firewall that was queried;
- `tunnels`: active tunnels with their IKE and IPsec settings and traffic selectors (local and remote networks);
- `unresolved_tunnels`: tunnels that are configured but down, for which the networks could not be confirmed.

The generated file describes a real VPN topology. It is excluded by `.gitignore`; keep it out of version control.

## Tests

```bash
python -m unittest discover -s tests
```

The tests parse sample command output with mocks; they do not connect to a firewall.

## Troubleshooting

- **SSH error**: check that SSH is enabled on the firewall and that your address is allowed.
- **SSL error**: check that the administration port is reachable.
