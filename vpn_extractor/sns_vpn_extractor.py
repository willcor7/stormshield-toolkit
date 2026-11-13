import json
import re
import sys
import argparse
import getpass
import logging

# Try to import external libraries, handle failure gracefully for development environment
try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from stormshield.sns.sslclient import SSLClient
except ImportError:
    SSLClient = None

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VPNScanner:
    def __init__(self, host, user, password, port=443, ssh_port=22):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.ssh_port = ssh_port
        self.ssh_client = None
        self.ssl_client = None

    def connect_ssh(self):
        """Connects to the firewall via SSH."""
        if not paramiko:
            logger.error("Paramiko library not found. Please install it.")
            sys.exit(1)

        logger.info(f"Connecting to {self.host} via SSH...")
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh_client.connect(self.host, port=self.ssh_port, username=self.user, password=self.password, timeout=10)
            logger.info("SSH Connection established.")
        except Exception as e:
            logger.error(f"Failed to connect via SSH: {e}")
            sys.exit(1)

    def connect_ssl(self):
        """Connects to the firewall via SSL API."""
        if not SSLClient:
            logger.error("stormshield.sns.sslclient library not found. Please install it.")
            sys.exit(1)

        logger.info(f"Connecting to {self.host} via SSL API...")
        try:
            # sslverifyhost=False is often needed for internal appliances with self-signed certs
            self.ssl_client = SSLClient(host=self.host, port=self.port, user=self.user, password=self.password, sslverifyhost=False)
            logger.info("SSL Connection established.")
        except Exception as e:
            logger.error(f"Failed to connect via SSL: {e}")
            sys.exit(1)

    def disconnect(self):
        if self.ssh_client:
            self.ssh_client.close()
        if self.ssl_client:
            # SSLClient usage usually doesn't require explicit close if just sending commands,
            # but good practice if the library supports it.
            # Based on docs, it might just be a wrapper around socket.
            pass

    def get_active_tunnels_ssh(self):
        """
        Executes 'ipsec statusall' via SSH and parses the output.
        Returns a dictionary {PeerName: [{'local': '...', 'remote': '...'}, ...]}
        """
        if not self.ssh_client:
            raise Exception("SSH Client not connected")

        command = "ipsec statusall"
        stdin, stdout, stderr = self.ssh_client.exec_command(command)
        output = stdout.read().decode('utf-8')

        return self.parse_ipsec_statusall(output)

    def parse_ipsec_statusall(self, output):
        """
        Parses the raw output of ipsec statusall.
        Separated for easier unit testing.
        """
        active_tunnels = {}
        current_peer = None

        # Regex to capture Peer Name from lines like "PeerName[1]: ESTABLISHED..."
        # or "PeerName{1}: ..." depending on version.
        # User said: "Repérer les lignes contenant le format A.B.C.D/XX ... E.F.G.H/YY. Associer ces réseaux au nom de la connexion (Peer) qui apparaît juste au-dessus"

        # We need a robust state machine or line-by-line parsing
        lines = output.splitlines()

        # Regex for finding the peer name.
        # Typical strongswan: "myvpn[2]: ESTABLISHED..."
        # We look for lines starting with a name followed by '[' or '{'
        peer_pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)(\[|\{)\d+(\]|\}):\s+ESTABLISHED")

        # Regex for finding subnets "A.B.C.D/XX ... E.F.G.H/YY"
        # The user specifically mentioned "..." (three dots). Standard StrongSwan uses " === " usually.
        # I will support both just in case.
        # Also, sometimes it's indented.
        subnet_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)(\s*\.\.\.\s*|\s*===\s*)(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)")

        for line in lines:
            line = line.strip()

            # Check for Peer Name
            peer_match = peer_pattern.match(line)
            if peer_match:
                current_peer = peer_match.group(1)
                if current_peer not in active_tunnels:
                    active_tunnels[current_peer] = []
                continue

            # Check for Subnets
            # Only match if we have identified a peer "above" (recently)
            if current_peer:
                subnet_match = subnet_pattern.search(line)
                if subnet_match:
                    local_cidr = subnet_match.group(1)
                    remote_cidr = subnet_match.group(3)

                    # Add to list
                    active_tunnels[current_peer].append({
                        'local': local_cidr,
                        'remote': remote_cidr
                    })

        return active_tunnels

    def get_peer_details_ssl(self, peer_name):
        """
        Executes 'CONFIG IPSEC PEER SHOW' via SSL and parses the output.
        """
        if not self.ssl_client:
            raise Exception("SSL Client not connected")

        command = f"CONFIG IPSEC PEER SHOW name={peer_name}"
        # sslclient.send_command returns a Response object usually, or text.
        # Based on search result: response = client.send_command(...)
        # response.data might contain the result.
        # The user output shows raw text with "101 code=...".
        # We need to handle how the library returns data.
        # Assuming for now it returns an object with a .data or .content attribute or is string.
        # I will wrap this in a try/except and assume it behaves like the examples found.

        try:
            response = self.ssl_client.send_command(command)
            # The library might parse the initial status line itself.
            # But the user showed raw output.
            # Let's convert response to string if it's not.
            output = str(response)
            # If the library returns an object, we might need to access a specific field.
            # If it returns the raw text provided by the user:
            return self.parse_peer_show(output, peer_name)
        except Exception as e:
            logger.error(f"Error getting details for {peer_name}: {e}")
            return {}

    def parse_peer_show(self, output, peer_name):
        """
        Parses the INI-like output of CONFIG IPSEC PEER SHOW.
        """
        details = {}

        # Regex for key="value" or key=value
        # The user output: Method="psk" \n ikeversion=2 ...
        lines = output.splitlines()
        for line in lines:
            line = line.strip()

            # Skip API response headers (e.g. 101 code=...) or section headers [Section]
            if line.startswith('10') or line.startswith('[') or 'code=' in line:
                continue

            if '=' in line:
                # Naive splitting might fail if value has =, but standard INI usually implies key=val
                parts = line.split('=', 1)
                key = parts[0].strip()
                val = parts[1].strip()

                # Remove quotes if present
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]

                details[key] = val

        return details

    def get_all_peers_ssl(self):
        """
        Gets list of all defined peers via SSL 'CONFIG IPSEC PEER LIST'.
        """
        if not self.ssl_client:
            raise Exception("SSL Client not connected")

        command = "CONFIG IPSEC PEER LIST"
        try:
            response = self.ssl_client.send_command(command)
            output = str(response) # Verify if this is how we get the text

            # Assuming output is a list of names or INI sections
            # If it's like [PeerName]\n...
            # Or a CSV. I'll need to be robust here.
            # For now, let's assume it returns a list of section headers [PeerName] or similar.

            peers = []
            # Naive parse: look for [PeerName]
            for line in output.splitlines():
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    peers.append(line[1:-1])

            # If that fails, maybe it's just a list of names?
            # Without sample data for LIST, this is a guess.
            # Fallback: if output is empty or parsing fails, we rely on SSH found peers only?
            # But we need "Unresolved tunnels" (configured but down).

            return peers
        except Exception as e:
            logger.error(f"Error listing peers: {e}")
            return []

    def run(self):
        self.connect_ssh()
        self.connect_ssl()

        # Phase 1: Inventory
        # Get all configured peers
        all_configured_peers = self.get_all_peers_ssl()
        logger.info(f"Found {len(all_configured_peers)} configured peers via SSL.")

        # Phase 2: Runtime "Truth"
        # Get active tunnels and their subnets
        active_tunnels_map = self.get_active_tunnels_ssh()
        logger.info(f"Found {len(active_tunnels_map)} active tunnels via SSH.")

        final_tunnels = []
        unresolved_tunnels = []

        processed_peers = set()

        # Phase 3: Enrichment
        for peer_name, subnets in active_tunnels_map.items():
            processed_peers.add(peer_name)

            # Get details from SSL
            details = self.get_peer_details_ssl(peer_name)

            # Map details to JSON structure
            # User wants: "ike": "IKE_AES256", "ipsec": "IPSEC_AES256"
            # In output sample: ikeversion=2, conf="TransitionIP", Method="psk"

            # We map 'conf' to 'ipsec' profile? And 'ikeversion' isn't a profile name.
            # We might need to look for 'auth_profile' or similar if it exists.
            # Based on user sample:
            # Method="psk"
            # ikeversion=2
            # conf="TransitionIP" -> This looks like an IPsec profile name.

            # IKE profile name is often implicit or named same as peer, or in another field.
            # Without exact field mapping, I'll use what I have.

            ike_profile = f"IKEv{details.get('ikeversion', '?')}_{details.get('Method', 'unknown')}"
            ipsec_profile = details.get('conf', 'default') # 'conf' often holds the IPsec phase 2 policy name

            tunnel_obj = {
                "name": peer_name,
                "peer_gateway": details.get('dst', 'unknown'), # 'dst' from sample output
                "status": "UP",
                "profiles": {
                    "ike": ike_profile,
                    "ipsec": ipsec_profile
                },
                "selectors": []
            }

            for subnet in subnets:
                local = subnet['local']
                remote = subnet['remote']

                # Generate suggested names
                # User format: Net_Local_<PeerName>_192.168.50.0
                sanitized_peer = re.sub(r'[^a-zA-Z0-9]', '_', peer_name)
                # Strip mask from name if desired, or keep it. User example: 192.168.50.0 (no /24 in name example, but maybe implied)
                # "Net_Local_Site_B_192.168.10.0"
                # If local is 192.168.10.0/24

                local_ip = local.split('/')[0]
                remote_ip = remote.split('/')[0]

                selector_obj = {
                    "local_cidr": local,
                    "remote_cidr": remote,
                    "smc_suggested_name_local": f"Net_Local_{sanitized_peer}_{local_ip}",
                    "smc_suggested_name_remote": f"Net_Remote_{sanitized_peer}_{remote_ip}"
                }
                tunnel_obj["selectors"].append(selector_obj)

            final_tunnels.append(tunnel_obj)

        # Phase 4: Dead Tunnels
        for peer in all_configured_peers:
            if peer not in processed_peers:
                # It's configured but not active in SSH statusall
                unresolved_tunnels.append(f"{peer} (Down - Config read from SSL, but no runtime traffic selectors)")

        # Phase 5: Output
        output_data = {
            "firewall_source": self.host,
            "tunnels": final_tunnels,
            "unresolved_tunnels": unresolved_tunnels
        }

        print(json.dumps(output_data, indent=2))

        # Save to file?
        with open('vpn_config_smc.json', 'w') as f:
            json.dump(output_data, f, indent=2)
            logger.info("Configuration saved to vpn_config_smc.json")

        self.disconnect()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract Stormshield VPN config for SMC import.")
    parser.add_argument("--host", required=True, help="Firewall IP address")
    parser.add_argument("--user", required=True, help="Admin username")
    parser.add_argument("--password", help="Admin password (will prompt if not provided)")

    args = parser.parse_args()

    password = args.password
    if not password:
        password = getpass.getpass("Password: ")

    scanner = VPNScanner(args.host, args.user, password)
    scanner.run()
