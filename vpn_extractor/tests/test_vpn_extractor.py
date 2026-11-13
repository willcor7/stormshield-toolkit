import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Ensure we can import the script
sys.path.append(os.getcwd())
from sns_vpn_extractor import VPNScanner

class TestVPNScanner(unittest.TestCase):

    def test_parse_ipsec_statusall(self):
        # Mock scanner instance
        scanner = VPNScanner('1.1.1.1', 'admin', 'pass')

        # Sample output simulating StrongSwan on Stormshield
        # Including variations: ... and ===, and indentation
        sample_output = """
Status of IKE charon daemon (strongSwan 5.5.1, Linux 4.4.0, x86_64):
  uptime: 21 hours, since Oct 25 10:00:00 2023
  malloc: sbrk 2854912, mmap 0, used 645312, free 2209600
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 6
  loaded plugins: charon aes des rc2 sha2 sha1 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default stroke updown eap-identity eap-md5 eap-mschapv2 eap-radius eap-tls xauth-generic xauth-eap

Security Associations (3 up, 0 connecting):
   Tunnel_Vers_Site_B[1]: ESTABLISHED 56 minutes ago, 10.0.0.254[10.0.0.254]...1.2.3.4[1.2.3.4]
   Tunnel_Vers_Site_B{1}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c3e0b82f_i c5f6a1e2_o
   Tunnel_Vers_Site_B{1}:   192.168.10.0/24 ... 10.20.0.0/24
   Tunnel_Vers_Site_B{2}:   192.168.11.0/24 === 10.21.0.0/24

   Legacy_Tunnel[2]: ESTABLISHED 10 minutes ago, 2.2.2.2[2.2.2.2]...3.3.3.3[3.3.3.3]
   Legacy_Tunnel{2}:  INSTALLED, TUNNEL, reqid 2, ESP SPIs: ...
   Legacy_Tunnel{2}:   10.0.0.5/32 ... 192.168.1.5/32
"""
        result = scanner.parse_ipsec_statusall(sample_output)

        self.assertIn('Tunnel_Vers_Site_B', result)
        self.assertEqual(len(result['Tunnel_Vers_Site_B']), 2)

        # Check first subnet
        self.assertEqual(result['Tunnel_Vers_Site_B'][0]['local'], '192.168.10.0/24')
        self.assertEqual(result['Tunnel_Vers_Site_B'][0]['remote'], '10.20.0.0/24')

        # Check second subnet (=== variation)
        self.assertEqual(result['Tunnel_Vers_Site_B'][1]['local'], '192.168.11.0/24')
        self.assertEqual(result['Tunnel_Vers_Site_B'][1]['remote'], '10.21.0.0/24')

        # Check Legacy Tunnel
        self.assertIn('Legacy_Tunnel', result)
        self.assertEqual(result['Legacy_Tunnel'][0]['local'], '10.0.0.5/32')
        self.assertEqual(result['Legacy_Tunnel'][0]['remote'], '192.168.1.5/32')

    def test_parse_peer_show(self):
        scanner = VPNScanner('1.1.1.1', 'admin', 'pass')

        sample_output = """101 code=00a01000 msg="D▒but" format="section"
[Site_test]
Method="psk"
ikeversion=2
dst="1.2.3.4"
src="Firewall_WAN-Test"
unique="never"
conf="TransitionIP"
psk="private_key"
dpd_mode="high"
reauth=1
mobike=0
100 code=00a00100 msg="Ok"
"""
        result = scanner.parse_peer_show(sample_output, 'Site_test')

        self.assertEqual(result.get('Method'), 'psk')
        self.assertEqual(result.get('ikeversion'), '2')
        self.assertEqual(result.get('dst'), '1.2.3.4')
        self.assertEqual(result.get('conf'), 'TransitionIP')

    @patch('sns_vpn_extractor.paramiko')
    @patch('sns_vpn_extractor.SSLClient')
    def test_full_flow(self, mock_ssl, mock_paramiko):
        # Setup Mocks
        scanner = VPNScanner('10.0.0.254', 'admin', 'pass')

        # Mock SSH Output
        mock_ssh_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_ssh_client
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"""
Security Associations (1 up, 0 connecting):
Tunnel_Vers_Site_B[1]: ESTABLISHED 56 minutes ago, 10.0.0.254...1.2.3.4
Tunnel_Vers_Site_B{1}:   192.168.10.0/24 ... 10.20.0.0/24
"""
        mock_ssh_client.exec_command.return_value = (None, mock_stdout, None)

        # Mock SSL Output
        # 1. LIST
        mock_ssl_instance = mock_ssl.return_value
        mock_ssl_instance.send_command.side_effect = [
            # First call: LIST
            """101 code=...
[Tunnel_Vers_Site_B]
[Dead_Tunnel]
""",
            # Second call: SHOW Tunnel_Vers_Site_B
            """101 code=...
[Tunnel_Vers_Site_B]
Method="psk"
ikeversion=2
dst="1.2.3.4"
conf="IPSEC_AES256"
""",
            # Third call: SHOW Dead_Tunnel (if logic queries it? The logic only queries active ones first usually, but let's see)
            # Actually, the logic iterates active_tunnels_map. Dead_Tunnel won't be in active map.
            # So this side_effect list needs to match exact calls.
            # My code:
            # 1. get_all_peers_ssl() -> LIST
            # 2. get_active_tunnels_ssh() -> SSH
            # 3. Loop active tunnels -> SHOW <peer>
        ]

        # Run
        # Capture stdout to verify JSON
        from io import StringIO
        captured_output = StringIO()
        sys.stdout = captured_output

        scanner.run()

        sys.stdout = sys.__stdout__
        output_json = captured_output.getvalue()

        import json
        data = json.loads(output_json)

        self.assertEqual(data['firewall_source'], '10.0.0.254')
        self.assertEqual(len(data['tunnels']), 1)
        self.assertEqual(data['tunnels'][0]['name'], 'Tunnel_Vers_Site_B')
        self.assertEqual(data['tunnels'][0]['profiles']['ipsec'], 'IPSEC_AES256')
        self.assertEqual(data['tunnels'][0]['selectors'][0]['local_cidr'], '192.168.10.0/24')

        self.assertIn('Dead_Tunnel', data['unresolved_tunnels'][0])

if __name__ == '__main__':
    unittest.main()
