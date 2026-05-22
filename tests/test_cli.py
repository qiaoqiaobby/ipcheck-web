import unittest

from ipcheck.cli import parse_macos_proxy, parse_tun_vpn


class ProxyDetectionTests(unittest.TestCase):
    def test_parse_macos_proxy_detects_enabled_proxy(self):
        output = """
<dictionary> {
  HTTPEnable : 1
  HTTPProxy : 127.0.0.1
  HTTPPort : 7890
  SOCKSEnable : 1
  SOCKSProxy : 127.0.0.1
  SOCKSPort : 7891
}
"""

        proxies = parse_macos_proxy(output)

        self.assertEqual(proxies, ["HTTP 127.0.0.1:7890", "SOCKS 127.0.0.1:7891"])

    def test_parse_macos_proxy_detects_pac(self):
        output = """
<dictionary> {
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://example.test/proxy.pac
}
"""

        proxies = parse_macos_proxy(output)

        self.assertEqual(proxies, ["PAC http://example.test/proxy.pac"])

    def test_parse_macos_proxy_ignores_disabled_proxy(self):
        output = """
<dictionary> {
  HTTPEnable : 0
  HTTPProxy : 127.0.0.1
  HTTPPort : 7890
}
"""

        proxies = parse_macos_proxy(output)

        self.assertEqual(proxies, [])


class TunVpnDetectionTests(unittest.TestCase):
    def test_parse_tun_vpn_detects_utun_route(self):
        ifconfig_output = """
utun1024: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
    inet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc
"""
        route_output = """
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
1                  198.18.0.1         UGSc             utun1024
128.0/1            198.18.0.1         UGSc             utun1024
"""

        active, details = parse_tun_vpn(ifconfig_output, route_output)

        self.assertTrue(active)
        self.assertTrue(any("utun1024" in item for item in details))
        self.assertTrue(any("198.18.0.1" in item for item in details))

    def test_parse_tun_vpn_ignores_plain_lan_route(self):
        ifconfig_output = """
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    inet 192.168.31.252 netmask 0xffffff00 broadcast 192.168.31.255
"""
        route_output = """
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.31.1       UGScg                 en0
"""

        active, details = parse_tun_vpn(ifconfig_output, route_output)

        self.assertFalse(active)
        self.assertEqual(details, [])


if __name__ == "__main__":
    unittest.main()
