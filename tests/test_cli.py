import unittest

from ipcheck.cli import (
    C,
    _ansi_wrap,
    display_len,
    parse_macos_proxy,
    parse_tun_vpn,
)


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


class AnsiWrapTests(unittest.TestCase):
    def test_short_value_unchanged(self):
        self.assertEqual(_ansi_wrap("192.168.1.10", 46), ["192.168.1.10"])

    def test_no_line_exceeds_width(self):
        text = "Hangzhou Alibaba Advertising Co.,Ltd. China Mobile"
        for ln in _ansi_wrap(text, 20):
            self.assertLessEqual(display_len(ln), 20)

    def test_breaks_on_space(self):
        lines = _ansi_wrap("aaa bbb ccc", 7)
        self.assertEqual(lines, ["aaa bbb", "ccc"])

    def test_hard_break_long_token(self):
        lines = _ansi_wrap("2001:4860:4860::8888", 8)
        self.assertTrue(all(display_len(ln) <= 8 for ln in lines))
        self.assertEqual("".join(lines), "2001:4860:4860::8888")

    def test_cjk_width_respected(self):
        # 每个汉字占 2 列，宽度 6 → 每行最多 3 个汉字
        lines = _ansi_wrap("一二三四五", 6)
        self.assertTrue(all(display_len(ln) <= 6 for ln in lines))

    def test_color_preserved_across_wrap(self):
        colored = f"{C.YELLOW}warn one two three four{C.RESET}"
        lines = _ansi_wrap(colored, 9)
        self.assertGreater(len(lines), 1)
        for ln in lines:
            if C.YELLOW:  # 仅在彩色启用时校验
                self.assertIn(C.YELLOW, ln)
                self.assertTrue(ln.endswith(C.RESET))


if __name__ == "__main__":
    unittest.main()
