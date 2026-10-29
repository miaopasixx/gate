import json
import os
import tempfile
import unittest
from unittest import mock

import vpngate


def make_node(host, *, residential="residential", latency=20, country="Japan", code="JP", port=443):
    return {
        "host": host,
        "port": port,
        "country": country,
        "country_code": code,
        "residential": residential,
        "latency_ms": latency,
        "success": True,
        "verification": "sstp-worker",
    }


def make_data(nodes):
    countries = {}
    for node in nodes:
        group = countries.setdefault(
            node["country"], {"code": node["country_code"], "nodes": [], "count": 0}
        )
        group["nodes"].append(node)
        group["count"] += 1
    return {
        "generated_at": "2026-10-29 00:00:00 UTC",
        "source": "fixture",
        "worker": "https://worker.example/check?sstp=vpn:vpn@",
        "stats": {
            "raw_nodes": len(nodes),
            "sstp_nodes": len(nodes),
            "checked": len(nodes),
            "success": len(nodes),
            "failed": 0,
            "countries": len(countries),
            "residential_est": sum(n["residential"] == "residential" for n in nodes),
            "datacenter_est": sum(n["residential"] != "residential" for n in nodes),
        },
        "countries": countries,
        "available": nodes,
    }


class BuildNodesTextTests(unittest.TestCase):
    def test_builds_complete_edgetunnel_chain(self):
        data = make_data([make_node("public-vpn-220.opengw.net")])

        text = vpngate.build_nodes_text(data, ["edge.example:443"])

        self.assertEqual(
            text,
            "edge.example:443#日本-住宅-01$sstp://vpn:vpn@public-vpn-220.opengw.net:443\n",
        )

    def test_sorts_nodes_and_rotates_edges(self):
        residential = make_node("vpn111111.opengw.net", latency=30)
        datacenter = make_node(
            "public-vpn-220.opengw.net", residential="datacenter", latency=10
        )
        data = make_data([datacenter, residential])

        lines = vpngate.build_nodes_text(
            data, ["edge-a.example:443", "edge-b.example:443"]
        ).splitlines()

        self.assertEqual(
            lines,
            [
                "edge-a.example:443#日本-住宅-01$sstp://vpn:vpn@vpn111111.opengw.net:443",
                "edge-b.example:443#日本-机房-01$sstp://vpn:vpn@public-vpn-220.opengw.net:443",
            ],
        )

    def test_empty_nodes_fail_instead_of_publishing_cloudflare_only(self):
        with self.assertRaisesRegex(ValueError, "没有经 SSTP Worker"):
            vpngate.build_nodes_text(make_data([]), ["162.159.130.234:443"])

    def test_allows_bracketed_ipv6_edge(self):
        text = vpngate.build_nodes_text(
            make_data([make_node("public-vpn-220.opengw.net")]),
            ["[2606:4700::1111]:443"],
        )
        self.assertTrue(text.startswith("[2606:4700::1111]:443#日本-住宅-01"))

    def test_rejects_edge_with_chain_or_url_delimiters(self):
        data = make_data([make_node("public-vpn-220.opengw.net")])
        invalid_edges = [
            "evil$http://attacker.example:443",
            "https://edge.example:443",
            "edge.example/path:443",
            "user@edge.example:443",
        ]
        for edge in invalid_edges:
            with self.subTest(edge=edge), self.assertRaisesRegex(ValueError, "端点|主机"):
                vpngate.build_nodes_text(data, [edge])


class PublishValidationTests(unittest.TestCase):
    def setUp(self):
        self.nodes = [make_node("public-vpn-220.opengw.net")]
        self.data = make_data(self.nodes)
        self.nodes_text = vpngate.build_nodes_text(self.data, ["162.159.130.234:443"])
        self.sstp_text = vpngate.build_sstp_text(self.data)

    def test_valid_bundle(self):
        vpngate.validate_publish_bundle(self.data, self.nodes_text, self.sstp_text)

    def test_rejects_cloudflare_only_regression(self):
        with self.assertRaisesRegex(ValueError, "完整链式代理"):
            vpngate.validate_publish_bundle(
                self.data,
                "162.159.130.234:443#日本-住宅-01\n",
                self.sstp_text,
            )

    def test_rejects_mismatched_or_duplicate_targets(self):
        duplicate = self.nodes_text + self.nodes_text
        with self.assertRaisesRegex(ValueError, "不一致"):
            vpngate.validate_publish_bundle(self.data, duplicate, self.sstp_text)

    def test_rejects_non_worker_result(self):
        data = make_data([make_node("public-vpn-220.opengw.net")])
        data["available"][0]["verification"] = "tcp-only"
        with self.assertRaisesRegex(ValueError, "未经 SSTP Worker"):
            vpngate.validate_publish_bundle(data, self.nodes_text, self.sstp_text)

    def test_sstp_text_contains_only_real_endpoint(self):
        self.assertEqual(self.sstp_text, "public-vpn-220.opengw.net:443\n")
        self.assertNotIn("162.159.130.234", self.sstp_text)
        self.assertNotIn("$sstp://", self.sstp_text)

    def test_write_and_validate_public_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            template = os.path.join(tmp, "template.html")
            with open(template, "w", encoding="utf-8") as stream:
                stream.write("<!doctype html><title>fixture</title>")
            with mock.patch.object(vpngate, "PUBLIC_DIR", tmp), mock.patch.object(
                vpngate, "TEMPLATE_HTML", template
            ):
                paths = vpngate.write_outputs(self.data, ["edge.example:443"])
                self.assertEqual(len(paths), 4)
                self.assertEqual(vpngate.validate_public_dir(tmp), 1)
                with open(os.path.join(tmp, "data.json"), encoding="utf-8") as stream:
                    saved = json.load(stream)
                self.assertEqual(saved["stats"]["success"], 1)


class VerificationSourceTests(unittest.TestCase):
    def test_build_outputs_excludes_tcp_only_result(self):
        worker = make_node("vpn111111.opengw.net")
        tcp_only = make_node("vpn222222.opengw.net")
        tcp_only.update(success=False, verification="tcp-only", tcp_reachable=True)

        data = vpngate.build_outputs([worker, tcp_only], 2, 2, "fixture")

        self.assertEqual([node["host"] for node in data["available"]], [worker["host"]])
        self.assertEqual(data["stats"]["success"], 1)
        self.assertEqual(data["stats"]["failed"], 1)

    def test_local_probe_is_diagnostic_only(self):
        node = {
            "host": "vpn111111.opengw.net",
            "port": 443,
            "country": "Japan",
            "country_code": "JP",
        }
        fake_socket = mock.MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        with mock.patch("vpngate.socket.create_connection", return_value=fake_socket):
            result = vpngate.check_one_local(node)

        self.assertTrue(result["tcp_reachable"])
        self.assertFalse(result["success"])
        self.assertEqual(result["verification"], "tcp-only")
        self.assertFalse(vpngate.is_publishable_result(result))


if __name__ == "__main__":
    unittest.main()
