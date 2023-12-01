'use strict';
'require dom';
'require fs';
'require poll';
'require uci';
'require ui';
'require view';

const variant = "xray_core";

function greater_than_zero(n) {
    if (n < 0) {
        return 0;
    }
    return n;
}

function get_inbound_uci_description(config, key) {
    const ks = key.split(":");
    switch (ks[0]) {
        case "https_inbound": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>https://0.0.0.0:443</strong> }`)]);
        }
        case "http_inbound": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>http://0.0.0.0:${uci.get_first(config, "general", "http_port") || 1081}</strong> }`)]);
        }
        case "socks_inbound": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>socks5://0.0.0.0:${uci.get_first(config, "general", "socks_port") || 1080}</strong> }`)]);
        }
        case "tproxy_tcp_inbound_v4": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>tproxy_tcp://0.0.0.0:${uci.get_first(config, "general", "tproxy_port_tcp_v4") || 1082}</strong> }`)]);
        }
        case "tproxy_udp_inbound_v4": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>tproxy_udp://0.0.0.0:${uci.get_first(config, "general", "tproxy_port_udp_v4") || 1084}</strong> }`)]);
        }
        case "tproxy_tcp_inbound_v6": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>tproxy_tcp://[::]:${uci.get_first(config, "general", "tproxy_port_tcp_v6") || 1083}</strong> }`)]);
        }
        case "tproxy_udp_inbound_v6": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>tproxy_udp://[::]:${uci.get_first(config, "general", "tproxy_port_udp_v6") || 1085}</strong> }`)]);
        }
        case "tproxy_tcp_inbound_f4": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>tproxy_tcp://0.0.0.0:${uci.get_first(config, "general", "tproxy_port_tcp_f4") || 1086}</strong> }`)]);
        }
        case "tproxy_udp_inbound_f4": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>tproxy_udp://0.0.0.0:${uci.get_first(config, "general", "tproxy_port_udp_f4") || 1088}</strong> }`)]);
        }
        case "tproxy_tcp_inbound_f6": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>tproxy_tcp://[::]:${uci.get_first(config, "general", "tproxy_port_tcp_f6") || 1087}</strong> }`)]);
        }
        case "tproxy_udp_inbound_f6": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>tproxy_udp://[::]:${uci.get_first(config, "general", "tproxy_port_udp_f6") || 1089}</strong> }`)]);
        }
        case "metrics": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>http://0.0.0.0:${uci.get_first(config, "general", "metrics_server_port") || 18888}</strong> }`)]);
        }
        case "api": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>grpc://127.0.0.1:8080</strong> }`)]);
        }
        case "dns_server_inbound": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>dns://0.0.0.0:${ks[1]}</strong> }`)]);
        }
    }
    const uci_key = key.slice(-9);
    const uci_item = uci.get(config, uci_key);
    if (uci_item == null) {
        return key;
    }
    switch (uci_item[".type"]) {
        case "extra_inbound": {
            return E([], [key, " ", E('span', { 'class': 'ifacebadge' }, `{ listen: <strong>${uci_item["inbound_type"]}://${uci_item["inbound_addr"]}:${uci_item["inbound_port"]}</strong> }`)]);
        }
    }
    return key;
}

function outbound_format(server) {
    if (server["alias"]) {
        return server["alias"];
    }
    if (server["server"].includes(":")) {
        return `${server["transport"]},[${server["server"]}]:${server["server_port"]}`;
    }
    return `${server["transport"]},${server["server"]}:${server["server_port"]}`;
}

function get_outbound_uci_description(config, key) {
    if (!key) {
        return "direct";
    }
    const uci_key = key.slice(-9);
    const uci_item = uci.get(config, uci_key);
    if (uci_item == null) {
        return "direct";
    }
    switch (uci_item[".type"]) {
        case "servers": {
            return outbound_format(uci_item);
        }
        case "extra_inbound": {
            return `${uci_item["inbound_type"]}://${uci_item["inbound_addr"]}:${uci_item["inbound_port"]}`;
        }
        case "manual_tproxy": {
            return `${uci_item["source_addr"]}:${uci_item["source_port"]} -> ${uci_item["dest_addr"] || "{sniffing}"}:${uci_item["dest_port"]}`;
        }
        case "fakedns": {
            return `${uci_item["fake_dns_domain_names"].length} ${_("domains")}\n${uci_item["fake_dns_domain_names"].join("\n")}`;
        }
    }
    return "direct";
}

function outbound_first_tag_format(tag_split, first_uci_description) {
    let result = [tag_split[0]];

    const first_tag = tag_split[0].split(":");
    if (first_tag.length == 1) {
        return result;
    }

    if (tag_split.length > 1) {
        switch (first_tag[0]) {
            case "extra_inbound": {
                if (tag_split.length < 3) {
                    result.push(" ", E('span', {
                        'class': 'ifacebadge',
                        'data-tooltip': `${first_uci_description}`,
                    }, `{ listen: <strong>${first_uci_description}</strong> }`));
                } else {
                    result.push(" ", E('span', {
                        'class': 'ifacebadge',
                        'data-tooltip': `${first_uci_description}`,
                    }, `{ listen <strong>...</strong> }`));
                }
                break;
            }
            case "force_forward": {
                result.push(" ", E('span', {
                    'class': 'ifacebadge',
                    'data-tooltip': `${first_uci_description}`,
                }, `{ force_forward <strong>...</strong> }`));
                break;
            }
            case "balancer_outbound": {
                if (tag_split.length < 4) {
                    result.push(" ", E('span', {
                        'class': 'ifacebadge',
                        'data-tooltip': `${first_uci_description}`,
                    }, `{ balancer_outbound <strong>...</strong> }`));
                }
                break;
            }
            case "fake_dns_tcp":
            case "fake_dns_udp": {
                result.push(" ", E('span', {
                    'class': 'ifacebadge',
                    'data-tooltip': `${first_uci_description}`,
                }, `{ fake_dns <strong>...</strong> }`));
            }
            case "manual_tproxy": {
                break;
            }
            default: {
                result.push(" ", E('span', {
                    'class': 'ifacebadge',
                    'data-tooltip': `${first_uci_description}`,
                }, `{ <strong>...</strong> }`));
                break;
            }
        }
    } else {
        result.push(" ", E('span', {
            'class': 'ifacebadge',
            'data-tooltip': first_tag[0],
        }, `{ <strong>${first_uci_description}</strong> }`));
    }
    return result;
}

function outbound_middle_tag_format(tag_split, first_uci_description, current_tag, current_uci_description) {
    switch (current_tag[0]) {
        case "extra_inbound": {
            if (tag_split.length < 3) {
                return E('span', {
                    'class': 'ifacebadge',
                    'data-tooltip': `${current_tag[0]}: ${current_uci_description} (${current_tag[1]})`,
                }, `{ listen: <strong>${current_uci_description}</strong> }`);
            }
            return E('span', {
                'class': 'ifacebadge',
                'data-tooltip': `${current_tag[0]}: ${current_uci_description} (${current_tag[1]})`,
            }, `{ listen <strong>...</strong> }`);
        }
        case "force_forward": {
            return E('span', {
                'class': 'ifacebadge',
                'data-tooltip': `${current_tag[0]}: ${current_uci_description} (${current_tag[1]})`,
            }, `{ force_forward <strong>...</strong> }`);
        }
        case "balancer_outbound": {
            if (tag_split.length < 4) {
                return E('span', {
                    'class': 'ifacebadge',
                    'data-tooltip': `${current_tag[0]}: ${current_uci_description} (${current_tag[1]})`,
                }, `{ balancer_outbound <strong>...</strong> }`);
            }
        }
        case "tcp_outbound": {
            if (tag_split.length < 4) {
                return E('span', {
                    'class': 'ifacebadge',
                    'data-tooltip': `${current_tag[0]}`,
                }, `{ tcp: <strong>${first_uci_description}</strong> }`);
            }
            return E('span', {
                'class': 'ifacebadge',
                'data-tooltip': `tcp: ${first_uci_description}`,
            }, `{ tcp <strong>...</strong> }`);
        }
        case "udp_outbound": {
            if (tag_split.length < 4) {
                return E('span', {
                    'class': 'ifacebadge',
                    'data-tooltip': `${current_tag[0]}`,
                }, `{ udp: <strong>${first_uci_description}</strong> }`);
            }
            return E('span', {
                'class': 'ifacebadge',
                'data-tooltip': `udp: ${first_uci_description}`,
            }, `{ udp <strong>...</strong> }`);
        }
        case "fake_dns_tcp":
        case "fake_dns_udp": {
            break;
        }
    }
    return E('span', {
        'class': 'ifacebadge',
        'data-tooltip': `${current_uci_description}`,
    }, `{ <strong>...</strong> }`);
}

function outbound_last_tag_format(first_uci_description, last_tag, last_uci_description) {
    if (last_tag[0] == "tcp_outbound") {
        return E('span', {
            'class': 'ifacebadge',
        }, `{ tcp: <strong>${first_uci_description}</strong> }`);
    } else if (last_tag[0] == "udp_outbound") {
        return E('span', {
            'class': 'ifacebadge',
        }, `{ udp: <strong>${first_uci_description}</strong> }`);
    }
    return E('span', {
        'class': 'ifacebadge',
        'data-tooltip': `${last_tag[1]}`,
    }, `{ ${last_tag[0]}: <strong>${last_uci_description}</strong> }`);
}

function get_outbound_description(config, tag) {
    const tag_split = tag.split("@");
    const first_uci_description = get_outbound_uci_description(config, tag_split[0].split(":")[1]);

    let result = outbound_first_tag_format(tag_split, first_uci_description);
    for (let i = 1; i < tag_split.length; i++) {
        const current_tag = tag_split[i].split(":");
        const current_uci_description = get_outbound_uci_description(config, current_tag[1]);
        if (i == tag_split.length - 1) {
            result.push(" ", outbound_last_tag_format(first_uci_description, current_tag, current_uci_description));
        } else {
            result.push(" ", outbound_middle_tag_format(tag_split, first_uci_description, current_tag, current_uci_description));
        }
    }
    return result;
}

function get_dns_badge(records, expire) {
    const now_timestamp = new Date().getTime() / 1000;
    const expire_badge = E('span', {
        'class': 'ifacebadge',
    }, `${_("ttl")}: <strong>${'%d'.format(greater_than_zero(expire - now_timestamp))}s</strong>`);

    switch (records.length) {
        case 0: {
            return "<i>empty or expired</i>";
        }
        case 1: {
            return E([], [records[0], " ", expire_badge]);
        }
    }
    return E([], [
        records[0],
        ", ... ",
        E('span', {
            'class': 'ifacebadge',
            'data-tooltip': `${records.length} ${_("in cache")} \n${records.join("\n")}`,
        }, `+<strong>${records.length - 1}</strong>`),
        " ",
        expire_badge
    ]);
}

function get_dns_cache_by_server(key, value, last_error) {
    return [
        E('h4', key),
        E('div', { 'class': 'cbi-map-descr' }, `${_("Last query failure reason: ")}<code>${last_error}</code>`),
        E('table', { 'class': 'table' }, [
            E('tr', { 'class': 'tr table-titles' }, [
                E('th', { 'class': 'th', 'width': '34%' }, _('Domain Name')),
                E('th', { 'class': 'th', 'width': '25%' }, _('Values IPv4')),
                E('th', { 'class': 'th', 'width': '41%' }, _('Values IPv6')),
            ]),
            ...Object.entries(value).map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                E('td', { 'class': 'td', 'width': '34%' }, v[0]),
                E('td', { 'class': 'td', 'width': '25%' }, get_dns_badge(v[1]["A"], v[1]["A_expire"])),
                E('td', { 'class': 'td', 'width': '41%' }, get_dns_badge(v[1]["AAAA"], v[1]["AAAA_expire"])),
            ]))
        ])
    ];
}

function get_dns_cache(vars) {
    const dns_cache = Object.entries(vars["dns"]);
    let result = [];
    for (const i of dns_cache) {
        for (const j of get_dns_cache_by_server(i[0], i[1]["cache"], i[1]["last_error"])) {
            result.push(j);
        }
    }
    return result;
}

function get_fake_dns_item(value) {
    return [
        E('h3', `FakeDNS Pool: ${value["pool"]}`),
        E('div', { 'class': 'cbi-map-descr' }, `${_("Pool usage")}: ${value["size"]} / ${value["cap"]}; ${value["query_key"]} ${_("domain to fake IP lookups")}, ${value["query_value"]} ${_("fake IP to domain lookups")}`),
        E('table', { 'class': 'table' }, [
            E('tr', { 'class': 'tr table-titles' }, [
                E('th', { 'class': 'th', 'width': '50%' }, _('Domain')),
                E('th', { 'class': 'th', 'width': '50%' }, _('Value')),
            ]),
            ...value["items"].map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                E('td', { 'class': 'td', 'width': '50%' }, v["key"]),
                E('td', { 'class': 'td', 'width': '50%' }, v["value"]),
            ]))
        ])
    ];
}

function get_fake_dns(vars) {
    const fake_dns = vars["fake_dns"] || [];
    let result = [];
    for (const i of fake_dns) {
        result.push(...get_fake_dns_item(i));
    }
    return result;
}

function core_table(vars) {
    const core = vars["core"];
    if (!core) {
        return [];
    }
    const aesgcm = function () {
        if (core["system"]["aesgcm"]) {
            return _("Supported");
        }
        return _("Not supported");
    };
    return [
        E('h3', _('Core Information')),
        E('div', { 'class': 'cbi-map-descr' }, _("Basic information about system and Xray runtime.")),
        E('table', { 'class': 'table' }, [
            E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                E('td', { 'class': 'td', 'width': '40%' }, _("Version")),
                E('td', { 'class': 'td' }, `${vars["version"]["version"]} (${vars["version"]["version_statement"][0].split(" ")[5]})`),
            ]),
            E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                E('td', { 'class': 'td', 'width': '40%' }, _('Total CPU Cores')),
                E('td', { 'class': 'td' }, core["system"]["numcpu"]),
            ]),
            E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                E('td', { 'class': 'td', 'width': '40%' }, _('Hardware AES-GCM acceleration')),
                E('td', { 'class': 'td' }, aesgcm()),
            ]),
            E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                E('td', { 'class': 'td', 'width': '40%' }, _('Random TLS Fingerprint')),
                E('td', { 'class': 'td' }, `${vars["random_tls_fingerprint"]["client"]} ${vars["random_tls_fingerprint"]["version"]}`),
            ]),
            E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                E('td', { 'class': 'td', 'width': '40%' }, _('Uptime')),
                E('td', { 'class': 'td' }, '%t'.format(core["runtime"]["uptime"])),
            ]),
            E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                E('td', { 'class': 'td', 'width': '40%' }, _('Goroutines')),
                E('td', { 'class': 'td' }, `${core["runtime"]["numgos"]}`),
            ]),
            E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                E('td', { 'class': 'td', 'width': '40%' }, _('Memory Stats')),
                E('td', { 'class': 'td' }, 'Alloc: %.2mB; HeapSys: %.2mB; StackSys: %.2mB; GC: %d (%d Forced)'.format(vars["memstats"]["Alloc"], vars["memstats"]["HeapSys"], vars["memstats"]["StackSys"], vars["memstats"]["NumGC"], vars["memstats"]["NumForcedGC"])),
            ]),
        ])
    ];
};

function observatory(vars, config) {
    if (!vars["observatory"]) {
        return [];
    }
    const now_timestamp = new Date().getTime() / 1000;
    return [
        E('h3', _('Outbound Observatory')),
        E('div', { 'class': 'cbi-map-descr' }, _("Availability of outbound servers are probed every few seconds.")),
        E('table', { 'class': 'table' }, [
            E('tr', { 'class': 'tr table-titles' }, [
                E('th', { 'class': 'th' }, _('Tag')),
                E('th', { 'class': 'th' }, _('Latency')),
                E('th', { 'class': 'th' }, _('Last seen')),
                E('th', { 'class': 'th' }, _('Last check')),
            ]), ...Object.entries(vars["observatory"]).map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                E('td', { 'class': 'td' }, get_outbound_description(config, v[0])),
                E('td', { 'class': 'td' }, function (c) {
                    if (c[1]["alive"]) {
                        return c[1]["delay"] + ' ' + _("ms");
                    }
                    return _("<i>unreachable</i>");
                }(v)),
                E('td', { 'class': 'td' }, '%d'.format(greater_than_zero(now_timestamp - v[1]["last_seen_time"])) + _('s ago')),
                E('td', { 'class': 'td' }, '%d'.format(greater_than_zero(now_timestamp - v[1]["last_try_time"])) + _('s ago')),
            ]))
        ])
    ];
};

function outbound_stats(vars, config) {
    if (!vars["stats"]) {
        return [];
    }
    if (!vars["stats"]["outbound"]) {
        return [];
    }
    return [
        E('h3', _('Outbound Statistics')),
        E('div', { 'class': 'cbi-map-descr' }, _("Data transferred for outbounds since Xray start.")),
        E('table', { 'class': 'table' }, [
            E('tr', { 'class': 'tr table-titles' }, [
                E('th', { 'class': 'th' }, _('Tag')),
                E('th', { 'class': 'th' }, _('Downlink')),
                E('th', { 'class': 'th' }, _('Uplink')),
            ]), ...Object.entries(vars["stats"]["outbound"]).map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                E('td', { 'class': 'td' }, get_outbound_description(config, v[0])),
                E('td', { 'class': 'td' }, '%.2mB'.format(v[1]["downlink"])),
                E('td', { 'class': 'td' }, '%.2mB'.format(v[1]["uplink"])),
            ]))
        ])
    ];
};

function balancer_stats(vars, config) {
    if (!vars["stats"]) {
        return [];
    }
    if (!vars["stats"]["balancer"]) {
        return [];
    }
    return [
        E('h3', _('Balancer Statistics')),
        E('div', { 'class': 'cbi-map-descr' }, _("Outbound picks by balancers.")),
        E('table', { 'class': 'table' }, [
            E('tr', { 'class': 'tr table-titles' }, [
                E('th', { 'class': 'th', 'width': '32%' }, _('Balancer')),
                E('th', { 'class': 'th', 'width': '68%' }, _('Outbound picks')),
            ]), ...Object.entries(vars["stats"]["balancer"]).map(function (v, index, arr) {
                const sum = Object.entries(v[1]).map((v1, i1, a1) => v1[1]).reduce((a, b) => a + b, 0);
                return E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                    E('td', { 'class': 'td', 'width': '32%' }, v[0]),
                    E('td', { 'class': 'td', 'width': '68%' }, E([], Object.entries(v[1]).flatMap(function (v1, i1, a1) {
                        return [
                            E('span', {
                                'class': 'ifacebadge',
                            }, `<strong>${get_outbound_uci_description(config, v1[0])}</strong>: ${v1[1]} (${"%d".format(greater_than_zero(v1[1] * 100 / sum))}%)`),
                            " "
                        ];
                    })))
                ]);
            })
        ])
    ];
};

function inbound_stats(vars, config) {
    if (!vars["stats"]) {
        return [];
    }
    if (!vars["stats"]["inbound"]) {
        return [];
    }
    return [
        E('h3', _('Inbound Statistics')),
        E('div', { 'class': 'cbi-map-descr' }, _("Data transferred for inbounds since Xray start.")),
        E('table', { 'class': 'table' }, [
            E('tr', { 'class': 'tr table-titles' }, [
                E('th', { 'class': 'th' }, _('Tag')),
                E('th', { 'class': 'th' }, _('Downlink')),
                E('th', { 'class': 'th' }, _('Uplink')),
            ]), ...Object.entries(vars["stats"]["inbound"]).map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                E('td', { 'class': 'td' }, get_inbound_uci_description(config, v[0])),
                E('td', { 'class': 'td' }, '%.2mB'.format(v[1]["downlink"])),
                E('td', { 'class': 'td' }, '%.2mB'.format(v[1]["uplink"])),
            ]))
        ])
    ];
};

function dns_server(vars) {
    if (!vars["stats"]) {
        return [];
    }
    if (!vars["stats"]["dns"]) {
        return [];
    }
    return [
        E('h3', _('DNS Server and Cache Information')),
        E('div', { 'class': 'cbi-map-descr' }, _("Xray Local DNS server statistics (queries and cache details).")),
        E('table', { 'class': 'table' }, [
            E('tr', { 'class': 'tr table-titles' }, [
                E('th', { 'class': 'th', 'width': '30%' }, _('Server')),
                E('th', { 'class': 'th' }, _('Cache size')),
                E('th', { 'class': 'th' }, _('Cache alloc')),
                E('th', { 'class': 'th' }, _('Cache cleanup')),
                E('th', { 'class': 'th' }, _('Cache expire')),
                E('th', { 'class': 'th' }, _('Cache flush')),
                E('th', { 'class': 'th' }, _('Cache hits')),
                E('th', { 'class': 'th' }, _('Cache misses')),
                E('th', { 'class': 'th' }, _('Query success')),
                E('th', { 'class': 'th' }, _('Query empty')),
                E('th', { 'class': 'th' }, _('Query failure')),
                E('th', { 'class': 'th' }, _('Query timeout')),
            ]), ...Object.entries(vars["stats"]["dns"]).map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                E('td', { 'class': 'td', 'width': '30%' }, v[0]),
                E('td', { 'class': 'td' }, v[1]["cache_size"] || 0),
                E('td', { 'class': 'td' }, v[1]["cache_alloc"] || 0),
                E('td', { 'class': 'td' }, v[1]["cache_cleanup"] || 0),
                E('td', { 'class': 'td' }, v[1]["cache_expire"] || 0),
                E('td', { 'class': 'td' }, v[1]["cache_flush"] || 0),
                E('td', { 'class': 'td' }, v[1]["cache_hits"] || 0),
                E('td', { 'class': 'td' }, v[1]["cache_misses"] || 0),
                E('td', { 'class': 'td' }, v[1]["query_success"] || 0),
                E('td', { 'class': 'td' }, v[1]["query_empty"] || 0),
                E('td', { 'class': 'td' }, v[1]["query_failure"] || 0),
                E('td', { 'class': 'td' }, v[1]["query_timeout"] || 0),
            ]))
        ]),
        ...get_dns_cache(vars),
    ];
};

return view.extend({
    load: function () {
        return uci.load(variant);
    },

    render: function (config) {
        if (uci.get_first(config, "general", "metrics_server_enable") != "1") {
            return E([], [
                E('h2', _('Xray (status)')),
                E('p', { 'class': 'cbi-map-descr' }, _("Xray metrics server not enabled. Enable Xray metrics server to see details."))
            ]);
        }
        const info = E('p', { 'class': 'cbi-map-descr' }, _("Collecting data. If any error occurs, check if wget is installed correctly."));
        const detail = E('div', {});
        poll.add(function () {
            fs.exec_direct("/usr/bin/wget", ["-O", "-", `http://127.0.0.1:${uci.get_first(config, "general", "metrics_server_port") || 18888}/debug/vars`], "json").then(function (vars) {
                const result = E([], [
                    E('div', {}, [
                        E('div', { 'class': 'cbi-section', 'data-tab': 'observatory', 'data-tab-title': _('Observatory') }, [
                            ...core_table(vars),
                            ...observatory(vars, config),
                        ]),
                        E('div', { 'class': 'cbi-section', 'data-tab': 'outbounds', 'data-tab-title': _('Outbounds') }, [
                            ...outbound_stats(vars, config),
                            ...balancer_stats(vars, config),
                        ]),
                        E('div', { 'class': 'cbi-section', 'data-tab': 'inbounds', 'data-tab-title': _('Inbounds') }, inbound_stats(vars, config)),
                        E('div', { 'class': 'cbi-section', 'data-tab': 'dns', 'data-tab-title': _('DNS') }, dns_server(vars)),
                        E('div', { 'class': 'cbi-section', 'data-tab': 'fake_dns', 'data-tab-title': _('FakeDNS') }, get_fake_dns(vars)),
                    ])
                ]);
                ui.tabs.initTabGroup(result.lastElementChild.childNodes);
                if (vars["version"]) {
                    dom.content(info, vars["version"]["version_statement"][0]);
                } else {
                    dom.content(info, _("Show some statistics of Xray. If nothing here, enable statistics and / or observatory for Xray."));
                }
                dom.content(detail, result);
            });
        });

        return E([], [
            E('h2', _('Xray (status)')),
            info,
            detail
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
