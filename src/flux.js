// Flux multi-channel configuration schema and form for the pinned Xboard admin bundle.
const fluxError = name => "dynamic_form.flux.errors." + name;

const fluxCountPorts = spec => {
  const raw = String(spec ?? "").trim();
  if (!raw || raw === "0") return {ok: true, ports: []};
  const tokens = raw.split(/[,;\s]+/).filter(Boolean);
  const seen = new Set();
  for (const token of tokens) {
    if (token.includes("-")) {
      const parts = token.split("-");
      if (parts.length !== 2 || !/^\d+$/.test(parts[0]) || !/^\d+$/.test(parts[1])) {
        return {ok: false, ports: []};
      }
      const start = Number(parts[0]), end = Number(parts[1]);
      if (start < 1 || end > 65535 || start > end || seen.size + (end - start + 1) > 64) {
        return {ok: false, ports: []};
      }
      for (let p = start; p <= end; p++) seen.add(p);
    } else {
      if (!/^\d+$/.test(token)) return {ok: false, ports: []};
      const p = Number(token);
      if (p < 1 || p > 65535 || (!seen.has(p) && seen.size >= 64)) {
        return {ok: false, ports: []};
      }
      seen.add(p);
    }
  }
  return {ok: seen.size > 0 && seen.size <= 64, ports: Array.from(seen)};
};

const fluxRandomHex = bytes => {
  const buf = new Uint8Array(bytes);
  if (typeof window !== "undefined" && window.crypto?.getRandomValues) {
    window.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < bytes; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(buf, b => b.toString(16).padStart(2, "0")).join("");
};

const fluxParseHeadersText = text => {
  const out = {};
  for (const line of String(text || "").split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const k = line.slice(0, idx).trim();
    const v = line.slice(idx + 1).trim();
    if (k && !/^\d+$/.test(k)) out[k] = v;
  }
  return out;
};

const fluxFormatHeadersText = obj => {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return "";
  return Object.entries(obj).map(([k, v]) => k + ": " + (v ?? "")).join("\n");
};

const createDefaultFluxChannels = () => {
  const sharedKey = fluxRandomHex(16);
  const make = (id, ip_version) => ({
    id,
    enabled: true,
    connect_host: "",
    connect_ports: "",
    ip_version,
    listen_ip: "",
    listen_ports: "",
    role: "primary",
    weight: 100,
    transport: "tcp",
    http_mode: "ws",
    http_host: "",
    http_path: "/",
    http_headers: {},
    security: "obfs",
    sni: "",
    fingerprint: "",
    cert_mode: "inherit",
    cert_path: "",
    key_path: "",
    obfs_key: sharedKey,
  });
  return [make("tcp-v4", "ipv4"), make("tcp-v6", "ipv6")];
};

const fluxChannelSchema = py({
  id: cy().default(""),
  enabled: uy().default(true),
  connect_host: cy().default(""),
  connect_ports: cy().default(""),
  ip_version: _y(["auto", "ipv4", "ipv6"]).default("auto"),
  listen_ip: cy().default(""),
  listen_ports: cy().default(""),
  role: _y(["primary", "udp_relay", "prefer", "backup"]).default("primary"),
  weight: yy().int().min(1).max(100).default(100),
  transport: _y(["tcp", "udp", "http"]).default("tcp"),
  http_mode: _y(["ws", "httpupgrade", "h2"]).optional().default("ws"),
  http_host: cy().optional().default(""),
  http_path: cy().optional().default("/"),
  http_headers: fy(cy()).optional().default({}),
  security: _y(["obfs", "tls"]).default("obfs"),
  sni: cy().optional().default(""),
  allow_insecure: uy().optional(),
  fingerprint: cy().optional().default(""),
  cert_mode: _y(["inherit", "file", "origin_plain"]).optional().default("inherit"),
  cert_path: cy().optional().default(""),
  key_path: cy().optional().default(""),
  obfs_key: cy().optional().default(""),
});

const fluxSchema = (certConfigSchema, routingSchema) => py({
  ip_strategy: _y(["latency", "dual", "prefer_v4", "prefer_v6", "v4_only", "v6_only"]).default("latency"),
  standby_channels: yy().int().min(0).max(16).default(2),
  rotation_interval_sec: yy().int().min(0).max(86400).default(180),
  rotation_bytes_mb: yy().int().min(0).max(10240).default(96),
  tls_settings: py({
    server_name: cy().default(""),
    allow_insecure: uy().default(false),
    ech: v4t,
  }).default({}),
  utls: _4t,
  cert_config: certConfigSchema.default({}),
  routing: routingSchema.optional().default({}),
  channels: gy(fluxChannelSchema).default(createDefaultFluxChannels),
}).superRefine((value, ctx) => {
  const channels = value.channels || [];
  if (channels.length === 0 || !channels.some(ch => ch.enabled)) {
    ctx.addIssue({code: "custom", path: ["channels"], message: fluxError("no_enabled_channel")});
    return;
  }
  let totalConnectPorts = 0;
  const listenBindings = new Map();
  channels.forEach((ch, idx) => {
    if (!ch.enabled) return;
    if (ch.connect_ports) {
      const parsed = fluxCountPorts(ch.connect_ports);
      if (!parsed.ok) {
        ctx.addIssue({code: "custom", path: ["channels", idx, "connect_ports"], message: fluxError("ports")});
      } else {
        totalConnectPorts += parsed.ports.length;
        if (totalConnectPorts > 64) {
          ctx.addIssue({code: "custom", path: ["channels", idx, "connect_ports"], message: fluxError("port_limit")});
        }
      }
    } else {
      totalConnectPorts += 1;
    }
    const sec = ch.security === "tls" ? "tls" : "obfs";
    const rawListen = ch.listen_ports || ch.connect_ports;
    if (rawListen) {
      const parsedL = fluxCountPorts(rawListen);
      if (!parsedL.ok) {
        ctx.addIssue({code: "custom", path: ["channels", idx, "listen_ports"], message: fluxError("ports")});
      } else {
        const ip = (ch.listen_ip || "0.0.0.0").trim();
        const proto = ch.transport === "udp" ? "udp" : "tcp";
        const sig = [
          ch.transport || "tcp",
          ch.transport === "http" ? (ch.http_mode || "ws") : "",
          ch.transport === "http" ? (ch.http_host || "") : "",
          ch.transport === "http" ? (ch.http_path || "/") : "",
          sec,
          sec === "obfs" ? String(ch.obfs_key || "").trim() : ((ch.cert_mode || "inherit") + ":" + (ch.cert_path || "") + ":" + (ch.key_path || "")),
        ].join("|");
        parsedL.ports.forEach(p => {
          const key = ip + ":" + p + "/" + proto;
          if (listenBindings.has(key) && listenBindings.get(key) !== sig) {
            ctx.addIssue({code: "custom", path: ["channels", idx, "listen_ports"], message: fluxError("port_conflict")});
          } else {
            listenBindings.set(key, sig);
          }
        });
        if (listenBindings.size > 64) {
          ctx.addIssue({code: "custom", path: ["channels", idx, "listen_ports"], message: fluxError("port_limit")});
        }
      }
    }
    if (sec === "tls") {
      if (ch.transport === "udp" && ch.cert_mode === "origin_plain") {
        ctx.addIssue({code: "custom", path: ["channels", idx, "cert_mode"], message: fluxError("udp_origin_plain")});
      }
      if (ch.cert_mode === "file" && (!String(ch.cert_path || "").trim() || !String(ch.key_path || "").trim())) {
        ctx.addIssue({code: "custom", path: ["channels", idx, "cert_path"], message: fluxError("cert_file")});
      }
    } else if (ch.obfs_key && String(ch.obfs_key).trim().length < 4) {
      ctx.addIssue({code: "custom", path: ["channels", idx, "obfs_key"], message: fluxError("obfs_key")});
    }
  });
});

function FluxChannelEditor({item, index, onUpdate, onRemove, t, tKey}) {
  const [open, setOpen] = H.useState(index === 0);
  const [headersText, setHeadersText] = H.useState(() => fluxFormatHeadersText(item.http_headers));
  H.useEffect(() => {
    const formatted = fluxFormatHeadersText(item.http_headers);
    if (JSON.stringify(fluxParseHeadersText(headersText)) !== JSON.stringify(item.http_headers || {})) {
      setHeadersText(formatted);
    }
  }, [item.http_headers]);

  const patch = updates => onUpdate(index, {...item, ...updates});
  const transport = item.transport || "tcp";
  const effectiveSec = item.security === "tls" ? "tls" : "obfs";
  const role = transport !== "udp" && item.role === "udp_relay" ? "primary" : (item.role || "primary");
  const roleOptions = transport === "udp"
    ? [
        ["primary", t(tKey("roles.primary_udp"))],
        ["udp_relay", t(tKey("roles.udp_relay"))],
        ["prefer", t(tKey("roles.prefer_udp"))],
        ["backup", t(tKey("roles.backup"))],
      ]
    : [
        ["primary", t(tKey("roles.primary"))],
        ["prefer", t(tKey("roles.prefer"))],
        ["backup", t(tKey("roles.backup"))],
      ];
  const roleLabel = role === "primary"
    ? null
    : (roleOptions.find(([v]) => v === role)?.[1] || role);
  const summaryParts = [
    transport.toUpperCase(),
    effectiveSec.toUpperCase(),
    item.ip_version && item.ip_version !== "auto" ? item.ip_version.toUpperCase() : null,
    item.connect_ports || "-",
    roleLabel,
  ].filter(Boolean).join(" · ");

  const labelEl = text => Q.jsx("label", {className: "block font-mono text-[11px] text-foreground/80 mb-1", children: text});
  const selectBox = (val, onChange, options) => Q.jsxs(yzt, {
    value: val,
    onValueChange: onChange,
    children: [
      Q.jsx(Czt, {className: "h-8 font-mono text-xs", children: Q.jsx(wzt, {})}),
      Q.jsx(Nzt, {children: options.map(([v, label]) => Q.jsx(Lzt, {value: v, children: label}, v))}),
    ],
  });

  return Q.jsxs("div", {
    className: "rounded-md border bg-background",
    children: [
      Q.jsxs("div", {
        className: "flex items-center justify-between gap-2 px-3 py-2",
        children: [
          Q.jsxs("button", {
            type: "button",
            onClick: () => setOpen(!open),
            className: "flex flex-1 items-center gap-2 text-left font-mono text-xs",
            children: [
              Q.jsx(YXt, {icon: open ? "lucide:chevron-down" : "lucide:chevron-right", className: "h-3.5 w-3.5 text-muted-foreground"}),
              Q.jsx("span", {className: "font-semibold", children: item.id || ("ch-" + (index + 1))}),
              Q.jsx("span", {className: "text-[11px] text-muted-foreground", children: summaryParts}),
            ],
          }),
          Q.jsxs("div", {
            className: "flex items-center gap-2",
            children: [
              Q.jsx(oZt, {checked: item.enabled !== false, onCheckedChange: checked => patch({enabled: checked})}),
              Q.jsx(xtt, {
                type: "button",
                variant: "ghost",
                size: "icon",
                className: "h-7 w-7 text-muted-foreground hover:text-destructive",
                onClick: () => onRemove(index),
                children: Q.jsx(YXt, {icon: "lucide:trash-2", className: "h-3.5 w-3.5"}),
              }),
            ],
          }),
        ],
      }),
      open && Q.jsxs("div", {
        className: "space-y-3 border-t px-3 py-3",
        children: [
          Q.jsxs("div", {
            className: "grid grid-cols-3 gap-2",
            children: [
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.id"))),
                Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.id || "", placeholder: "ch-" + (index + 1), onChange: e => patch({id: e.target.value})}),
              ]}),
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.transport"))),
                selectBox(transport, v => patch({
                  transport: v,
                  role: v !== "udp" && item.role === "udp_relay" ? "primary" : (item.role || "primary"),
                }), [
                  ["tcp", "TCP"],
                  ["udp", "UDP (QUIC)"],
                  ["http", "HTTP"],
                ]),
              ]}),
              Q.jsxs("div", {children: [
                labelEl(t(tKey(transport === "udp" ? "channel.udp_priority" : "channel.role"))),
                selectBox(role, v => patch({role: v}), roleOptions),
              ]}),
            ],
          }),
          Q.jsxs("div", {
            className: "grid grid-cols-3 gap-2",
            children: [
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.connect_host"))),
                Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.connect_host || "", placeholder: t(tKey("channel.inherit_host")), onChange: e => patch({connect_host: e.target.value})}),
              ]}),
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.connect_ports"))),
                Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.connect_ports || "", placeholder: "443 / 20000-20010", onChange: e => patch({connect_ports: e.target.value})}),
              ]}),
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.ip_version"))),
                selectBox(item.ip_version || "auto", v => patch({ip_version: v}), [
                  ["auto", "Auto"],
                  ["ipv4", "IPv4"],
                  ["ipv6", "IPv6"],
                ]),
              ]}),
            ],
          }),
          Q.jsxs("div", {
            className: "grid grid-cols-3 gap-2",
            children: [
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.listen_ip"))),
                Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.listen_ip || "", placeholder: "0.0.0.0", onChange: e => patch({listen_ip: e.target.value})}),
              ]}),
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.listen_ports"))),
                Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.listen_ports || "", placeholder: t(tKey("channel.inherit_ports")), onChange: e => patch({listen_ports: e.target.value})}),
              ]}),
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.weight"))),
                Q.jsx(u8e, {type: "number", min: 1, max: 100, className: "h-8 font-mono text-xs", value: item.weight ?? 100, onChange: e => patch({weight: e.target.value === "" ? 100 : Number(e.target.value)})}),
              ]}),
            ],
          }),
          transport === "http" && Q.jsxs("div", {
            className: "space-y-2 rounded border bg-muted/10 p-2.5",
            children: [
              Q.jsxs("div", {
                className: "grid grid-cols-3 gap-2",
                children: [
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("channel.http_mode"))),
                    selectBox(item.http_mode || "ws", v => patch({http_mode: v}), [
                      ["ws", "WebSocket"],
                      ["httpupgrade", "HTTPUpgrade"],
                      ["h2", "HTTP/2"],
                    ]),
                  ]}),
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("channel.http_host"))),
                    Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.http_host || "", onChange: e => patch({http_host: e.target.value})}),
                  ]}),
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("channel.http_path"))),
                    Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.http_path || "/", placeholder: "/", onChange: e => patch({http_path: e.target.value})}),
                  ]}),
                ],
              }),
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.http_headers"))),
                Q.jsx(aZt, {
                  rows: 2,
                  className: "font-mono text-xs",
                  placeholder: "X-Forwarded-Proto: https",
                  value: headersText,
                  onChange: e => {
                    const val = e.target.value;
                    setHeadersText(val);
                    patch({http_headers: fluxParseHeadersText(val)});
                  },
                }),
              ]}),
            ],
          }),
          Q.jsxs("div", {
            className: "grid grid-cols-3 gap-2",
            children: effectiveSec === "tls"
              ? [
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("channel.security"))),
                    selectBox(effectiveSec, v => patch({
                      security: v,
                      obfs_key: v === "obfs" && !item.obfs_key ? fluxRandomHex(16) : (item.obfs_key || ""),
                    }), [
                      ["obfs", t(tKey("security_modes.obfs"))],
                      ["tls", t(tKey("security_modes.tls"))],
                    ]),
                  ]}, "sec"),
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("channel.sni"))),
                    Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.sni || "", onChange: e => patch({sni: e.target.value})}),
                  ]}, "sni"),
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("channel.fingerprint"))),
                    selectBox(item.fingerprint || "__inherit__", v => patch({fingerprint: v === "__inherit__" ? "" : v}), [
                      ["__inherit__", t(tKey("security_modes.inherit"))],
                      ...b4t.map(fp => [fp.value, fp.label]),
                    ]),
                  ]}, "fp"),
                ]
              : [
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("channel.security"))),
                    selectBox(effectiveSec, v => patch({security: v}), [
                      ["obfs", t(tKey("security_modes.obfs"))],
                      ["tls", t(tKey("security_modes.tls"))],
                    ]),
                  ]}, "sec"),
                  Q.jsxs("div", {className: "col-span-2", children: [
                    labelEl(t(tKey("obfs_key"))),
                    Q.jsxs("div", {className: "relative", children: [
                      Q.jsx(u8e, {className: "h-8 pr-8 font-mono text-xs", value: item.obfs_key || "", onChange: e => patch({obfs_key: e.target.value})}),
                      Q.jsx(xtt, {
                        type: "button",
                        variant: "ghost",
                        size: "icon",
                        className: "absolute right-0 top-0 h-8 w-8",
                        onClick: () => patch({obfs_key: fluxRandomHex(16)}),
                        children: Q.jsx(YXt, {icon: "ion:refresh-outline", className: "h-3.5 w-3.5"}),
                      }),
                    ]}),
                  ]}, "obfs"),
                ],
          }),
          effectiveSec === "tls" && Q.jsxs("div", {
            className: "space-y-2 rounded border bg-muted/10 p-2.5",
            children: [
              Q.jsxs("div", {
                className: "grid grid-cols-2 gap-2",
                children: [
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("channel.cert_mode"))),
                    selectBox(item.cert_mode || "inherit", v => patch({cert_mode: v}), [
                      ["inherit", t(tKey("cert_modes.inherit"))],
                      ["file", t(tKey("cert_modes.file"))],
                      ["origin_plain", t(tKey("cert_modes.origin_plain"))],
                    ]),
                  ]}),
                  Q.jsxs("div", {className: "flex items-center justify-between pt-5", children: [
                    Q.jsx("span", {className: "font-mono text-xs text-foreground/80", children: t(tKey("channel.allow_insecure"))}),
                    Q.jsx(oZt, {checked: Boolean(item.allow_insecure), onCheckedChange: v => patch({allow_insecure: v})}),
                  ]}),
                ],
              }),
              item.cert_mode === "file" && Q.jsxs("div", {
                className: "grid grid-cols-2 gap-2",
                children: [
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("channel.cert_path"))),
                    Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.cert_path || "", placeholder: "/etc/ssl/cert.pem", onChange: e => patch({cert_path: e.target.value})}),
                  ]}),
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("channel.key_path"))),
                    Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.key_path || "", placeholder: "/etc/ssl/key.pem", onChange: e => patch({key_path: e.target.value})}),
                  ]}),
                ],
              }),
            ],
          }),
        ],
      }),
    ],
  });
}

function FluxForm({form, t}) {
  const channels = form.watch("channels") || [];
  const hasInheritedTls = channels.some(ch => ch?.enabled !== false && ch?.security === "tls" && (ch?.cert_mode || "inherit") === "inherit");
  const tKey = name => "dynamic_form.flux." + name;

  const field = (name, render) => Q.jsx($y, {
    control: form.control,
    name,
    render: ({field: f, fieldState}) => Q.jsxs(Gy, {
      children: [
        Q.jsx(Zy, {className: "text-[12px] font-mono text-foreground/80", children: t(tKey(name))}),
        Q.jsx(Yy, {children: render(f)}),
        fieldState.error && Q.jsx("p", {role: "alert", className: "text-xs font-medium text-destructive", children: t(fieldState.error.message)}),
      ],
    }),
  }, name);

  const select = (name, options) => field(name, f => Q.jsxs(yzt, {
    value: f.value,
    onValueChange: f.onChange,
    children: [
      Q.jsx(Czt, {className: "font-mono text-xs", children: Q.jsx(wzt, {})}),
      Q.jsx(Nzt, {children: options.map(([val, label]) => Q.jsx(Lzt, {value: val, children: label}, val))}),
    ],
  }));

  const numField = (name, min, max) => field(name, f => Q.jsx(u8e, {
    ...f,
    type: "number",
    min,
    max,
    step: 1,
    className: "font-mono text-xs",
    value: f.value ?? "",
    onChange: e => f.onChange(e.target.value === "" ? undefined : Number(e.target.value)),
  }));

  const addChannel = () => {
    const list = form.getValues("channels") || [];
    const nextIdx = list.length + 1;
    form.setValue("channels", [
      ...list,
      {
        id: "ch-" + nextIdx,
        enabled: true,
        connect_host: "",
        connect_ports: "",
        ip_version: "auto",
        listen_ip: "",
        listen_ports: "",
        role: "primary",
        weight: 100,
        transport: "tcp",
        http_mode: "ws",
        http_host: "",
        http_path: "/",
        http_headers: {},
        security: "obfs",
        sni: "",
        fingerprint: "",
        cert_mode: "inherit",
        cert_path: "",
        key_path: "",
        obfs_key: fluxRandomHex(16),
      },
    ], {shouldDirty: true, shouldValidate: true});
  };

  const updateChannel = (index, updated) => {
    const list = [...(form.getValues("channels") || [])];
    list[index] = updated;
    form.setValue("channels", list, {shouldDirty: true, shouldValidate: true});
  };

  const removeChannel = index => {
    const list = (form.getValues("channels") || []).filter((_, i) => i !== index);
    form.setValue("channels", list, {shouldDirty: true, shouldValidate: true});
  };

  return Q.jsxs("div", {
    className: "space-y-4",
    children: [
      Q.jsxs("div", {
        className: "grid grid-cols-2 gap-3",
        children: [
          select("ip_strategy", ["latency", "dual", "prefer_v4", "prefer_v6", "v4_only", "v6_only"].map(v => [v, t(tKey("ip_strategies." + v))])),
          numField("standby_channels", 0, 16),
          numField("rotation_interval_sec", 0, 86400),
          numField("rotation_bytes_mb", 0, 10240),
        ],
      }),
      hasInheritedTls && Q.jsxs("div", {
        className: "space-y-3 rounded-lg border bg-muted/5 p-3",
        children: [
          Q.jsxs("div", {
            className: "flex gap-2",
            children: [
              Q.jsx("div", {className: "flex-1", children: field("tls_settings.server_name", f => Q.jsx(u8e, {...f, value: f.value || "", className: "font-mono text-xs"}))}),
              field("tls_settings.allow_insecure", f => Q.jsx("div", {className: "py-2 text-center", children: Q.jsx(oZt, {checked: Boolean(f.value), onCheckedChange: f.onChange})})),
            ],
          }),
          Q.jsx(y4t, {form, t}),
          Q.jsx(x4t, {form, t, prefix: "tls_settings.ech"}),
        ],
      }),
      Q.jsxs("div", {
        className: "space-y-2 rounded-lg border bg-muted/5 p-3",
        children: [
          Q.jsxs("div", {
            className: "flex items-center justify-between",
            children: [
              Q.jsx("span", {className: "font-mono text-xs font-semibold text-foreground/90", children: t(tKey("channels_title"))}),
              Q.jsxs(Lf, {
                type: "button",
                variant: "outline",
                size: "sm",
                className: "h-7 px-2.5 font-mono text-xs",
                onClick: addChannel,
                children: [
                  Q.jsx(YXt, {icon: "lucide:plus", className: "mr-1 h-3.5 w-3.5"}),
                  t(tKey("add_channel")),
                ],
              }),
            ],
          }),
          channels.length === 0
            ? Q.jsx("p", {className: "font-mono text-[11px] text-muted-foreground", children: t(tKey("channels_empty"))})
            : Q.jsx("div", {
                className: "space-y-2",
                children: channels.map((item, index) => Q.jsx(FluxChannelEditor, {
                  item,
                  index,
                  onUpdate: updateChannel,
                  onRemove: removeChannel,
                  t,
                  tKey,
                }, item.id || ("idx-" + index))),
              }),
        ],
      }),
    ],
  });
}
