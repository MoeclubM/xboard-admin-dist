// Flux multi-channel configuration schema and form for the pinned Xboard admin bundle.
const fluxShortIdPattern = /^(?:[0-9a-fA-F]{2}){0,8}$/;
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
  window.crypto.getRandomValues(buf);
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

const fluxRealityBlockSchema = py({
  server_name: cy().default(""),
  server_port: yy().int().min(1).max(65535).default(443),
  public_key: cy().default(""),
  private_key: cy().default(""),
  short_id: cy().refine(v => v === "" || fluxShortIdPattern.test(v), fluxError("short_id")).default(""),
  dest: cy().default(""),
  allow_insecure: uy().default(false),
});

const fluxChannelSchema = py({
  id: cy().default(""),
  enabled: uy().default(true),
  connect_host: cy().default(""),
  connect_ports: cy().default(""),
  ip_version: _y(["auto", "ipv4", "ipv6"]).default("auto"),
  listen_ip: cy().default(""),
  listen_ports: cy().default(""),
  role: _y(["primary", "backup"]).default("primary"),
  weight: yy().int().min(1).max(100).default(100),
  transport: _y(["tcp", "udp", "http"]).default("tcp"),
  http_mode: _y(["ws", "httpupgrade", "h2"]).optional().default("ws"),
  http_host: cy().optional().default(""),
  http_path: cy().optional().default("/"),
  http_headers: fy(cy()).optional().default({}),
  security: cy().optional().default(""),
  sni: cy().optional().default(""),
  allow_insecure: uy().optional().default(false),
  fingerprint: cy().optional().default(""),
  cert_mode: _y(["inherit", "file", "origin_plain"]).optional().default("inherit"),
  cert_path: cy().optional().default(""),
  key_path: cy().optional().default(""),
  obfs_key: cy().optional().default(""),
  reality: fluxRealityBlockSchema.optional().default({}),
});

const fluxSchema = (certConfigSchema, routingSchema) => py({
  ip_strategy: _y(["dual", "prefer_v4", "prefer_v6", "v4_only", "v6_only"]).default("dual"),
  standby_channels: yy().int().min(0).max(16).default(2),
  rotation_interval_sec: yy().int().min(0).max(86400).default(180),
  rotation_bytes_mb: yy().int().min(0).max(10240).default(96),
  security: _y(["reality", "tls", "obfs"]).default("reality"),
  obfs_key: cy().default(""),
  tls_settings: py({
    server_name: cy().default(""),
    allow_insecure: uy().default(false),
    ech: v4t,
  }).default({}),
  reality_settings: fluxRealityBlockSchema.default({}),
  utls: _4t,
  cert_config: certConfigSchema.default({}),
  routing: routingSchema.optional().default({}),
  channels: gy(fluxChannelSchema).default([]),
}).superRefine((value, ctx) => {
  const channels = value.channels || [];
  if (channels.length > 0 && !channels.some(ch => ch.enabled)) {
    ctx.addIssue({code: "custom", path: ["channels"], message: fluxError("no_enabled_channel")});
    return;
  }
  let totalConnectPorts = 0;
  const listenBindings = new Set();
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
    const rawListen = ch.listen_ports || ch.connect_ports;
    if (rawListen) {
      const parsedL = fluxCountPorts(rawListen);
      if (!parsedL.ok) {
        ctx.addIssue({code: "custom", path: ["channels", idx, "listen_ports"], message: fluxError("ports")});
      } else {
        const ip = (ch.listen_ip || "0.0.0.0").trim();
        const proto = ch.transport === "udp" ? "udp" : "tcp";
        parsedL.ports.forEach(p => listenBindings.add(ip + ":" + p + "/" + proto));
        if (listenBindings.size > 64) {
          ctx.addIssue({code: "custom", path: ["channels", idx, "listen_ports"], message: fluxError("port_limit")});
        }
      }
    }
    const sec = ch.security || value.security;
    if (sec === "tls") {
      if (ch.transport === "udp" && ch.cert_mode === "origin_plain") {
        ctx.addIssue({code: "custom", path: ["channels", idx, "cert_mode"], message: fluxError("udp_origin_plain")});
      }
      if (ch.cert_mode === "file" && (!String(ch.cert_path || "").trim() || !String(ch.key_path || "").trim())) {
        ctx.addIssue({code: "custom", path: ["channels", idx, "cert_path"], message: fluxError("cert_file")});
      }
    }
  });
});

function FluxChannelEditor({item, index, nodeSecurity, onUpdate, onRemove, t, tKey}) {
  const [open, setOpen] = H.useState(index === 0);
  const [headersText, setHeadersText] = H.useState(() => fluxFormatHeadersText(item.http_headers));
  H.useEffect(() => {
    const formatted = fluxFormatHeadersText(item.http_headers);
    if (JSON.stringify(fluxParseHeadersText(headersText)) !== JSON.stringify(item.http_headers || {})) {
      setHeadersText(formatted);
    }
  }, [item.http_headers]);

  const patch = updates => onUpdate(index, {...item, ...updates});
  const patchReality = updates => patch({reality: {...(item.reality || {}), ...updates}});
  const effectiveSec = item.security || nodeSecurity || "reality";
  const summaryParts = [
    (item.transport || "tcp").toUpperCase(),
    effectiveSec.toUpperCase(),
    item.connect_ports || "-",
    item.role === "backup" ? t(tKey("roles.backup")) : null,
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
                labelEl(t(tKey("channel.role"))),
                selectBox(item.role || "primary", v => patch({role: v}), [
                  ["primary", t(tKey("roles.primary"))],
                  ["backup", t(tKey("roles.backup"))],
                ]),
              ]}),
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.weight"))),
                Q.jsx(u8e, {type: "number", min: 1, max: 100, className: "h-8 font-mono text-xs", value: item.weight ?? 100, onChange: e => patch({weight: e.target.value === "" ? 100 : Number(e.target.value)})}),
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
                labelEl(t(tKey("channel.transport"))),
                selectBox(item.transport || "tcp", v => patch({transport: v}), [
                  ["tcp", "TCP"],
                  ["udp", "UDP (QUIC)"],
                  ["http", "HTTP"],
                ]),
              ]}),
            ],
          }),
          item.transport === "http" && Q.jsxs("div", {
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
            children: [
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.security"))),
                selectBox(item.security || "__inherit__", v => patch({security: v === "__inherit__" ? "" : v}), [
                  ["__inherit__", t(tKey("security_modes.inherit"))],
                  ["reality", "REALITY"],
                  ["tls", "TLS"],
                  ["obfs", "Obfs"],
                ]),
              ]}),
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.sni"))),
                Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.sni || "", onChange: e => patch({sni: e.target.value})}),
              ]}),
              Q.jsxs("div", {children: [
                labelEl(t(tKey("channel.fingerprint"))),
                selectBox(item.fingerprint || "__inherit__", v => patch({fingerprint: v === "__inherit__" ? "" : v}), [
                  ["__inherit__", t(tKey("security_modes.inherit"))],
                  ...b4t.map(fp => [fp.value, fp.label]),
                ]),
              ]}),
            ],
          }),
          effectiveSec === "reality" && Q.jsxs("div", {
            className: "space-y-2 rounded border bg-muted/10 p-2.5",
            children: [
              Q.jsxs("div", {
                className: "grid grid-cols-3 gap-2",
                children: [
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("reality.dest"))),
                    Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.reality?.dest || "", placeholder: "www.microsoft.com:443", onChange: e => patchReality({dest: e.target.value})}),
                  ]}),
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("reality.server_name"))),
                    Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.reality?.server_name || "", onChange: e => patchReality({server_name: e.target.value})}),
                  ]}),
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("reality.short_id"))),
                    Q.jsxs("div", {className: "relative", children: [
                      Q.jsx(u8e, {className: "h-8 pr-8 font-mono text-xs", value: item.reality?.short_id || "", onChange: e => patchReality({short_id: e.target.value})}),
                      Q.jsx(xtt, {
                        type: "button",
                        variant: "ghost",
                        size: "icon",
                        className: "absolute right-0 top-0 h-8 w-8",
                        onClick: () => patchReality({short_id: M4t()}),
                        children: Q.jsx(YXt, {icon: "ion:refresh-outline", className: "h-3.5 w-3.5"}),
                      }),
                    ]}),
                  ]}),
                ],
              }),
              Q.jsxs("div", {
                className: "grid grid-cols-2 gap-2",
                children: [
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("reality.private_key"))),
                    Q.jsxs("div", {className: "relative", children: [
                      Q.jsx(u8e, {className: "h-8 pr-8 font-mono text-xs", value: item.reality?.private_key || "", onChange: e => patchReality({private_key: e.target.value})}),
                      Q.jsx(xtt, {
                        type: "button",
                        variant: "ghost",
                        size: "icon",
                        className: "absolute right-0 top-0 h-8 w-8",
                        onClick: () => {
                          const kp = O4t();
                          patchReality({private_key: kp.privateKey, public_key: kp.publicKey});
                        },
                        children: Q.jsx(YXt, {icon: "ion:key-outline", className: "h-3.5 w-3.5"}),
                      }),
                    ]}),
                  ]}),
                  Q.jsxs("div", {children: [
                    labelEl(t(tKey("reality.public_key"))),
                    Q.jsx(u8e, {className: "h-8 font-mono text-xs", value: item.reality?.public_key || "", onChange: e => patchReality({public_key: e.target.value})}),
                  ]}),
                ],
              }),
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
          effectiveSec === "obfs" && Q.jsxs("div", {
            className: "rounded border bg-muted/10 p-2.5",
            children: [
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
            ],
          }),
        ],
      }),
    ],
  });
}

function FluxForm({form, t}) {
  const security = form.watch("security") || "reality";
  const channels = form.watch("channels") || [];
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
        transport: nextIdx === 2 ? "udp" : "tcp",
        http_mode: "ws",
        http_host: "",
        http_path: "/",
        http_headers: {},
        security: "",
        sni: "",
        allow_insecure: false,
        fingerprint: "",
        cert_mode: "inherit",
        cert_path: "",
        key_path: "",
        obfs_key: "",
        reality: {server_name: "", server_port: 443, public_key: "", private_key: "", short_id: "", dest: "", allow_insecure: false},
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
          select("security", [
            ["reality", "REALITY"],
            ["tls", "TLS"],
            ["obfs", "Obfs"],
          ]),
          select("ip_strategy", ["dual", "prefer_v4", "prefer_v6", "v4_only", "v6_only"].map(v => [v, t(tKey("ip_strategies." + v))])),
        ],
      }),
      Q.jsxs("div", {
        className: "grid grid-cols-3 gap-3",
        children: [
          numField("standby_channels", 0, 16),
          numField("rotation_interval_sec", 0, 86400),
          numField("rotation_bytes_mb", 0, 10240),
        ],
      }),
      security === "reality" && Q.jsxs("div", {
        className: "space-y-3 rounded-lg border bg-muted/5 p-3",
        children: [
          Q.jsxs("div", {
            className: "grid grid-cols-3 gap-2",
            children: [
              field("reality_settings.server_name", f => Q.jsx(u8e, {...f, value: f.value || "", placeholder: "www.microsoft.com", className: "font-mono text-xs"})),
              field("reality_settings.server_port", f => Q.jsx(u8e, {...f, type: "number", min: 1, max: 65535, value: f.value ?? 443, onChange: e => f.onChange(Number(e.target.value || 443)), className: "font-mono text-xs"})),
              field("reality_settings.dest", f => Q.jsx(u8e, {...f, value: f.value || "", placeholder: "www.microsoft.com:443", className: "font-mono text-xs"})),
            ],
          }),
          Q.jsxs("div", {
            className: "grid grid-cols-2 gap-2",
            children: [
              field("reality_settings.private_key", f => Q.jsxs("div", {
                className: "relative",
                children: [
                  Q.jsx(u8e, {...f, value: f.value || "", className: "pr-9 font-mono text-xs"}),
                  Q.jsx(xtt, {
                    type: "button",
                    variant: "ghost",
                    size: "icon",
                    className: "absolute right-0 top-0 h-full px-2",
                    onClick: () => {
                      const kp = O4t();
                      form.setValue("reality_settings.private_key", kp.privateKey, {shouldDirty: true, shouldValidate: true});
                      form.setValue("reality_settings.public_key", kp.publicKey, {shouldDirty: true, shouldValidate: true});
                    },
                    children: Q.jsx(YXt, {icon: "ion:key-outline", className: "h-4 w-4"}),
                  }),
                ],
              })),
              field("reality_settings.public_key", f => Q.jsx(u8e, {...f, value: f.value || "", className: "font-mono text-xs"})),
            ],
          }),
          field("reality_settings.short_id", f => Q.jsxs("div", {
            className: "relative",
            children: [
              Q.jsx(u8e, {...f, value: f.value || "", className: "pr-9 font-mono text-xs"}),
              Q.jsx(xtt, {
                type: "button",
                variant: "ghost",
                size: "icon",
                className: "absolute right-0 top-0 h-full px-2",
                onClick: () => form.setValue("reality_settings.short_id", M4t(), {shouldDirty: true, shouldValidate: true}),
                children: Q.jsx(YXt, {icon: "ion:refresh-outline", className: "h-4 w-4"}),
              }),
            ],
          })),
          Q.jsx(y4t, {form, t}),
        ],
      }),
      security === "tls" && Q.jsxs("div", {
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
      security === "obfs" && Q.jsx("div", {
        className: "rounded-lg border bg-muted/5 p-3",
        children: field("obfs_key", f => Q.jsxs("div", {
          className: "relative",
          children: [
            Q.jsx(u8e, {...f, value: f.value || "", className: "pr-9 font-mono text-xs"}),
            Q.jsx(xtt, {
              type: "button",
              variant: "ghost",
              size: "icon",
              className: "absolute right-0 top-0 h-full px-2",
              onClick: () => form.setValue("obfs_key", fluxRandomHex(16), {shouldDirty: true, shouldValidate: true}),
              children: Q.jsx(YXt, {icon: "ion:refresh-outline", className: "h-4 w-4"}),
            }),
          ],
        })),
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
                  nodeSecurity: security,
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
