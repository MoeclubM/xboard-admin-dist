// The upstream admin source is private. These symbols belong to the pinned
// upstream distribution and are checked by scripts/build-sudoku.mjs.
const sudokuTablePattern = /^(?=(?:[^x]*x){2}[^x]*$)(?=(?:[^p]*p){2}[^p]*$)[xpv]{8}$/;
const sudokuError = name => `dynamic_form.sudoku.errors.${name}`;
const sudokuSchema = py({
  aead: _y(["chacha20-poly1305", "aes-128-gcm"]).default("chacha20-poly1305"),
  table_type: _y(["prefer_entropy", "prefer_ascii", "up_ascii_down_entropy", "up_entropy_down_ascii"]).default("prefer_entropy"),
  padding_min: yy().int().min(0).max(100).default(5),
  padding_max: yy().int().min(0).max(100).default(15),
  enable_pure_downlink: uy().default(false),
  custom_table: cy().refine(value => value === "" || sudokuTablePattern.test(value), sudokuError("table")).default(""),
  custom_tables: gy(cy()).refine(values => values.every(value => sudokuTablePattern.test(value)), sudokuError("table")).default([]),
  multiplex: _y(["off", "auto", "on"]).default("off"),
  http_mask: uy().default(false),
  http_mask_mode: _y(["legacy", "ws"]).default("legacy"),
  http_mask_tls: uy().default(false),
  http_mask_host: cy().default(""),
  path_root: cy().regex(/^[a-zA-Z0-9_-]*$/, sudokuError("path")).default(""),
}).superRefine((value, context) => {
  if (value.padding_min > value.padding_max) {
    context.addIssue({code: "custom", path: ["padding_max"], message: sudokuError("padding")});
  }
  if (value.http_mask_tls && !value.http_mask) {
    context.addIssue({code: "custom", path: ["http_mask_tls"], message: sudokuError("tls")});
  }
});

const SudokuTablesInput = H.forwardRef(function SudokuTablesInput({field, ...controlProps}, ref) {
  const [text, setText] = H.useState(() => (field.value || []).join("\n"));
  H.useEffect(() => {
    const parsed = text.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
    if (JSON.stringify(parsed) !== JSON.stringify(field.value || [])) {
      setText((field.value || []).join("\n"));
    }
  }, [field.value]);
  return Q.jsx(aZt, {
    ...field, ...controlProps, ref: element => {
      field.ref(element);
      if (typeof ref === "function") ref(element);
      else if (ref) ref.current = element;
    }, className: "font-mono text-xs", rows: 3, value: text,
    placeholder: "xpxvvpvv",
    onChange: event => {
      const value = event.target.value;
      setText(value);
      field.onChange(value.split(/\r?\n/).map(item => item.trim()).filter(Boolean));
    },
  });
});

function SudokuForm({form, t}) {
  const maskEnabled = form.watch("http_mask");
  const key = name => `dynamic_form.sudoku.${name}`;
  const field = (name, render, hint) => Q.jsx($y, {
    control: form.control, name,
    render: ({field, fieldState}) => Q.jsxs(Gy, {
      children: [
        Q.jsx(Zy, {className: "text-[12px] font-mono text-foreground/80", children: t(key(name))}),
        Q.jsx(Yy, {children: render(field)}),
        hint && Q.jsx("p", {className: "font-mono text-[11px] text-muted-foreground", children: t(key(hint))}),
        fieldState.error && Q.jsx("p", {role: "alert", className: "text-sm font-medium text-destructive", children: t(fieldState.error.message)}),
      ],
    }),
  }, name);
  const select = (name, options) => field(name, value => Q.jsxs(yzt, {
    value: value.value, onValueChange: value.onChange,
    children: [
      Q.jsx(Czt, {className: "font-mono text-xs", children: Q.jsx(wzt, {})}),
      Q.jsx(Nzt, {children: options.map(([option, label]) => Q.jsx(Lzt, {value: option, children: label}, option))}),
    ],
  }));
  const text = (name, hint) => field(name, value => Q.jsx(u8e, {
    ...value, value: value.value || "", className: "font-mono text-xs",
  }), hint);
  const number = name => field(name, value => Q.jsx(u8e, {
    ...value, type: "number", min: 0, max: 100, step: 1,
    className: "font-mono text-xs", value: value.value ?? "",
    onChange: event => value.onChange(event.target.value === "" ? undefined : Number(event.target.value)),
  }));
  const toggle = (name, hint) => field(name, value => Q.jsx(oZt, {
    checked: Boolean(value.value),
    onCheckedChange: checked => {
      value.onChange(checked);
      if (name === "http_mask" && !checked) {
        form.setValue("http_mask_tls", false, {shouldValidate: true});
      }
    },
  }), hint);
  return Q.jsxs(Q.Fragment, {
    children: [
      Q.jsxs("div", {className: "grid grid-cols-2 gap-3", children: [
        select("aead", [["chacha20-poly1305", "ChaCha20-Poly1305"], ["aes-128-gcm", "AES-128-GCM"]]),
        select("table_type", ["prefer_entropy", "prefer_ascii", "up_ascii_down_entropy", "up_entropy_down_ascii"].map(value => [value, t(key(`tables.${value}`))])),
        number("padding_min"), number("padding_max"),
      ]}),
      toggle("enable_pure_downlink", "pure_downlink_hint"),
      text("custom_table", "table_hint"),
      field("custom_tables", value => Q.jsx(SudokuTablesInput, {field: value}), "tables_hint"),
      toggle("http_mask"),
      maskEnabled && Q.jsxs("div", {className: "space-y-4 rounded-lg border bg-muted/5 p-4", children: [
        Q.jsxs("div", {className: "grid grid-cols-2 gap-3", children: [
          select("http_mask_mode", [["legacy", "HTTP (legacy)"], ["ws", "WebSocket"]]),
          select("multiplex", ["off", "auto", "on"].map(value => [value, t(key(`multiplex_options.${value}`))])),
        ]}),
        toggle("http_mask_tls", "tls_hint"),
        text("http_mask_host", "host_hint"),
        text("path_root", "path_hint"),
      ]}),
    ],
  });
}
