import {execFileSync} from "node:child_process";
import {createHash} from "node:crypto";
import {readFileSync, writeFileSync, existsSync, unlinkSync} from "node:fs";
import {fileURLToPath} from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const baseline = "ef5f43da335092cbff8fdf0ad7ff9b4d92d7d0d7";
const originalFile = "assets/index-CEIYH7i8.js";
const originalHash = "f04f09a95bfdb04fa5132e336bf87c364d4e360cb95774872ff18eb69e9bcd77";
const upstream = file => execFileSync("git", ["show", `${baseline}:${file}`], {cwd: root, maxBuffer: 20 * 1024 * 1024});
const digest = value => createHash("sha256").update(value).digest("hex");
let bundle = upstream(originalFile).toString("utf8");
if (digest(bundle) !== originalHash) throw new Error("Unexpected upstream admin bundle; review the integration points before rebuilding.");
const replace = (before, after) => {
  if (bundle.split(before).length !== 2) throw new Error(`Expected one integration point: ${before}`);
  bundle = bundle.replace(before, after);
};

replace('e.AnyTLS="anytls",e))(iqt', 'e.AnyTLS="anytls",e.Sudoku="sudoku",e))(iqt');
replace('{type:"anytls",label:"AnyTLS"}],sqt=', '{type:"anytls",label:"AnyTLS"},{type:"sudoku",label:"Sudoku"}],sqt=');
replace('anytls:"#7E57C2"};', 'anytls:"#7E57C2",sudoku:"#0F766E"};');
replace('const h4t=', `${readFileSync(path.join(root, "src/sudoku.js"), "utf8")}\nconst h4t=`);
replace('mieru:{schema:n5t(t),component:r5t}}))', 'mieru:{schema:n5t(t),component:r5t},sudoku:{schema:sudokuSchema,component:SudokuForm}}))');
replace('hasMultiplex:"multiplex"in(s5t[l]?.schema?.shape||{})', 'hasMultiplex:l!=="sudoku"&&"multiplex"in(s5t[l]?.schema?.shape||{})');
replace('color:sqt[iqt.Mieru]}];function x5t', 'color:sqt[iqt.Mieru]},{value:iqt.Sudoku,label:"Sudoku",color:sqt[iqt.Sudoku]}];function x5t');
replace('const t=x.getValues(),n=parseFloat(t.transfer_enable_gb||"0")', 'const t=x.getValues();if(l==="sudoku"){const result=sudokuSchema.safeParse(t.protocol_settings);if(!result.success)return void gE.error(e(result.error.issues[0].message));t.protocol_settings=result.data}const n=parseFloat(t.transfer_enable_gb||"0")');

const manifestPath = path.join(root, "manifest.json");
const previousFile = JSON.parse(readFileSync(manifestPath, "utf8"))["index.html"].file;
const outputFile = `assets/index-${digest(bundle).slice(0, 12)}.js`;
writeFileSync(path.join(root, outputFile), bundle);
execFileSync(process.execPath, ["--check", path.join(root, outputFile)]);
const manifest = JSON.parse(upstream("manifest.json"));
manifest["index.html"].file = outputFile;
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
writeFileSync(path.join(root, "index.html"), upstream("index.html").toString("utf8").replaceAll(originalFile, outputFile));
for (const oldFile of new Set([originalFile, previousFile])) {
  if (oldFile !== outputFile && existsSync(path.join(root, oldFile))) unlinkSync(path.join(root, oldFile));
}

const locales = JSON.parse(readFileSync(path.join(root, "src/sudoku.locales.json"), "utf8"));
for (const [locale, messages] of Object.entries(locales)) {
  const file = `locales/${locale}.js`;
  const text = upstream(file).toString("utf8");
  const prefix = `window.XBOARD_TRANSLATIONS['${locale}'] = `;
  const start = text.indexOf(prefix) + prefix.length;
  const end = text.lastIndexOf(";");
  if (start < prefix.length || end < start) throw new Error(`Unexpected locale format: ${locale}`);
  const data = JSON.parse(text.slice(start, end));
  data.server.dynamic_form.sudoku = messages;
  writeFileSync(path.join(root, file), text.slice(0, start) + JSON.stringify(data, null, 2) + ";\n");
}
console.log(JSON.stringify({baseline, file: outputFile, sha256: digest(bundle)}, null, 2));
