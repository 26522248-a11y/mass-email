export class ParseArgsError extends Error {}

export function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (!tok.startsWith('--')) { out._.push(tok); continue; }
    const key = tok.slice(2);
    if (key.includes('=')) {
      const idx = key.indexOf('=');
      out[key.slice(0, idx)] = key.slice(idx + 1);
      continue;
    }
    if (key === 'yes' || key === 'dry-run' || key === 'no-sign' || key === 'help' || key === 'verbose') {
      out[key] = true;
      continue;
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) { out[key] = true; continue; }
    out[key] = value;
    i++;
  }
  return out;
}
