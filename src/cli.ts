import { readFileSync } from 'fs';
import { glob } from 'glob';
import { scanK8sManifest, formatK8sOutput } from './k8s.js';

async function main() {
  const args = process.argv.slice(2);
  let dir = '.';
  let format: 'text' | 'json' = 'text';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--format' && args[i + 1] === 'json') {
      format = 'json';
      i++;
    } else if (!args[i].startsWith('-')) {
      dir = args[i];
    }
  }

  const files: string[] = await new Promise((res, rej) => {
    glob('**/*.{yaml,yml}', { cwd: dir, absolute: true }, (err, matches) => {
      if (err) rej(err);
      else res(matches);
    });
  });

  let allFindings = scanK8sManifest('');

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const findings = scanK8sManifest(content);
      allFindings = allFindings.concat(findings);
    } catch {
      // skip unreadable files
    }
  }

  console.log(formatK8sOutput(allFindings, format));
}

main();