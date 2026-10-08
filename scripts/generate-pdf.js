/**
 * University Cryptography Lab - Markdown to PDF Converter
 * Converts report/report.md to report/Security_Report.pdf
 * Uses marked to generate formatted HTML and renders it to PDF using
 * the system's headless browser engine (Microsoft Edge / Chrome) or md-to-pdf.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const marked = require('marked');

const inputMd = path.join(__dirname, '..', 'report', 'report.md');
const tempHtml = path.join(__dirname, '..', 'report', 'temp_report.html');
const outputPdf = path.join(__dirname, '..', 'report', 'Security_Report.pdf');

if (!fs.existsSync(inputMd)) {
  console.error(`Error: ${inputMd} does not exist.`);
  process.exit(1);
}

console.log('Reading report markdown...');
const mdContent = fs.readFileSync(inputMd, 'utf8');

console.log('Parsing markdown to styled HTML...');
const bodyHtml = marked.parse(mdContent);

const fullHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Technical Security Report: Cryptography Lab</title>
<style>
  @page {
    margin: 18mm 16mm;
    size: A4 portrait;
    @bottom-right {
      content: counter(page);
    }
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    line-height: 1.55;
    color: #1f2937;
    font-size: 10.5pt;
    margin: 0;
    padding: 0;
  }
  h1, h2, h3, h4 {
    color: #1e3a8a;
    font-weight: 700;
    page-break-after: avoid;
    break-after: avoid;
  }
  h1 {
    font-size: 1.85rem;
    border-bottom: 2px solid #1e3a8a;
    padding-bottom: 0.3rem;
    margin-top: 0;
    margin-bottom: 0.8rem;
  }
  h2 {
    font-size: 1.35rem;
    border-bottom: 1px solid #e5e7eb;
    padding-bottom: 0.25rem;
    margin-top: 1.8rem;
    margin-bottom: 0.6rem;
  }
  h3 {
    font-size: 1.15rem;
    margin-top: 1.4rem;
    margin-bottom: 0.4rem;
  }
  p {
    margin-top: 0.4rem;
    margin-bottom: 0.6rem;
    text-align: justify;
  }
  pre {
    background-color: #f8fafc;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 10px 12px;
    overflow-x: auto;
    font-family: "Cascadia Code", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 8.5pt;
    line-height: 1.4;
    page-break-inside: avoid;
    break-inside: avoid;
    margin: 0.6rem 0;
  }
  code {
    background-color: #f1f5f9;
    color: #0f172a;
    border-radius: 4px;
    padding: 2px 4px;
    font-family: "Cascadia Code", Consolas, Menlo, monospace;
    font-size: 8.5pt;
  }
  pre code {
    background-color: transparent;
    padding: 0;
    color: inherit;
    font-size: inherit;
  }
  table {
    border-collapse: collapse;
    width: 100%;
    margin: 1rem 0;
    font-size: 9pt;
    page-break-inside: avoid;
    break-inside: avoid;
  }
  th, td {
    border: 1px solid #cbd5e1;
    padding: 6px 10px;
    text-align: left;
    vertical-align: top;
  }
  th {
    background-color: #f1f5f9;
    font-weight: 600;
    color: #1e3a8a;
  }
  tr:nth-child(even) td {
    background-color: #f8fafc;
  }
  blockquote {
    border-left: 4px solid #3b82f6;
    background: #eff6ff;
    padding: 8px 14px;
    margin: 0.8rem 0;
    color: #1e40af;
  }
  hr {
    border: none;
    border-top: 1px solid #e2e8f0;
    margin: 1.6rem 0;
  }
  ul, ol {
    margin-top: 0.4rem;
    margin-bottom: 0.6rem;
    padding-left: 1.5rem;
  }
  li {
    margin-bottom: 0.25rem;
  }
  /* Screenshot Placeholders */
  .screenshot-placeholder {
    border: 2px dashed #3b82f6;
    background: #eff6ff;
    padding: 18px;
    text-align: center;
    border-radius: 6px;
    font-weight: 600;
    color: #1e40af;
    margin: 1rem 0;
    page-break-inside: avoid;
  }
</style>
</head>
<body>
${bodyHtml}
</body>
</html>`;

fs.writeFileSync(tempHtml, fullHtml, 'utf8');

function findBrowserBinary() {
  const possiblePaths = [
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
  ];
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }
  return null;
}

const browserPath = findBrowserBinary();

if (!browserPath) {
  console.error('Error: Could not locate Microsoft Edge or Chrome binary for headless PDF conversion.');
  process.exit(1);
}

console.log(`Using headless browser: ${browserPath}`);
console.log(`Converting ${tempHtml} to ${outputPdf}...`);

try {
  // Use file:// URL format for browser navigation
  const fileUrl = 'file:///' + tempHtml.replace(/\\/g, '/');
  const cmd = `"${browserPath}" --headless --disable-gpu --run-all-compositor-stages-before-draw --print-to-pdf="${outputPdf}" "${fileUrl}"`;
  execSync(cmd, { stdio: 'inherit' });

  if (fs.existsSync(outputPdf)) {
    const stats = fs.statSync(outputPdf);
    console.log(` Successfully generated Security_Report.pdf (${(stats.size / 1024).toFixed(1)} KB)`);
    console.log(`Location: ${outputPdf}`);
    
    // Clean up temporary HTML file
    if (fs.existsSync(tempHtml)) {
      fs.unlinkSync(tempHtml);
    }
  } else {
    throw new Error('PDF file was not created.');
  }
} catch (err) {
  console.error('Failed to generate PDF:', err.message);
  process.exit(1);
}
