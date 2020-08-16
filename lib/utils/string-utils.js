const xmlFormat = require('xml-formatter');
const chalk = require('chalk');

function dedent(str) {
  // Reduce the indentation of all lines by the indentation of the first line
  const match = str.match(/^\n?( +)/);
  if (!match) {
    return str;
  }
  const indentRe = new RegExp(`\n${match[1]}`, 'g');
  return str.replace(indentRe, '\n').replace(/^\n/, '');
}

function prettyPrintXml(xml, indent) {
  // This works well, because we format the xml before applying the replacements
  const prettyXml = xmlFormat(xml, {indentation: '  '})
      // Matches `<{prefix}:{name} .*?>`
      .replace(/<(\/)?((?:[\w]+)(?::))?([\w]+)(.*?)>/g, chalk`<{green $1$2{bold $3}}$4>`)
      // Matches ` {attribute}="{value}"
      .replace(/ ([\w:]+)="(.+?)"/g, chalk` {white $1}={cyan "$2"}`);
  if (indent) {
    return prettyXml.replace(/(^|\n)/g, `$1${' '.repeat(indent)}`);
  }
  return prettyXml;
}

module.exports = {
  dedent,
  prettyPrintXml
}
