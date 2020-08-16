const fs = require('fs');
const path = require('path');

function resolveFilePath(filePath) {
  if (filePath.startsWith('pix-saml-idp/')) {
    // Allows file path options to files included in this package, like config.js
    const resolvedPath = require.resolve(filePath.replace(/^pix\-saml\-idp\//, `${__dirname}/`));
    return fs.existsSync(resolvedPath) && resolvedPath;
  }
  let possiblePath;
  if (fs.existsSync(filePath)) {
    return filePath;
  }
  if (filePath.startsWith('~/')) {
    possiblePath = path.resolve(process.env.HOME, filePath.slice(2));
    if (fs.existsSync(possiblePath)) {
      return possiblePath;
    } else {
      // for ~/ paths, don't try to resolve further
      return filePath;
    }
  }
  return ['.', __dirname]
      .map(base => path.resolve(base, filePath))
      .find(possiblePath => fs.existsSync(possiblePath));
}

module.exports = {
  resolveFilePath
}
