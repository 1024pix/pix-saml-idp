const SimpleProfileMapper = require('./lib/simpleProfileMapper');
const { dedent, prettyPrintXml } = require('./utils/string-utils');
const Parser = require('xmldom').DOMParser;
const chalk = require('chalk');
const fs = require('fs');

function resolveFilePath(filePath) {

  if (filePath.startsWith('saml-idp/')) {
    // Allows file path options to files included in this package, like config.js
    const resolvedPath = require.resolve(filePath.replace(/^saml\-idp\//, `${__dirname}/`));
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

function certFileCoercer(value) {
  const filePath = resolveFilePath(value);
  if (filePath) {
    return fs.readFileSync(filePath)
  }
  throw new Error(
      chalk`{red Invalid / missing {bold ${description}}} - {yellow not a valid crypt key/cert or file path}${helpText ? '\n' + helpText : ''}`
  )
};

const metadata = [{
  id: "IDO",
  optional: true,
  displayName: 'IDO',
  description: 'The smalId',
  multiValue: false
}, {
  id: "firstName",
  optional: false,
  displayName: 'First Name',
  description: 'The given name of the user',
  multiValue: false
}, {
  id: "lastName",
  optional: false,
  displayName: 'Last Name',
  description: 'The surname of the user',
  multiValue: false
}];

const profileMapper = SimpleProfileMapper.fromMetadata(metadata);

module.exports = (function() {
  const config = {
    profile: {
      userName: 'saml.jackson@example.com',
      nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      IDO: 'SamlID',
      firstName: 'Saml',
      lastName: 'Jackson',
    },
    metadata,
    IDP_PATHS: {
      SSO: '/saml/sso',
      SLO: '/saml/slo',
      METADATA: '/metadata',
      SIGN_IN: '/signin',
      SIGN_OUT: '/signout',
      SETTINGS: '/settings'
    },
    idpOptions: {
      issuer:                 'urn:exemplae:idp',
      signatureAlgorithm:     'rsa-sha256',
      digestAlgorithm:        'sha256',
      signResponse:           true,
      lifetimeInSeconds:      3600,
      authnContextClassRef:   'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      allowRequestAcsUrl:     true,
      serviceProviderId:      'http://localhost:4200/api/saml/metadata.xml',
      sloUrl:                 '',
      acsUrl:                 'http://localhost:4200/api/saml/assert',
      destination:            'http://localhost:4200/api/saml/assert',
      recipient:              'http://localhost:4200/api/saml/assert',
      audience:               'http://localhost:4200/api/saml/metadata.xml',
      RelayState:             'http://localhost:4200/api/saml/login',
      cert:                   certFileCoercer('./idp-public-cert.pem'),
      key:                    certFileCoercer('./idp-private-key.pem'),
      encryptAssertion:       false,
      encryptionCert:         true,
      encryptionAlgorithm:    'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
      keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
      authnContextDecl:       null,
      includeAttributeNameFormat: true,
      profileMapper,
      postEndpointPath:       function() { return this.IDP_PATHS.SSO },
      redirectEndpointPath:   function() { return this.IDP_PATHS.SSO },
      logoutEndpointPaths:   {},
      getUserFromRequest:     function(req) { return req.user; },
      getPostURL:             function (audience, authnRequestDom, req, callback) {
        return callback(null, req.idp.options.acsUrl);
      },
      transformAssertion:     function(assertionDom) {
        if (this.authnContextDecl) {
          var declDoc;
          try {
            declDoc = new Parser().parseFromString(this.authnContextDecl);
          } catch(err){
            console.log('Unable to parse Authentication Context Declaration XML', err);
          }
          if (declDoc) {
            const authnContextDeclEl = assertionDom.createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnContextDecl');
            authnContextDeclEl.appendChild(declDoc.documentElement);
            const authnContextEl = assertionDom.getElementsByTagName('saml:AuthnContext')[0];
            authnContextEl.appendChild(authnContextDeclEl);
          }
        }
      },
      responseHandler:        function(response, opts, req, res, next) {
        console.log(dedent(chalk`
                                Sending SAML Response to {cyan ${opts.postUrl}} =>
                                  {bold RelayState} =>
                                    {cyan ${opts.RelayState || UNDEFINED_VALUE}}
                                  {bold SAMLResponse} =>`
        ));

        console.log(prettyPrintXml(response.toString(), 4));

        res.render('samlresponse', {
          AcsUrl: opts.postUrl,
          SAMLResponse: response.toString('base64'),
          RelayState: opts.RelayState
        });
      },
    },
    CRYPT_TYPES: {
      certificate: /-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/,
      'RSA private key': /-----BEGIN RSA PRIVATE KEY-----\n[^-]*\n-----END RSA PRIVATE KEY-----/,
      'public key': /-----BEGIN PUBLIC KEY-----\n[^-]*\n-----END PUBLIC KEY-----/,
    },
    CERT_OPTIONS: [
      'cert',
      'key',
      'encryptionCert',
      'encryptionPublicKey',
      'httpsPrivateKey',
      'httpsCert',
    ],
    WILDCARD_ADDRESSES: ['0.0.0.0', '::'],
    UNDEFINED_VALUE: 'None'
  }

  return config
})();
