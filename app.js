require('dotenv').config();
const chalk               = require('chalk'),
      express             = require('express'),
      os                  = require('os'),
      http                = require('http'),
      https               = require('https'),
      path                = require('path'),
      extend              = require('extend'),
      hbs                 = require('hbs'),
      logger              = require('morgan'),
      bodyParser          = require('body-parser'),
      session             = require('express-session'),
      yargs               = require('yargs/yargs'),
      samlp               = require('samlp'),
      SessionParticipants = require('samlp/lib/sessionParticipants');

const { IDP_PATHS, UNDEFINED_VALUE, WILDCARD_ADDRESSES, CERT_OPTIONS, profile, idpOptions, metadata } = require('./config')
const { dedent } = require('./lib/utils/string-utils');
const generateEnvironmentVariables = require('./lib/usecases/generate-environment-variables');

function getHashCode(str) {
  let hash = 0;
  if (str.length == 0) return hash;
  for (i = 0; i < str.length; i++) {
    char = str.charCodeAt(i);
    hash = ((hash<<5)-hash)+char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash;
}

function formatOptionValue(key, value) {
  if (typeof value === 'string') {
    return value;
  }
  if (CERT_OPTIONS.includes(key)) {
    return chalk`${
        value.toString()
            .replace(/-----.+?-----|\n/g, '')
            .substring(0, 80)
    }{white …}`;
  }
  if (!value && value !== false) {
    return UNDEFINED_VALUE;
  }
  if (typeof value === 'function') {
    const lines = `${value}`.split('\n');
    return lines[0].slice(0, -2);
  }
  return `${JSON.stringify(value)}`;
}

/**
 * Arguments
 */
function processArgs(args, options) {
  let baseArgv;

  if (options) {
    baseArgv = yargs(args).config(options);
  } else {
    baseArgv = yargs(args);
  }
  return baseArgv
    .usage('\nSimple IdP for SAML 2.0 WebSSO & SLO Profile\n\n' +
        'Launches an IdP web server that mints SAML assertions or logout responses for a Service Provider (SP)\n\n' +
        'Usage:\n\t$0 --acsUrl {url} --audience {uri}')
    .alias({h: 'help'})
    .options({
      host: {
        description: 'IdP Web Server Listener Host',
        required: false,
        default: 'localhost'
      },
      port: {
        description: 'IdP Web Server Listener Port',
        required: true,
        alias: 'p',
        default: 7000
      },
      issuer: {
        description: 'IdP Issuer URI',
        required: true,
        alias: 'iss',
        default: 'urn:example:idp'
      },
      acsUrl: {
        description: 'SP Assertion Consumer URL',
        required: false,
        alias: 'acs'
      },
      sloUrl: {
        description: 'SP Single Logout URL',
        required: false,
        alias: 'slo'
      },
      audience: {
        description: 'SP Audience URI',
        required: false,
        alias: 'aud'
      },
      serviceProviderId: {
        description: 'SP Issuer/Entity URI',
        required: false,
        alias: 'spId',
        string: true
      },
      relayState: {
        description: 'Default SAML RelayState for SAMLResponse',
        required: false,
        alias: 'rs'
      },
      disableRequestAcsUrl: {
        description: 'Disables ability for SP AuthnRequest to specify Assertion Consumer URL',
        required: false,
        boolean: true,
        alias: 'static',
        default: false
      },
      encryptAssertion: {
        description: 'Encrypts assertion with SP Public Key',
        required: false,
        boolean: true,
        alias: 'enc',
        default: false
      },
      https: {
        description: 'Enables HTTPS Listener (requires httpsPrivateKey and httpsCert)',
        required: true,
        boolean: true,
        default: false
      },
      signResponse: {
        description: 'Enables signing of responses',
        required: false,
        boolean: true,
        default: true,
        alias: 'signResponse'
      },
      rollSession: {
        description: 'Create a new session for every authn request instead of reusing an existing session',
        required: false,
        boolean: true,
        default: false
      },
      authnContextClassRef: {
        description: 'Authentication Context Class Reference',
        required: false,
        string: true,
        default: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
        alias: 'acr'
      },
    })
    .example('$0 --acsUrl http://acme.okta.com/auth/saml20/exampleidp --audience https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV', '')
    .check(function(argv, aliases) {
      if (argv.encryptAssertion) {
        if (argv.encryptionPublicKey === undefined) {
          return 'encryptionPublicKey argument is also required for assertion encryption';
        }
        if (argv.encryptionCert === undefined) {
          return 'encryptionCert argument is also required for assertion encryption';
        }
      }
      return true;
    })
    .wrap(baseArgv.terminalWidth());
}

function _runServer(argv) {
  const app = express();
  const httpServer = argv.https ?
    https.createServer({ key: argv.httpsPrivateKey, cert: argv.httpsCert }, app) :
    http.createServer(app);
  const blocks = {};

  console.log(dedent(chalk`
    Listener Port:
      {cyan ${argv.host}:${argv.port}}
    HTTPS Enabled:
      {cyan ${argv.https}}

    {bold [{yellow Identity Provider}]}

    Issuer URI:
      {cyan ${argv.issuer}}
    Sign Response Message:
      {cyan ${argv.signResponse}}
    Encrypt Assertion:
      {cyan ${argv.encryptAssertion}}
    Authentication Context Class Reference:
      {cyan ${argv.authnContextClassRef || UNDEFINED_VALUE}}
    Authentication Context Declaration:
      {cyan ${argv.authnContextDecl || UNDEFINED_VALUE}}
    Default RelayState:
      {cyan ${argv.relayState || UNDEFINED_VALUE}}

    {bold [{yellow Service Provider}]}

    Issuer URI:
      {cyan ${argv.serviceProviderId || UNDEFINED_VALUE}}
    Audience URI:
      {cyan ${argv.audience || UNDEFINED_VALUE}}
    ACS URL:
      {cyan ${argv.acsUrl || UNDEFINED_VALUE}}
    SLO URL:
      {cyan ${argv.sloUrl || UNDEFINED_VALUE}}
    Trust ACS URL in Request:
      {cyan ${!argv.disableRequestAcsUrl}}
  `));

  /**
   * App Environment
   */

  app.set('host', process.env.HOST || argv.host);
  app.set('port', process.env.PORT || argv.port);
  app.set('views', path.join(__dirname, 'views'));

  /**
   * View Engine
   */

  app.set('view engine', 'hbs');
  app.set('view options', { layout: 'layout' })
  app.engine('handlebars', hbs.__express);

  // Register Helpers
  hbs.registerHelper('extend', function(name, context) {
    var block = blocks[name];
    if (!block) {
      block = blocks[name] = [];
    }

    block.push(context.fn(this));
  });

  hbs.registerHelper('block', function(name) {
    const val = (blocks[name] || []).join('\n');
    // clear the block
    blocks[name] = [];
    return val;
  });


  hbs.registerHelper('select', function(selected, options) {
    return options.fn(this).replace(
      new RegExp(' value=\"' + selected + '\"'), '$& selected="selected"');
  });

  hbs.registerHelper('getProperty', function(attribute, context) {
    return context[attribute];
  });

  hbs.registerHelper('serialize', function(context) {
    return new Buffer(JSON.stringify(context)).toString('base64');
  });

  /**
   * Middleware
   */

  app.use(logger(':date> :method :url - {:referrer} => :status (:response-time ms)', {
    skip: function (req, res)
      {
        return req.path.startsWith('/bower_components') || req.path.startsWith('/css')
      }
  }));
  app.use(bodyParser.urlencoded({extended: true}));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(session({
    secret: 'The universe works on a math equation that never even ever really ends in the end',
    resave: false,
    saveUninitialized: true,
    name: 'idp_sid',
    cookie: { maxAge: 60 * 60 * 1000 }
  }));

  /**
   * View Handlers
   */

  const showUser = function (req, res, next) {
    res.render('user', {
      user: req.user,
      participant: req.participant,
      metadata: req.metadata,
      authnRequest: req.authnRequest,
      idp: req.idp.options,
      paths: IDP_PATHS
    });
  }

  /**
   * Shared Handlers
   */

  const parseSamlRequest = function(req, res, next) {
    samlp.parseRequest(req, function(err, data) {
      if (err) {
        return res.render('error', {
          message: 'SAML AuthnRequest Parse Error: ' + err.message,
          error: err
        });
      };
      if (data) {
        req.authnRequest = {
          relayState: req.query.RelayState || req.body.RelayState,
          id: data.id,
          issuer: data.issuer,
          destination: data.destination,
          acsUrl: data.assertionConsumerServiceURL,
          forceAuthn: data.forceAuthn === 'true'
        };
        console.log('Received AuthnRequest => \n', req.authnRequest);
      }
      return showUser(req, res, next);
    })
  };

  const getSessionIndex = function(req) {
    if (req && req.session) {
      return Math.abs(getHashCode(req.session.id)).toString();
    }
  }

  const getParticipant = function(req) {
    return {
      serviceProviderId: req.idp.options.serviceProviderId,
      sessionIndex: getSessionIndex(req),
      nameId: req.user.userName,
      nameIdFormat: req.user.nameIdFormat,
      serviceProviderLogoutURL: req.idp.options.sloUrl
    }
  }

  const parseLogoutRequest = function(req, res, next) {
    if (!req.idp.options.sloUrl) {
      return res.render('error', {
        message: 'SAML Single Logout Service URL not defined for Service Provider'
      });
    };

    console.log('Processing SAML SLO request for participant => \n', req.participant);

    return samlp.logout({
      issuer:                 req.idp.options.issuer,
      cert:                   req.idp.options.cert,
      key:                    req.idp.options.key,
      digestAlgorithm:        req.idp.options.digestAlgorithm,
      signatureAlgorithm:     req.idp.options.signatureAlgorithm,
      sessionParticipants:    new SessionParticipants(
      [
        req.participant
      ]),
      clearIdPSession: function(callback) {
        console.log('Destroying session ' + req.session.id + ' for participant', req.participant);
        req.session.destroy();
        callback();
      }
    })(req, res, next);
  }

  /**
   * Routes
   */

  app.use(function(req, res, next){
    if (argv.rollSession) {
      req.session.regenerate(function(err) {
        return next();
      });
    } else {
      next()
    }
  });

  app.use(function(req, res, next){
    req.user = profile;
    req.metadata = metadata;
    req.idp = { options: idpOptions };
    req.participant = getParticipant(req);
    next();
  });

  app.get(['/', '/idp', IDP_PATHS.SSO], parseSamlRequest);
  app.post(['/', '/idp', IDP_PATHS.SSO], parseSamlRequest);

  app.get(IDP_PATHS.SLO, parseLogoutRequest);
  app.post(IDP_PATHS.SLO, parseLogoutRequest);

  app.post(IDP_PATHS.SIGN_IN, function(req, res) {
    const authOptions = extend({}, req.idp.options);
    Object.keys(req.body).forEach(function(key) {
      var buffer;
      if (key === '_authnRequest') {
        buffer = new Buffer(req.body[key], 'base64');
        req.authnRequest = JSON.parse(buffer.toString('utf8'));

        // Apply AuthnRequest Params
        authOptions.inResponseTo = req.authnRequest.id;
        if (req.idp.options.allowRequestAcsUrl && req.authnRequest.acsUrl) {
          authOptions.acsUrl = req.authnRequest.acsUrl;
          authOptions.recipient = req.authnRequest.acsUrl;
          authOptions.destination = req.authnRequest.acsUrl;
          authOptions.forceAuthn = req.authnRequest.forceAuthn;
        }
        if (req.authnRequest.relayState) {
          authOptions.RelayState = req.authnRequest.relayState;
        }
      } else {
        req.user[key] = req.body[key];
      }
    });

    if (!authOptions.encryptAssertion) {
      delete authOptions.encryptionCert;
      delete authOptions.encryptionPublicKey;
    }

    // Set Session Index
    authOptions.sessionIndex = getSessionIndex(req);

    // Keep calm and Single Sign On
    console.log(dedent(chalk`
      Generating SAML Response using =>
        {bold User} => ${Object.entries(req.user).map(([key, value]) => chalk`
          ${key}: {cyan ${value}}`
        ).join('')}
        {bold SAMLP Options} => ${Object.entries(authOptions).map(([key, value]) => chalk`
          ${key}: {cyan ${formatOptionValue(key, value)}}`
        ).join('')}
    `));
    samlp.auth(authOptions)(req, res);
  })

  app.get(IDP_PATHS.METADATA, function(req, res, next) {
    samlp.metadata(req.idp.options)(req, res);
  });

  app.post(IDP_PATHS.METADATA, function(req, res, next) {
    if (req.body && req.body.attributeName && req.body.displayName) {
      var attributeExists = false;
      const attribute = {
        id: req.body.attributeName,
        optional: true,
        displayName: req.body.displayName,
        description: req.body.description || '',
        multiValue: req.body.valueType === 'multi'
      };

      req.metadata.forEach(function(entry) {
        if (entry.id === req.body.attributeName) {
          entry = attribute;
          attributeExists = true;
        }
      });

      if (!attributeExists) {
        req.metadata.push(attribute);
      }
      console.log("Updated SAML Attribute Metadata => \n", req.metadata)
      res.status(200).end();
    }
  });

  app.get(IDP_PATHS.SIGN_OUT, function(req, res, next) {
    if (req.idp.options.sloUrl) {
      console.log('Initiating SAML SLO request for user: ' + req.user.userName +
      ' with sessionIndex: ' + getSessionIndex(req));
      res.redirect(IDP_PATHS.SLO);
    } else {
      console.log('SAML SLO is not enabled for SP, destroying IDP session');
      req.session.destroy(function(err) {
        if (err) {
          throw err;
        }
        res.redirect('back');
      })
    }
  });

  app.get([IDP_PATHS.SETTINGS], function(req, res, next) {
    res.render('settings', {
      idp: req.idp.options
    });
  });

  app.post([IDP_PATHS.SETTINGS], function(req, res, next) {
    Object.keys(req.body).forEach(function(key) {
      switch(req.body[key].toLowerCase()){
        case "true": case "yes": case "1":
          req.idp.options[key] = true;
          break;
        case "false": case "no": case "0":
          req.idp.options[key] = false;
          break;
        default:
          req.idp.options[key] = req.body[key];
          break;
      }

      if (req.body[key].match(/^\d+$/)) {
        req.idp.options[key] = parseInt(req.body[key], '10');
      }
    });

    console.log('Updated IdP Configuration => \n', req.idp.options);
    res.redirect('/');
  });

  app.post([IDP_PATHS.GENERATE], function(req, res, next) {
    const env = generateEnvironmentVariables(req.body.location)
    res.render('envResponse', {
      env
    });
  });

  // catch 404 and forward to error handler
  app.use(function(req, res, next) {
    const err = new Error('Route Not Found');
    err.status = 404;
    next(err);
  });

  // development error handler
  app.use(function(err, req, res, next) {
    if (err) {
      res.status(err.status || 500);
      res.render('error', {
          message: err.message,
          error: err
      });
    }
  });

  /**
   * Start IdP Web Server
   */

  console.log(chalk`Starting IdP server on port {cyan ${app.get('host')}:${app.get('port')}}...\n`);

  httpServer.listen(app.get('port'), app.get('host'), function() {
    const scheme          = argv.https ? 'https' : 'http',
          {address, port} = httpServer.address(),
          hostname        = WILDCARD_ADDRESSES.includes(address) ? os.hostname() : 'localhost',
          baseUrl         = `${scheme}://${hostname}:${port}`;

    console.log(dedent(chalk`
      IdP Metadata URL:
        {cyan ${baseUrl}${IDP_PATHS.METADATA}}

      SSO Bindings:
        urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
          => {cyan ${baseUrl}${IDP_PATHS.SSO}}
        urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
          => {cyan ${baseUrl}${IDP_PATHS.SSO}}
          
      IdP server ready at
        {cyan ${baseUrl}}
    `));
  });
}

function runServer(options) {
  const args = processArgs([], options);
  return _runServer(args.argv);
}

function main () {
  const args = processArgs(process.argv.slice(2));
  _runServer(args.argv);
}

module.exports = {
  runServer,
  main,
};

if (require.main === module) {
  main();
}
