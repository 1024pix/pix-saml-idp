const xmlBuilder = require('xmlbuilder');
const { idpOptions, spPaths } = require('../../config');

module.exports = function generateEnvironmentVariable(location) {
  const cert = idpOptions.cert.toString('utf-8');
  const xmlSamlIdpConfig = _makeXmlSamlIdpConfig(cert);
  const xmlSamlSpConfig = _makeXmlSamlSpConfig(cert);
  const idpEnv = {
    metadata: xmlSamlIdpConfig
  }
  const spEnv = {
    metadata: xmlSamlSpConfig,
    relayState: `${location}${spPaths.assert}`
  }

  return { idp: JSON.stringify(idpEnv), sp: JSON.stringify(spEnv) }
}

function _makeXmlSamlIdpConfig(cert) {
  const xml = xmlBuilder
      .create('EntityDescriptor', { headless: true})
      .attribute('xmlns', 'urn:oasis:names:tc:SAML:2.0:metadata')
      .attribute('xmlns:shibmd', 'urn:mace:shibboleth:metadata:1.0')
      .attribute('xmlns:xml', 'http://www.w3.org/XML/1998/namespace')
      .attribute('xmlns:mdui', 'urn:oasis:names:tc:SAML:metadata:ui')
      .attribute('entityID', idpOptions.issuer)
      .element('IDPSSODescriptor')
      .attribute('protocolSupportEnumeration','urn:oasis:names:tc:SAML:2.0:protocol')
      .element('KeyDescriptor')
      .attribute('use','signing')
      .element('ds:KeyInfo')
      .element('ds:X509Data')
      .element('ds:X509Certificate', cert)
      .up()
      .up()
      .up()
      .up()
      .element('NameIDFormat','urn:oasis:names:tc:SAML:2.0:nameid-format:transient')
      .up()
      .element('SingleSignOnService')
      .attribute('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')
      .attribute('Location', idpOptions.postEndpointPath);
  return xml.end();
}

function _makeXmlSamlSpConfig(cert) {
  const xml = xmlBuilder
      .create('EntityDescriptor', { headless: true})
      .attribute('xmlns', 'urn:oasis:names:tc:SAML:2.0:metadata')
      .attribute('xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#')
      .attribute('entityID', idpOptions.issuer)
      .element('SPSSODescriptor').attribute('protocolSupportEnumeration','urn:oasis:names:tc:SAML:2.0:protocol')
      .element('KeyDescriptor')
      .element('ds:KeyInfo')
      .element('ds:X509Data')
      .element('ds:X509Certificate', cert)
      .up()
      .up()
      .up()
      .element('EncryptionMethod').attribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#aes256-cbc')
      .up()
      .element('EncryptionMethod').attribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#aes128-cbc')
      .up()
      .element('EncryptionMethod').attribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc')
      .up()
      .up()
      .element('NameIDFormat','urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
      .up()
      .element('AssertionConsumerService')
      .attribute('index', '1')
      .attribute('isDefault', 'true')
      .attribute('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
      .attribute('Location', idpOptions.postEndpointPath);
  return xml.end();
}
