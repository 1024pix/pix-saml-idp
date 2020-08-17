function SimpleProfileMapper (pu) {
  if(!(this instanceof SimpleProfileMapper)) {
    return new SimpleProfileMapper(pu);
  }
  this._pu = pu;
}

SimpleProfileMapper.fromMetadata = function (metadata) {
  function CustomProfileMapper(user) {
    if(!(this instanceof CustomProfileMapper)) {
      return new CustomProfileMapper(user);
    }
    SimpleProfileMapper.call(this, user);
  }
  CustomProfileMapper.prototype = Object.create(SimpleProfileMapper.prototype);
  CustomProfileMapper.prototype.metadata = metadata;
  return CustomProfileMapper;
}

SimpleProfileMapper.prototype.getClaims = function() {
  var self = this;
  var claims = {};

  this.metadata.forEach(function(entry) {
    claims[entry.id] = entry.multiValue ?
      self._pu[entry.id].split(',') :
      self._pu[entry.id];
  });

  return Object.keys(claims).length && claims;
};

SimpleProfileMapper.prototype.getNameIdentifier = function() {
  return {
    nameIdentifier:                  this._pu.userName,
    nameIdentifierFormat:            this._pu.nameIdFormat,
    nameIdentifierNameQualifier:     this._pu.nameIdNameQualifier,
    nameIdentifierSPNameQualifier:   this._pu.nameIdSPNameQualifier,
    nameIdentifierSPProvidedID:      this._pu.nameIdSPProvidedID
  };
};


SimpleProfileMapper.prototype.metadata = [ {
  id: "IDO",
  optional: false,
  displayName: 'Saml ID',
  description: 'Le samlID de l‘élève',
  multiValue: false
}, {
  id: "PRE",
  optional: false,
  displayName: 'Prénom',
  description: 'Le prénom de l‘élève',
  multiValue: false
}, {
  id: "NOM",
  optional: true,
  displayName: 'Nom',
  description: 'Le nom de l‘élève',
  multiValue: false
}];

module.exports = SimpleProfileMapper;
