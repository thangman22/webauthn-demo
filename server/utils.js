const crypto = require('crypto')
const base64url = require('base64url')
const cbor = require('cbor')
const verifyPackedWebauthn = require('./verify.packed.webauthn')
const verifyFidoU2fWebauthn = require('./verify.fidou2f.webauthn')
const verifyAndroidSafetynetWebauthn = require('./verify.android-safetynet.webauthn')
const verifyAndroidKeyWebauthn = require('./verify.android-key.webauthn')

const helpers = require('./helpers')

/**
 * U2F Presence constant
 */
let U2F_USER_PRESENTED = 0x01

/**
 * Takes signature, data and PEM public key and tries to verify signature
 * @param  {Buffer} signature
 * @param  {Buffer} data
 * @param  {String} publicKey - PEM encoded public key
 * @return {Boolean}
 */
let verifySignature = (signature, data, publicKey) => {
  return crypto.createVerify('SHA256')
    .update(data)
    .verify(publicKey, signature)
}

/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
let randomBase64URLBuffer = (len) => {
  len = len || 32

  let buff = crypto.randomBytes(len)

  return base64url(buff)
}

/**
 * Generates makeCredentials request
 * @param  {String} username       - username
 * @param  {String} displayName    - user's personal display name
 * @param  {String} id             - user's base64url encoded id
 * @return {MakePublicKeyCredentialOptions} - server encoded make credentials request
 */
let generateServerCredentialsChallenge = (username, displayName, id, type) => {
  // TODO: STEP 2 Genarate Credential Challenge
  let authenticatorSelection = null
  if (type === 'cross-platform') {
    // TODO: STEP 3.1 add this for security key
    authenticatorSelection = {
      authenticatorAttachment: 'cross-platform',
      requireResidentKey: false
    }
  } else if (type === 'platform') {
    // TODO: STEP 3.2 Add this for finger print
    authenticatorSelection = {
      authenticatorAttachment: 'platform',
      requireResidentKey: false,
      userVerification: 'required'
    }
  }

  return {
    challenge: randomBase64URLBuffer(32),

    rp: {
      name: 'WebAuthn Demo'
    },

    user: {
      id: id,
      name: username,
      displayName: displayName
    },
    authenticatorSelection: authenticatorSelection,
    attestation: 'direct',
    pubKeyCredParams: [{
      type: 'public-key',
      alg: -7
    }]
  }
}

/**
 * Generates getAssertion request
 * @param  {Array} authenticators              - list of registered authenticators
 * @return {PublicKeyCredentialRequestOptions} - server encoded get assertion request
 */
let generateServerGetAssertion = (authenticators) => {
  let allowCredentials = []
  // TODO: STEP 19 Return allow credential ID
  for (let authr of authenticators) {
    allowCredentials.push({
      type: 'public-key',
      id: authr.credID,
      transports: ['usb', 'nfc', 'ble', 'internal']
    })
  }
  return {
    challenge: randomBase64URLBuffer(32),
    allowCredentials: allowCredentials
  }
}

/**
 * Returns SHA-256 digest of the given data.
 * @param  {Buffer} data - data to hash
 * @return {Buffer}      - the hash
 */
let hash = (data) => {
  return crypto.createHash('SHA256').update(data).digest()
}

/**
 * Verify creadential from client
 * @param  {Object} webAuthnResponse - Data from navigator.credentials.create
 */
let verifyAuthenticatorAttestationResponse = (webAuthnResponse) => {
  let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject)
  // TODO: STEP 11 Extract attestation Object
  let ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0]
  // TODO: STEP 12 Extract auth data
  let authrDataStruct = helpers.parseMakeCredAuthData(ctapMakeCredResp.authData)
  // TODO: STEP 13 Extract public key
  let publicKey = helpers.COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
  let response = { 'verified': false }
  console.log('---------------------- ctapMakeCredResp ---------------------')
  console.log(ctapMakeCredResp)
  console.log('---------------------- authrDataStruct ---------------------')
  console.log(authrDataStruct)
  console.log('---------------------- publicKey ---------------------')
  console.log(publicKey)
  // TODO: STEP 14 Verify attestation based on type of device
  if (ctapMakeCredResp.fmt === 'fido-u2f') {
    response.verified = verifyFidoU2fWebauthn.verifyFidoU2fAttestation(webAuthnResponse)
  } else if (ctapMakeCredResp.fmt === 'packed') {
    response.verified = verifyPackedWebauthn.verifyPackedAttestation(webAuthnResponse)
  } else if (ctapMakeCredResp.fmt === 'android-key') {
    response.verified = verifyAndroidKeyWebauthn.verifyPackedAttestation(webAuthnResponse)
  } else if (ctapMakeCredResp.fmt === 'android-safetynet') {
    response.verified = verifyAndroidSafetynetWebauthn.verifyPackedAttestation(webAuthnResponse)
  }

  if (response.verified) {
    // TODO: STEP 15 Create data for save to database
    response.authrInfo = {
      fmt: ctapMakeCredResp.fmt,
      publicKey: base64url.encode(publicKey),
      counter: authrDataStruct.counter,
      credID: base64url.encode(authrDataStruct.credID)
    }
  }

  return response
}

/**
 * Takes an array of registered authenticators and find one specified by credID
 * @param  {String} credID        - base64url encoded credential
 * @param  {Array} authenticators - list of authenticators
 * @return {Object}               - found authenticator
 */
let findAuthr = (credID, authenticators) => {
  for (let authr of authenticators) {
    if (authr.credID === credID) { return authr }
  }

  throw new Error(`Unknown authenticator with credID ${credID}!`)
}

/**
 * Parses AuthenticatorData from GetAssertion response
 * @param  {Buffer} buffer - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseGetAssertAuthData = (buffer) => {
  let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32)
  let flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1)
  let flags = flagsBuf[0]
  let counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4)
  let counter = counterBuf.readUInt32BE(0)

  return { rpIdHash, flagsBuf, flags, counter, counterBuf }
}
/**
 * @param  {Object} webAuthnResponse - Data from navigator.credentials.get
 * @param  {Object} authenticators - Credential from Database
 */
let verifyAuthenticatorAssertionResponse = (webAuthnResponse, authenticators) => {
  // TODO: STEP 24 Query public key base on user ID
  let authr = findAuthr(webAuthnResponse.id, authenticators)
  let authenticatorData = base64url.toBuffer(webAuthnResponse.response.authenticatorData)

  let response = { 'verified': false }
  // TODO: STEP 25 parse auth data
  let authrDataStruct = parseGetAssertAuthData(authenticatorData)

  if (!(authrDataStruct.flags & U2F_USER_PRESENTED)) { throw new Error('User was NOT presented durring authentication!') }
  // TODO: STEP 26 hash clientDataJSON with sha256
  let clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
  // TODO: STEP 27 create signature base by concat authenticatorData and clientDataHash
  let signatureBase = Buffer.concat([authenticatorData, clientDataHash])
  // TODO: STEP 28 format public key
  let publicKey = helpers.ASN1toPEM(base64url.toBuffer(authr.publicKey))
  // TODO: STEP 29 convert signature to buffer
  let signature = base64url.toBuffer(webAuthnResponse.response.signature)
  // TODO: STEP 30 verify signature
  response.verified = verifySignature(signature, signatureBase, publicKey)

  if (response.verified) {
    if (response.counter <= authr.counter) { throw new Error('Authr counter did not increase!') }

    authr.counter = authrDataStruct.counter
  }

  return response
}

module.exports = {
  randomBase64URLBuffer,
  generateServerCredentialsChallenge,
  generateServerGetAssertion,
  verifyAuthenticatorAttestationResponse,
  verifyAuthenticatorAssertionResponse
}
