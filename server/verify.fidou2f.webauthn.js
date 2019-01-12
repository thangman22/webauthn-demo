const base64url = require('base64url')
const cbor = require('cbor')
const crypto = require('crypto')
const helpers = require('./helpers')

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

let verifyFidoU2fAttestation = (webAuthnResponse) => {
  let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject)
  let ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0]

  let authrDataStruct = helpers.parseMakeCredAuthData(ctapMakeCredResp.authData)

  if (!(authrDataStruct.flags & U2F_USER_PRESENTED)) { throw new Error('User was NOT presented durring authentication!') }

  let clientDataHash = helpers.hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
  let reservedByte = Buffer.from([0x00])
  let publicKey = helpers.COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
  let signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey])

  let PEMCertificate = helpers.ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0])
  let signature = ctapMakeCredResp.attStmt.sig

  return verifySignature(signature, signatureBase, PEMCertificate)
}

module.exports = { verifyFidoU2fAttestation }
