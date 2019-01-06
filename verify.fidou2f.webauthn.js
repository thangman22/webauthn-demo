const base64url = require('base64url')
const cbor = require('cbor')
const crypto = require('crypto')

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
 * Returns SHA-256 digest of the given data.
 * @param  {Buffer} data - data to hash
 * @return {Buffer}      - the hash
 */
let hash = (data) => {
  return crypto.createHash('SHA256').update(data).digest()
}

/**
 * Parses authenticatorData buffer.
 * @param  {Buffer} buffer - authenticatorData buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseMakeCredAuthData = (buffer) => {
  let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32)
  let flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1)
  let flags = flagsBuf[0]
  let counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4)
  let counter = counterBuf.readUInt32BE(0)
  let aaguid = buffer.slice(0, 16); buffer = buffer.slice(16)
  let credIDLenBuf = buffer.slice(0, 2); buffer = buffer.slice(2)
  let credIDLen = credIDLenBuf.readUInt16BE(0)
  let credID = buffer.slice(0, credIDLen); buffer = buffer.slice(credIDLen)
  let COSEPublicKey = buffer

  return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey }
}

let COSEECDHAtoPKCS = (COSEPublicKey) => {
  /*
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

  let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0]
  let tag = Buffer.from([0x04])
  let x = coseStruct.get(-2)
  let y = coseStruct.get(-3)

  return Buffer.concat([tag, x, y])
}

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
let ASN1toPEM = (pkBuffer) => {
  if (!Buffer.isBuffer(pkBuffer)) { throw new Error('ASN1toPEM: pkBuffer must be Buffer.') }

  let type
  if (pkBuffer.length === 65 && pkBuffer[0] === 0x04) {
    /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */

    pkBuffer = Buffer.concat([
      new Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
      pkBuffer
    ])

    type = 'PUBLIC KEY'
  } else {
    type = 'CERTIFICATE'
  }

  let b64cert = pkBuffer.toString('base64')

  let PEMKey = ''
  for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
    let start = 64 * i

    PEMKey += b64cert.substr(start, 64) + '\n'
  }

  PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`

  return PEMKey
}

let verifyFidoU2fAttestation = (webAuthnResponse) => {
  let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject)
  let ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0]

  let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData)

  if (!(authrDataStruct.flags & U2F_USER_PRESENTED)) { throw new Error('User was NOT presented durring authentication!') }

  let clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
  let reservedByte = Buffer.from([0x00])
  let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
  let signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey])

  let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0])
  let signature = ctapMakeCredResp.attStmt.sig

  return verifySignature(signature, signatureBase, PEMCertificate)
}

module.exports = { verifyFidoU2fAttestation }
