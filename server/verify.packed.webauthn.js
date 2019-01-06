const crypto = require('crypto')
const base64url = require('base64url')
const cbor = require('cbor')
const jsrsasign = require('jsrsasign')
const elliptic = require('elliptic')
const nodersa = require('node-rsa')
const helpers = require('./helpers')

let COSEKEYS = {
  'kty': 1,
  'alg': 3,
  'crv': -1,
  'x': -2,
  'y': -3,
  'n': -1,
  'e': -2
}

let COSEKTY = {
  'OKP': 1,
  'EC2': 2,
  'RSA': 3
}

let COSERSASCHEME = {
  '-3': 'pss-sha256',
  '-39': 'pss-sha512',
  '-38': 'pss-sha384',
  '-262': 'pkcs1-sha1',
  '-257': 'pkcs1-sha256',
  '-258': 'pkcs1-sha384',
  '-259': 'pkcs1-sha512'
}

var COSECRV = {
  '1': 'p256',
  '2': 'p384',
  '3': 'p521'
}

var COSEALGHASH = {
  '-257': 'sha256',
  '-258': 'sha384',
  '-259': 'sha512',
  '-262': 'sha1',
  '-39': 'sha512',
  '-38': 'sha384',
  '-37': 'sha256',
  '-260': 'sha256',
  '-261': 'sha512',
  '-7': 'sha256',
  '-36': 'sha384'
}

let base64ToPem = (b64cert) => {
  let pemcert = ''
  for (let i = 0; i < b64cert.length; i += 64) { pemcert += b64cert.slice(i, i + 64) + '\n' }

  return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----'
}

var getCertificateInfo = (certificate) => {
  let subjectCert = new jsrsasign.X509()
  subjectCert.readCertPEM(certificate)

  let subjectString = subjectCert.getSubjectString()
  let subjectParts = subjectString.slice(1).split('/')

  let subject = {}
  for (let field of subjectParts) {
    let kv = field.split('=')
    subject[kv[0]] = kv[1]
  }

  let version = subjectCert.version
  let basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA

  return {
    subject, version, basicConstraintsCA
  }
}

var parseAuthData = (buffer) => {
  let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32)
  let flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1)
  let flagsInt = flagsBuf[0]
  let flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
    flagsInt
  }

  let counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4)
  let counter = counterBuf.readUInt32BE(0)

  let aaguid
  let credID
  let COSEPublicKey

  if (flags.at) {
    aaguid = buffer.slice(0, 16); buffer = buffer.slice(16)
    let credIDLenBuf = buffer.slice(0, 2); buffer = buffer.slice(2)
    let credIDLen = credIDLenBuf.readUInt16BE(0)
    credID = buffer.slice(0, credIDLen); buffer = buffer.slice(credIDLen)
    COSEPublicKey = buffer
  }

  return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey }
}

let verifyPackedAttestation = (webAuthnResponse) => {
  let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject)
  let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0]

  let authDataStruct = parseAuthData(attestationStruct.authData)

  let clientDataHashBuf = helpers.hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
  let signatureBaseBuffer = Buffer.concat([attestationStruct.authData, clientDataHashBuf])

  let signatureBuffer = attestationStruct.attStmt.sig
  let signatureIsValid = false

  if (attestationStruct.attStmt.x5c) {
    /* ----- Verify FULL attestation ----- */
    let leafCert = base64ToPem(attestationStruct.attStmt.x5c[0].toString('base64'))
    let certInfo = getCertificateInfo(leafCert)

    if (certInfo.subject.OU !== 'Authenticator Attestation') { throw new Error('Batch certificate OU MUST be set strictly to "Authenticator Attestation"!') }

    if (!certInfo.subject.CN) { throw new Error('Batch certificate CN MUST no be empty!') }

    if (!certInfo.subject.O) { throw new Error('Batch certificate CN MUST no be empty!') }

    if (!certInfo.subject.C || certInfo.subject.C.length !== 2) { throw new Error('Batch certificate C MUST be set to two character ISO 3166 code!') }

    if (certInfo.basicConstraintsCA) { throw new Error('Batch certificate basic constraints CA MUST be false!') }

    if (certInfo.version !== 3) { throw new Error('Batch certificate version MUST be 3(ASN1 2)!') }

    signatureIsValid = crypto.createVerify('sha256')
      .update(signatureBaseBuffer)
      .verify(leafCert, signatureBuffer)
    /* ----- Verify FULL attestation ENDS ----- */
  } else if (attestationStruct.attStmt.ecdaaKeyId) {
    throw new Error('ECDAA IS NOT SUPPORTED YET!')
  } else {
    /* ----- Verify SURROGATE attestation ----- */
    let pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0]
    if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
      let x = pubKeyCose.get(COSEKEYS.x)
      let y = pubKeyCose.get(COSEKEYS.y)

      let ansiKey = Buffer.concat([Buffer.from([0x04]), x, y])

      let signatureBaseHash = helpers.hash(COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)], signatureBaseBuffer)

      let ec = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)])
      let key = ec.keyFromPublic(ansiKey)

      signatureIsValid = key.verify(signatureBaseHash, signatureBuffer)
    } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
      let key = new NodeRSA(COSERSASCHEME[COSEKEYS.alg])
      key.importKey({
        n: pubKeyCose.get(COSEKEYS.n),
        e: 65537
      }, 'components-public')

      signatureIsValid = key.verify(signatureBaseBuffer, signatureBuffer)
    } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
      let x = pubKeyCose.get(COSEKEYS.x)
      let signatureBaseHash = helpers.hash(COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)], signatureBaseBuffer)

      let key = new elliptic.eddsa('ed25519')
      key.keyFromPublic(x)

      signatureIsValid = key.verify(signatureBaseHash, signatureBuffer)
    }
    /* ----- Verify SURROGATE attestation ENDS ----- */
  }

  if (!signatureIsValid) { throw new Error('Failed to verify the signature!') }

  return true
}

module.exports = { verifyPackedAttestation }
