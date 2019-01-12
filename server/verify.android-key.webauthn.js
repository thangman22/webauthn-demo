const crypto = require('crypto')
const base64url = require('base64url')
const cbor = require('cbor')
const asn1 = require('@lapo/asn1js')
const jsrsasign = require('jsrsasign')

/* Android Keystore Root is not published anywhere.
 * This certificate was extracted from one of the attestations
 * The last certificate in x5c must match this certificate
 * This needs to be checked to ensure that malicious party wont generate fake attestations
 */
let androidkeystoreroot = 'MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw=='

let COSEKEYS = {
  'kty': 1,
  'alg': 3,
  'crv': -1,
  'x': -2,
  'y': -3,
  'n': -1,
  'e': -2
}

var hash = (alg, message) => {
  return crypto.createHash(alg).update(message).digest()
}

var base64ToPem = (b64cert) => {
  let pemcert = ''
  for (let i = 0; i < b64cert.length; i += 64) { pemcert += b64cert.slice(i, i + 64) + '\n' }

  return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----'
}

var findOID = (asn1object, oid) => {
  if (!asn1object.sub) { return }

  for (let sub of asn1object.sub) {
    if (sub.typeName() !== 'OBJECT_IDENTIFIER' || sub.content() !== oid) {
      let result = findOID(sub, oid)

      if (result) { return result }
    } else {
      return asn1object
    }
  }
}

let asn1ObjectToJSON = (asn1object) => {
  let JASN1 = {
    'type': asn1object.typeName()
  }

  if (!asn1object.sub) {
    if (asn1object.typeName() === 'BIT_STRING' || asn1object.typeName() === 'OCTET_STRING') { JASN1.data = asn1object.stream.enc.slice(asn1object.posContent(), asn1object.posEnd()) } else { JASN1.data = asn1object.content() }

    return JASN1
  }

  JASN1.data = []
  for (let sub of asn1object.sub) {
    JASN1.data.push(asn1ObjectToJSON(sub))
  }

  return JASN1
}

let containsASN1Tag = (seq, tag) => {
  for (let member of seq) {
    if (member.type === '[' + tag + ']') { return true }
  }

  return false
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

var getCertificateSubject = (certificate) => {
  let subjectCert = new jsrsasign.X509()
  subjectCert.readCertPEM(certificate)

  let subjectString = subjectCert.getSubjectString()
  let subjectFields = subjectString.slice(1).split('/')

  let fields = {}
  for (let field of subjectFields) {
    let kv = field.split('=')
    fields[kv[0]] = kv[1]
  }

  return fields
}

var validateCertificatePath = (certificates) => {
  if ((new Set(certificates)).size !== certificates.length) { throw new Error('Failed to validate certificates path! Dublicate certificates detected!') }

  for (let i = 0; i < certificates.length; i++) {
    let subjectPem = certificates[i]
    let subjectCert = new jsrsasign.X509()
    subjectCert.readCertPEM(subjectPem)

    let issuerPem = ''
    if (i + 1 >= certificates.length) { issuerPem = subjectPem } else { issuerPem = certificates[i + 1] }

    let issuerCert = new jsrsasign.X509()
    issuerCert.readCertPEM(issuerPem)

    if (subjectCert.getIssuerString() !== issuerCert.getSubjectString()) { throw new Error('Failed to validate certificate path! Issuers dont match!') }

    let subjectCertStruct = jsrsasign.ASN1HEX.getTLVbyList(subjectCert.hex, 0, [0])
    let algorithm = subjectCert.getSignatureAlgorithmField()
    let signatureHex = subjectCert.getSignatureValueHex()

    let Signature = new jsrsasign.crypto.Signature({ alg: algorithm })
    Signature.init(issuerPem)
    Signature.updateHex(subjectCertStruct)

    if (!Signature.verify(signatureHex)) { throw new Error('Failed to validate certificate path!') }
  }

  return true
}

let verifyPackedAttestation = (webAuthnResponse) => {
  let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject)
  let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0]

  let authDataStruct = parseAuthData(attestationStruct.authData)
  let clientDataHashBuf = hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON))

  /* ----- VERIFY SIGNATURE ----- */
  let signatureBaseBuffer = Buffer.concat([attestationStruct.authData, clientDataHashBuf])

  let signatureBuffer = attestationStruct.attStmt.sig
  let signatureIsValid = false

  let leafCert = base64ToPem(attestationStruct.attStmt.x5c[0].toString('base64'))

  signatureIsValid = crypto.createVerify('sha256')
    .update(signatureBaseBuffer)
    .verify(leafCert, signatureBuffer)

  if (!signatureIsValid) { throw new Error('Failed to verify the signature!') }

  let attestationRootCertificateBuffer = attestationStruct.attStmt.x5c[attestationStruct.attStmt.x5c.length - 1]
  // TODO: STEP 31 Comment this line below if you allow rooted device for login
  if (attestationRootCertificateBuffer.toString('base64') !== androidkeystoreroot) { throw new Error('Attestation root is not invalid!') }

  let certPath = attestationStruct.attStmt.x5c.map((cert) => {
    cert = cert.toString('base64')

    let pemcert = ''
    for (let i = 0; i < cert.length; i += 64) { pemcert += cert.slice(i, i + 64) + '\n' }

    return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----'
  })

  validateCertificatePath(certPath)
  /* ----- VERIFY SIGNATURE ENDS ----- */

  let certASN1 = asn1.decode(attestationStruct.attStmt.x5c[0])

  /* ----- VERIFY PUBLIC KEY MATCHING ----- */
  let certJSON = asn1ObjectToJSON(certASN1)
  let certTBS = certJSON.data[0]
  let certPubKey = certTBS.data[6]
  let certPubKeyBuff = certPubKey.data[1].data

  /* CHECK PUBKEY */
  let coseKey = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0]

  /* ANSI ECC KEY is 0x04 with X and Y coefficients. But certs have it padded with 0x00 so for simplicity it easier to do it that way */
  let ansiKey = Buffer.concat([Buffer([0x00, 0x04]), coseKey.get(COSEKEYS.x), coseKey.get(COSEKEYS.y)])

  if (ansiKey.toString('hex') !== certPubKeyBuff.toString('hex')) { throw new Error('Certificate public key does not match public key in authData') }
  /* ----- VERIFY PUBLIC KEY MATCHING ENDS ----- */

  /* ----- VERIFY CERTIFICATE REQUIREMENTS ----- */
  let AttestationExtension = findOID(certASN1, '1.3.6.1.4.1.11129.2.1.17')
  let AttestationExtensionJSON = asn1ObjectToJSON(AttestationExtension)

  let attestationChallenge = AttestationExtensionJSON.data[1].data[0].data[4].data

  if (attestationChallenge.toString('hex') !== clientDataHashBuf.toString('hex')) { throw new Error('Certificate attestation challenge is not set to the clientData hash!') }

  let softwareEnforcedAuthz = AttestationExtensionJSON.data[1].data[0].data[6].data
  let teeEnforcedAuthz = AttestationExtensionJSON.data[1].data[0].data[7].data

  if (containsASN1Tag(softwareEnforcedAuthz, 600) || containsASN1Tag(teeEnforcedAuthz, 600)) { throw new Error('TEE or Software autherisation list contains "allApplication" flag, which means that credential is not bound to the RP!') }
  /* ----- VERIFY CERTIFICATE REQUIREMENTS ENDS ----- */

  return true
}

module.exports = { verifyPackedAttestation }
