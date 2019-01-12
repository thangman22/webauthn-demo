const express = require('express')
const utils = require('./utils')
const config = require('../config.json')
const base64url = require('base64url')
const router = express.Router()
const database = require('./db')

router.post('/register', (request, response) => {
  if (!request.body || !request.body.username || !request.body.name || !request.body.type) {
    response.json({
      'status': 'failed',
      'message': 'Request field is missing'
    })

    return
  }

  let username = request.body.username
  let name = request.body.name
  let type = request.body.type
  if (database[username] && database[username].registered) {
    response.json({
      'status': 'failed',
      'message': `Username ${username} already exists`
    })

    return
  }

  database[username] = {
    'name': name,
    'registered': false,
    'id': utils.randomBase64URLBuffer(),
    'authenticators': []
  }

  let challengeMakeCred = utils.generateServerCredentialsChallenge(username, name, database[username].id, type)
  challengeMakeCred.status = 'ok'
  // TODO: STEP 4 Save challenge to Session or Cookie
  request.session.challenge = challengeMakeCred.challenge
  request.session.username = username

  response.json(challengeMakeCred)
})

router.post('/login', (request, response) => {
  if (!request.body || !request.body.username) {
    response.json({
      'status': 'failed',
      'message': 'Request missing username field!'
    })

    return
  }

  let username = request.body.username

  if (!database[username] || !database[username].registered) {
    response.json({
      'status': 'failed',
      'message': `User ${username} does not exist!`
    })

    return
  }
  // TODO: STEP 18 Genrate assertion
  let getAssertion = utils.generateServerGetAssertion(database[username].authenticators)
  getAssertion.status = 'ok'

  request.session.challenge = getAssertion.challenge
  request.session.username = username

  response.json(getAssertion)
})

router.post('/response', (request, response) => {
  if (!request.body || !request.body.id ||
    !request.body.rawId || !request.body.response ||
    !request.body.type || request.body.type !== 'public-key') {
    response.json({
      'status': 'failed',
      'message': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
    })

    return
  }

  let webauthnResp = request.body
  let clientData = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON))

  // TODO: STEP 8 Verify challenge is match with cookie
  if (clientData.challenge !== request.session.challenge) {
    response.json({
      'status': 'failed',
      'message': 'Challenges don\'t match!'
    })
  }

  // TODO: STEP 9 Verify origin is match
  if (clientData.origin !== config.origin) {
    response.json({
      'status': 'failed',
      'message': 'Origins don\'t match!'
    })
  }

  let result

  if (webauthnResp.response.attestationObject !== undefined) {
    // TODO: STEP 10 Verify attestation
    result = utils.verifyAuthenticatorAttestationResponse(webauthnResp)
    // TODO: STEP 16 Save data to database
    if (result.verified) {
      database[request.session.username].authenticators.push(result.authrInfo)
      database[request.session.username].registered = true
    }
  } else if (webauthnResp.response.authenticatorData !== undefined) {
    // TODO: STEP 23 Verify assertion
    result = utils.verifyAuthenticatorAssertionResponse(webauthnResp, database[request.session.username].authenticators)
  } else {
    response.json({
      'status': 'failed',
      'message': 'Can not determine type of response!'
    })
  }

  if (result.verified) {
    request.session.loggedIn = true
    response.json({ 'status': 'ok' })
  } else {
    response.json({
      'status': 'failed',
      'message': 'Can not authenticate signature!'
    })
  }
})

module.exports = router
