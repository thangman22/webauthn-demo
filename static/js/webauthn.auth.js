'use strict'

let getMakeCredentialsChallenge = (formBody) => {
  return window.fetch('/webauthn/register', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(formBody)
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.status !== 'ok') { throw new Error(`Server responed with error. The message is: ${response.message}`) }

      return response
    })
}

let sendWebAuthnResponse = (body) => {
  return window.fetch('/webauthn/response', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.status !== 'ok') { throw new Error(`Server responed with error. The message is: ${response.message}`) }

      return response
    })
}

/* Handle for register form submission */
window.$('#register').submit(function (event) {
  event.preventDefault()

  let username = this.username.value
  let name = this.username.value
  let type = this.type.value

  if (!username || !name) {
    window.alert('Name or username is missing!')
    return
  }

  getMakeCredentialsChallenge({ username, name, type })
    .then((response) => {
      console.log('Options for creating crendential', response)
      let publicKey = window.preformatMakeCredReq(response)
      return navigator.credentials.create({ publicKey })
    })
    .then((response) => {
      let makeCredResponse = window.publicKeyCredentialToJSON(response)
      console.log('Credential', makeCredResponse)
      return sendWebAuthnResponse(makeCredResponse)
    })
    .then((response) => {
      if (response.status === 'ok') {
        console.log('Credential is in server')
      } else {
        window.alert(`Server responed with error. The message is: ${response.message}`)
      }
    })
    .catch((error) => window.alert(error))
})

let getGetAssertionChallenge = (formBody) => {
  return window.fetch('/webauthn/login', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(formBody)
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.status !== 'ok') { throw new Error(`Server responed with error. The message is: ${response.message}`) }

      return response
    })
}

/* Handle for login form submission */
window.$('#login').submit(function (event) {
  event.preventDefault()

  let username = this.username.value

  if (!username) {
    window.alert('Username is missing!')
    return
  }

  getGetAssertionChallenge({ username })
    .then((response) => {
      let publicKey = window.preformatGetAssertReq(response)
      return navigator.credentials.get({ publicKey })
    })
    .then((response) => {
      let getAssertionResponse = window.publicKeyCredentialToJSON(response)
      console.log(getAssertionResponse)
      return sendWebAuthnResponse(getAssertionResponse)
    })
    .then((response) => {
      if (response.status === 'ok') {
        console.log('Credential is saved')
      } else {
        window.alert(`Server responed with error. The message is: ${response.message}`)
      }
    })
    .catch((error) => window.alert(error))
})
