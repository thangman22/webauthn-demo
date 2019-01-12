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
document.getElementById('register').addEventListener('submit', function (event) {
  event.preventDefault()

  let username = this.username.value
  let name = this.username.value
  let type = this.type.value

  if (!username || !name) {
    window.alert('Name or username is missing!')
    return
  }

  // TODO: STEP 1 request createCredentialObject from server
  getMakeCredentialsChallenge({ username, name, type })
    .then((response) => {
      console.log('Options for creating crendential', response)
      // TODO: STEP 5 convert challenge & id to buffer and perform register
      let publicKey = window.preformatMakeCredReq(response)
      clearAlert()
      document.getElementById('touch-alert').style.display = 'block'
      return navigator.credentials.create({ publicKey })
    })
    .then((response) => {
      // TODO: STEP 6 convert response from buffer to json
      let makeCredResponse = window.publicKeyCredentialToJSON(response)
      console.log('Credential', makeCredResponse)
      // TODO: STEP 7 Send to server
      return sendWebAuthnResponse(makeCredResponse)
    })
    .then((response) => {
      if (response.status === 'ok') {
        clearAlert()
        document.getElementById('register-success-alert').style.display = 'block'
        console.log('Registration completed')
      } else {
        window.alert(`Server responed with error. The message is: ${response.message}`)
      }
    })
    .catch((error) => window.alert(error))
})

let getGetAssertionChallenge = (formBody) => {
  // TODO: STEP 17 Start login flow
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

let clearAlert = () => {
  Array.from(document.getElementsByClassName('alert')).forEach(ele => {
    ele.style.display = 'none'
  })
}

/* Handle for login form submission */
document.getElementById('login').addEventListener('submit', function (event) {
  event.preventDefault()

  let username = this.username.value

  if (!username) {
    window.alert('Username is missing!')
    return
  }

  getGetAssertionChallenge({ username })
    .then((response) => {
      // TODO: STEP 20 perform get credential
      let publicKey = window.preformatGetAssertReq(response)
      clearAlert()
      document.getElementById('touch-alert').style.display = 'block'
      return navigator.credentials.get({ publicKey })
    })
    .then((response) => {
      // TODO: STEP 21 convert response to json
      let getAssertionResponse = window.publicKeyCredentialToJSON(response)
      console.log('Assertion', getAssertionResponse)
      // TODO: STEP 22 send information to server
      return sendWebAuthnResponse(getAssertionResponse)
    })
    .then((response) => {
      if (response.status === 'ok') {
        clearAlert()
        document.getElementById('login-success-alert').style.display = 'block'
        console.log('Login success')
      } else {
        window.alert(`Server responed with error. The message is: ${response.message}`)
      }
    })
    .catch((error) => window.alert(error))
})
