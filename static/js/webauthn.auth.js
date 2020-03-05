'use strict'

const getMakeCredentialsChallenge = async formBody => {
  const response = await window
    .fetch('/webauthn/register', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formBody)
    })
  const responseJson = await response.json()
  if (responseJson.status !== 'ok') {
    throw new Error(`Server responed with error. The message is: ${responseJson.message}`)
  }
  return responseJson
}

const sendWebAuthnResponse = async body => {
  const response = await window
    .fetch('/webauthn/response', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    })
  const responseJson = await response.json()
  if (responseJson.status !== 'ok') {
    throw new Error(`Server responed with error. The message is: ${responseJson.message}`)
  }
  return responseJson
}

/* Handle for register form submission */
document.getElementById('register').addEventListener('submit', function (event) {
  event.preventDefault()

  let username = this.username.value
  let name = this.username.value

  if (!username || !name) {
    window.alert('Name or username is missing!')
  }

  performCreateCreadential(username, name)
})

const performCreateCreadential = async (username, name) => {
  // TODO: STEP 1 request createCredentialObject from server
  try {
    const response = await getMakeCredentialsChallenge({ username, name })
    console.log('Options for creating crendential', response)
    // TODO: STEP 5 convert challenge & id to buffer and perform register
    let publicKey = window.preformatMakeCredReq(response)
    clearAlert()
    document.getElementById('touch-alert').style.display = 'block'
    const credential = await navigator.credentials.create({ publicKey })
    // TODO: STEP 6 convert response from buffer to json
    let makeCredResponse = window.publicKeyCredentialToJSON(credential)
    console.log('Credential', makeCredResponse)
    const responseRegister = await sendWebAuthnResponse(makeCredResponse)
    if (responseRegister.status === 'ok') {
      clearAlert()
      document.getElementById('register-success-alert').style.display =
        'block'
      console.log('Registration completed')
    } else {
      window.alert(`Server responed with error. The message is: ${responseRegister.message}`)
    }
  } catch (error) {
    return window.alert(error)
  }
}

let getGetAssertionChallenge = async formBody => {
  // TODO: STEP 17 Start login flow
  const response = await window
    .fetch('/webauthn/login', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formBody)
    })
  const responseJson = await response.json()
  if (responseJson.status !== 'ok') {
    throw new Error(`Server responed with error. The message is: ${responseJson.message}`)
  }
  return responseJson
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
    .then(response => {
      // TODO: STEP 20 perform get credential
      let publicKey = window.preformatGetAssertReq(response)
      clearAlert()
      document.getElementById('touch-alert').style.display = 'block'
      return navigator.credentials.get({ publicKey })
    })
    .then(response => {
      // TODO: STEP 21 convert response to json
      let getAssertionResponse = window.publicKeyCredentialToJSON(response)
      console.log('Assertion', getAssertionResponse)
      // TODO: STEP 22 send information to server
      return sendWebAuthnResponse(getAssertionResponse)
    })
    .then(response => {
      if (response.status === 'ok') {
        clearAlert()
        document.getElementById('login-success-alert').style.display = 'block'
        console.log('Login success')
      } else {
        window.alert(
          `Server responed with error. The message is: ${response.message}`
        )
      }
    })
    .catch(error => window.alert(error))
})
