"use strict";

const assert = require("assert")
const fs = require('fs')
const { v4: uuidv4 } = require('uuid')
const CryptoJS = require('crypto-js')
const WebSocket = require("ws")
const hivejs = require('@hiveio/hive-js')
const ecc = require("@hiveio/hive-js/lib/auth/ecc");

const { Client, PrivateKey, Tansaction } = require('@hiveio/dhive');
const { TIMEOUT } = require("dns");
const hiveAPI = "https://api.hive.blog"
const hiveClient = new Client(hiveAPI)

const KEY_TYPES = ["posting","active","memo"]

const HAS_SERVER = "wss://hive-auth.arcange.eu"
const HAS_PROTOCOL = 0.8            // supported HAS protocol version
const PING_RATE = 60 * 1000 			  // 1 minute
const PING_TIMEOUT = 5 * PING_RATE  // 5 minutes

let wsClient = undefined
let wsHeartbeat = undefined
let hasProtocol = undefined

// NOTE: PKSA in service mode - Use local file as pksa storage
const pksaStorage = "storage.json"
// NOTE: PKSA in service mode - Use local file as keys storage
const keysStorage = "../../hive-keys.json"

const keys = JSON.parse(fs.readFileSync(keysStorage))
function getPrivateKey(name, type) {
  const account = keys.find(o => o.name==name)
  switch(type) {
    case "posting":
      return account.posting
    case "active":
      return account.active
    case "memo":
      return account.memo
    default:
      throw new Error(`invalid key type ${type}`)
  }
}

function datetoISO(date) {
  return date.toISOString().replace(/T|Z/g," ")
}

function log(message) {
  console.log(`${datetoISO(new Date())} - ${message}`)
}

function logerror(message) {
  console.error(`${datetoISO(new Date())} - ${message}`)
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function HASSend(message) {
  log(`[SEND] ${message}`)
  wsClient.send(message)
}

function checkUsername(name) {
  const err = `Invalid account name "${name}"`
  assert(name, `${err} (undefined)`)
  assert(name[0], `${err} (empty)`)
  assert(name==name.trim(), `${err} (spaces)`)
  assert(name==name.toLowerCase(), `${err} (case)`)
}

async function processMessage(message) {
  try {
    const payload = typeof(message)=="string" ? JSON.parse(message) : message
    if(!payload.cmd || !typeof(payload.cmd)=="string") {
      throw new Error(`invalid payload (cmd)`)
    }
    if(payload.uuid) {
      // validate APP request forwarded by HAS
      assert(payload.uuid && typeof(payload.uuid)=="string", `invalid payload (uuid)`)
      assert(payload.expire && typeof(payload.expire)=="number", `invalid payload (expire)`)
      assert(payload.account && typeof(payload.account)=="string", `invalid payload (account)`)
      assert(Date.now() < payload.expire, `request expired - now:${Date.now()} > expire:${payload.expire}}`)
    }
    switch(payload.cmd) {
      // Process HAS <-> PKSA protocol
      case "connected":
        // connection confirmation from the HAS
        hasProtocol = payload.protocol || 0
        return
      case "error":
        // error from the HAS
        return
      case "register_ack":
        // registration confirmation from the HAS
        return 
      case "key_ack":
        // server public key received
        const key_server = payload.key
        if(key_server) {
          try {
            const storage = JSON.parse(fs.readFileSync(pksaStorage))
            const request = {
              cmd: "register_req",
              app: storage.pksa_name,
              accounts: []
            }
            const accounts = storage.accounts
            for(const account of accounts) {
              checkUsername(account.name,true)
              const key_type = "posting"
              // retrieve account private key from PKSA storage
              const key_private = getPrivateKey(account.name, key_type)
              if(!key_private) throw new Error(`Private ${key_type} key missing for ${account.name}`)
              const challenge = hivejs.memo.encode(key_private,key_server,'#'+Date.now())
              request.accounts.push({name:account.name, key_type:key_type, challenge:challenge})
            }
            // Register accounts on HAS server
            HASSend(JSON.stringify(request))
          } catch(e) {
            logerror(e.message)
          }
        }
        break

      // Process App requests relayed by HAS
      case "auth_req":
        // Authentications request
        // Payload structure:
        // { 
        //   cmd: "auth_req" 
        //   account: string
        //   data: {
        //       token: string = undefined
        //       app: {
        //           name: string
        //           description: string = undefined
        //           icon: string = undefined
        //       }
        //       challenge: { = undefined
        //           key_type: string
        //           challenge: string
        //       }
        //   }
        // }
        //
        // NOTE:    PKSA may not process "auth_req" from the HAS except when it runs in "service" mode
        //          It the PKSA wants to display info from the app data, it must wait for "auth_req" before displaying information to the user and sending "auth_ack" or "auth_nack" back to the HAS
        //          Processing "auth_req" allows a "service" APP to retieve a token/expiration and optionally communication encryption key (auth_key)
        //          If the app send the auth_key online with the auth_req payload, it must be encrypted with an encryption secret pre-shared between the app and the PKSA.
        //          This prevents the HAS host being able to decrypt communication between an App and the PKSA!

        assert(payload.account && typeof(payload.account)=="string", `invalid payload (account)`)
        assert(payload.data && typeof(payload.data)=="string", `invalid payload (data)`)
        // Reload data from storage
        const dataStorage = JSON.parse(fs.readFileSync(pksaStorage))
        let auth_key = undefined
        // If the PKSA run in "service mode " or for debug purpose, the APP can pass the encryption key to the PKSA with the auth_req payload
        if(payload.auth_key && dataStorage.auth_req_secret) {
          // Decrypt the provided auth_key using the pre-shared PKSA secret
          auth_key = CryptoJS.AES.decrypt(payload.auth_key,dataStorage.auth_req_secret).toString(CryptoJS.enc.Utf8)   
        }
        if(auth_key){
          try {
            // Check if the account is managed by the PKSA
            const account = dataStorage.accounts.find(o => o.name==payload.account)
            // Process payload only if the PKSA manage the account else ignore message
            if(account) {
              // NOTE: A PKSA with a UI should ask for user approval here
              //       If the PKSA runs in "service" mode,
              //       - set approve to true if you need to initialise your APP token
              //       - set approve to false when your APP already has a valid token
              //       Alternatively, you can initialise from your storage file.
              let approve = dataStorage.auth_req_approve || false
              // Prepare reply
              const auth_ack_data = {}
              // NOTE: The default expiration time for a token is 24 hours - It can be set to a longer duration for "service" APPS
              const timeout = (dataStorage.token_timeout_days || 1) * 24 * 60 * 60 * 1000
              // Create authentication challenge
              // Decrypt data received with off-band app encryption key
              const auth_req_data = JSON.parse(CryptoJS.AES.decrypt(payload.data,auth_key).toString(CryptoJS.enc.Utf8))
              // Check if we received a token and if it's still valid
              const validToken = payload.token && account.auths.find(o => o.token==payload.token && o.expire > Date.now())
              if(validToken) {
                // Token is valid, reuse it and approve auth_req
                approve = true
                auth_ack_data.token = validToken.token
                auth_ack_data.expire = validToken.expire
              } else {
                // create a new token
                auth_ack_data.token =  uuidv4(),
                auth_ack_data.expire = Date.now() + timeout
              }
              // Check if the app also requires the PKSA to sign a challenge
              if(auth_req_data.challenge) {
                const challenge_data = auth_req_data.challenge
                assert(challenge_data.key_type && typeof(challenge_data.key_type)=="string" && KEY_TYPES.includes(challenge_data.key_type), `invalid payload (challenge_data.key_type)`)
                assert(challenge_data.challenge && typeof(challenge_data.challenge)=="string", `invalid payload (challenge_data.challenge)`)
                // Check if the PKSA stores the requested private key
                const key_private = getPrivateKey(payload.account,challenge_data.key_type)
                if(key_private)  {
                  const sigHex = ecc.Signature.signBuffer(challenge_data.challenge,key_private).toHex()
                  const pubKey = ecc.PrivateKey.fromWif(key_private).toPublic().toString()
                  auth_ack_data.challenge = { pubkey:pubKey, challenge:sigHex }
                } else {
                  // Else case should be managed with caution to avoid malicious actor sniffing keys availability
                  approve = false
                }
              }
              if(approve) {
                // Encrypt the returned data
                const data = CryptoJS.AES.encrypt(JSON.stringify(auth_ack_data),auth_key).toString()
                HASSend(JSON.stringify({cmd:"auth_ack", uuid:payload.uuid, data:data}))
                if(!validToken) {
                  // Add new token into storage
                  account.auths.push({
                      token:auth_ack_data.token,
                      expire:auth_ack_data.expire,
                      key:auth_key,
                      app:auth_req_data.app.name,
                      ts_create:datetoISO(new Date()),
                      ts_expire:datetoISO(new Date(auth_ack_data.expire)) })
                } else {
                  validToken.ts_lastused = datetoISO(new Date())
                }
              } else {
                if(dataStorage.auth_req_reject) {
                  // PKSA does not allow another PKSA to approve auth_req
                  const data = CryptoJS.AES.encrypt(payload.uuid,auth_key).toString()
                  HASSend(JSON.stringify({cmd:"auth_nack", uuid:payload.uuid, data:data}))
                }
              }
              // clean storage from expired tokens
              account.auths = account.auths.filter(o => o.expire > Date.now()) 
              // Update local storage
              fs.writeFileSync(pksaStorage,JSON.stringify(dataStorage, null, '\t'))
            }
          } catch(e) {
            logerror(e.message)
            HASSend(JSON.stringify({cmd:"auth_err", uuid:payload.uuid, error:"Failed to process authentication request"}))
          }
        }
        break
      case "sign_req": {
        // Transaction request
        // Payload structure:
        // { 
        //   cmd: "auth_req" 
        //   account: string
        //   token: string
        //   data: {
        //    key_type: string
        //    ops: string
        //    broadcast: boolean
        //   }
        // }
        assert(payload.account && typeof(payload.account)=="string","Invalid payload (account)")
        assert(payload.token && typeof(payload.token)=="string","Invalid payload (token)")
        assert(payload.data && typeof(payload.data)=="string", "invalid payload (data)")

        const dataStorage = JSON.parse(fs.readFileSync(pksaStorage))
        // Check if the account is managed by the PKSA
        const account = dataStorage.accounts.find(o => o.name==payload.account)
        // Process payload only if the PKSA manage the account else ignore message
        if(account) {
          // Check if the PKSA stores that token and it hasn't expired
          const auth = account.auths.find(o => o.token==payload.token && o.expire > Date.now())
          if(auth) {
            try {
              // Decrypt the sign_data to sign with the encryption key associated to the token.
              const sign_data = JSON.parse(CryptoJS.AES.decrypt(payload.data, auth.key).toString(CryptoJS.enc.Utf8))
              assert(sign_data.key_type && typeof(sign_data.key_type)=="string" && KEY_TYPES.includes(sign_data.key_type), "invalid data (key_type)")
              assert(sign_data.ops && sign_data.ops.length >0, "invalid data (ops)")
              assert(sign_data.broadcast!=undefined, "invalid data (broadcast)")

              const key_private = getPrivateKey(payload.account, sign_data.key_type)
              let approve = false
              // WARNING: A PKSA running in service mode should NOT allow operations requiring the active key
              //          Bypass the following test at your own risk.
              if(sign_data.key_type!="active") {
                // Check if the PKSA stores the requested private key
                if(key_private) {
                  // NOTE: A PKSA with a UI should ask for user approval here
                  approve = true
                }
              }
              if(approve) {
                if(sign_data.broadcast) {
                  const res = await hiveClient.broadcast.sendOperations(sign_data.ops, PrivateKey.from(key_private))
                  HASSend(JSON.stringify({cmd:"sign_ack", uuid:payload.uuid, data:res.id, broadcast:payload.broadcast}))
                } else {
                  throw new Error("Transaction signing not enabled")
                  // To enable transaction signing, comment the above line uncomment the following code.
                  //
                  // const tx = new Transaction
                  // tx.ops = ops
                  // const signed_tx = await hiveClient.broadcast.sign(tx, PrivateKey.from(key_private))
                  // HASSend(JSON.stringify({cmd:"sign_ack", uuid:uuid, broadcast:payload.broadcast, data:signed_tx}))
                }
              } else {
                if(dataStorage.sign_req_reject) {
                  // PKSA does not allow another PKSA to approve sign_req
                  const data = CryptoJS.AES.encrypt(payload.uuid,auth_key).toString()
                  HASSend(JSON.stringify({cmd:"sign_nack", uuid:payload.uuid, data:data}))
                }
              }
            } catch(e) {
              // Encrypt error message before sending it to the APP via the HAS
              const ee = CryptoJS.AES.encrypt(e.message,auth.key).toString()
              HASSend(JSON.stringify({cmd:"sign_err", uuid:payload.uuid, error:ee}))
            }
          }
        }
        break
      }
      case "challenge_req": {
        // Challenge request
        // Payload structure:
        // { 
        //   cmd: "challenge_req"
        //   account: string
        //   token: string
        //   data: {
        //       key_type: string
        //       challenge: string
        //   }
        // }
        assert(payload.account && typeof(payload.account)=="string","Invalid payload (account)")
        assert(payload.token && typeof(payload.token)=="string","Invalid payload (token)")
        assert(payload.data && typeof(payload.data)=="string", "invalid payload (data)")

        const dataStorage = JSON.parse(fs.readFileSync(pksaStorage))
        // Check if the account is managed by the PKSA
        const account = dataStorage.accounts.find(o => o.name==payload.account)
        // Process payload only if the PKSA manage the account else ignore message
        if(account) {
          // Check if the PKSA stores that token and it hasn't expired
          const auth = account.auths.find(o => o.token==payload.token && o.expire > Date.now())
          if(auth) {
            try {
              // Decrypt the challenge_data to sign with the encryption key associated to the token.
              const challenge_data = JSON.parse(CryptoJS.AES.decrypt(payload.data, auth.key).toString(CryptoJS.enc.Utf8))
              assert(challenge_data.key_type && ["posting","active","memo"].includes(challenge_data.key_type), "invalid data (key_type)")
              assert(challenge_data.challenge && typeof(challenge_data.challenge)=='string', "invalid data (challenge)")

              let approve = false
              // Check if the PKSA stores the requested private key
              const key_private = getPrivateKey(payload.account, challenge_data.key_type)
              if(key_private) {
                // NOTE: A PKSA with a UI should ask for user approval here
                approve = true
              }
              if(approve) {
                  const sigHex = ecc.Signature.signBuffer(challenge_data.challenge,key_private).toHex()
                  const pubKey = ecc.PrivateKey.fromWif(key_private).toPublic().toString()
                  const challenge_ack_data = { pubkey:pubKey, challenge:sigHex }
                  // Encrypt the returned data
                  const data = CryptoJS.AES.encrypt(JSON.stringify(challenge_ack_data),auth.key).toString()
                  HASSend(JSON.stringify({cmd:"challenge_ack", uuid:payload.uuid, data:data}))
              } else {
                if(dataStorage.challenge_req_reject) {
                  const data = CryptoJS.AES.encrypt(payload.uuid,auth_key).toString()
                  HASSend(JSON.stringify({cmd:"challenge_nack", uuid:payload.uuid, data:data}))
                }
              }
            } catch(e) {
              // Encrypt error message before sending it to the APP via the HAS
              const ee = CryptoJS.AES.encrypt(e.message,auth.key).toString()
              HASSend(JSON.stringify({cmd:"challenge_err", uuid:payload.uuid, error:ee}))
            }
          }
        }
        break
      }
      default:
          throw new Error("Invalid payload (unknown cmd)")
    }
  } catch(e) {
    HASSend(JSON.stringify({cmd:"error", error:e.message}))
  }
}

// HAS client
function startWebsocket() {
  log(`PKSA started - protocol: ${HAS_PROTOCOL} `)
  //const wsClient = new WebSocket("ws://localhost:3000/")
  wsClient = new WebSocket(HAS_SERVER)

  //when a websocket connection with the HAS is established
  wsClient.onopen = async function(e) {
    log("HAS connection established")
    // Wait for HAS protocol info
    while(hasProtocol==undefined) {
      await sleep(250)
    }
    // Check HAS protocol version
    if(hasProtocol && HAS_PROTOCOL < hasProtocol) {
      logerror(`Unsupported HAS protocol - PKSA:${HAS_PROTOCOL} <-> HAS:${hasProtocol}`)
      // Stop PKSA
      wsClient.close()
    } else {
    // Request key for registration process
    HASSend(JSON.stringify({cmd:"key_req"}))
    }
  }

  wsClient.onmessage = async function(event) {
    log(`[RECV] ${event.data}`)
    processMessage(event.data)
  }

  wsClient.onclose = async function(event) {
    // connection closed, discard the old websocket
    wsClient = undefined
    if (event.wasClean) {
      log("HAS Connection closed")
    } else {
      // e.g. server process killed or network down
      log('HAS Connection died')
      // Wait 1 second before trying to reconnect
      await sleep(1000)
      // restart a new websocket
      startWebsocket()
    }
  }

  wsClient.onerror = function(error) {
    log(`[error] ${error.message}`)
  }

  wsClient.on("pong", () => {
    // HAS server is alive
    wsHeartbeat = Date.now()
  })
}

function heartbeat() {
  if(wsHeartbeat && wsHeartbeat + PING_TIMEOUT < Date.now()) {
    // HAS server no more responding - try to reconnect
    log("HAS Connection lost")
    wsClient = undefined
    startWebsocket()
  } else {
    if(wsClient) {
      // Ping HAS server
      wsClient.ping()
    }
  }
}

// Start PKSA
startWebsocket()
// Schedule HAS connection check
const interval = setInterval(heartbeat,PING_RATE)
