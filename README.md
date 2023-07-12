# Hive Authentication Service PKSA

This is an example on how to run a PKSA in service mode

### How to Use

- Clone this repository
- Make sure you have latest LTS or greater version of Node JS installed
- Go inside the cloned folder and type `npm install`
- Rename `storage.example.json` to `storage.json` and update it to fit your needs (see below).
- Rename `keys.example.json` to `keys.json` and update it to fit your needs (see below) 

### storage.json file

The `storage.json` file is where the PKSA will store its configuration, the accounts it manages and their access tokens.

**Structure**

```
{
    "pksa_name": string
    "auth_req_secret": string (optional)
    "auth_req_approve": boolean
    "auth_req_reject": boolean
    "sign_req_reject": boolean
    "challenge_req_reject": boolean
    "auth_timeout_days": number (optional)
    "accounts": [
        {
            "name": "string"
            "auths": [
                {
                    "expire": number
                    "key": string
                    "app": string
                },
                { ... }
            ]
        },
        { ... }
    ]
}
```

* `pksa_name`: the PKSA name
* `auth_req_secret`: the PKSA encryption secret used to encrypt/decrypt the `auth_key` when an app send it with its `auth_req`. Should be defined only if the PKSA runs in "service mode"
* `auth_req_approve`: if set to true, the PKSA will automatically approve authentication requests. It should be left to false for secury reasons unless you want to create a new approval.
* `auth_req_reject`: if set to true, the PKSA will automatically reply with an `auth_nack` to any incoming `auth_req`, preventing any other PKSA to approve them.
* `sign_req_reject`: if set to true, the PKSA will automatically reply with an `sign_nack` to any incoming `sign_req`, preventing any other PKSA to approve them.
* `challenge_req_reject`: if set to true, the PKSA will automatically reply with a `challenge_nack` to any incoming `challenge_req`, preventing any other PKSA to approve them.
* `auth_timeout_days`: (optional) the number of days before an authentication approval expires. The default value if not present is 1 day.
* `hive_api`: a string or an array of strings with Hive API node(s) url,
* `has_server`: the HAS server to connect to (ws://... or wss://...)
* `keys`: full path to file containing managed accounts private keys. Default to local file "keys.json" if not present
* `hideEncryptedData`: (optional) if set to true, the encrypted data will be replaced with "<...>" to reduce log size. The default value if not present is false

* `accounts`: an array of account objects for each account managed by the PKSA
    * `name`: Hive username
    * `auths`: an array of auth objects for each access token created (it will be automatically populated when the PKSA approves new authentication requests)
        * `expire`: UNIX time when the token expire
        * `key`: the symetric encryption key used to enrypt communication between the App and the PKSA, usually a uuid (encryption key should be unique per session)
        * `app`: any string that identify the app (example: "peakd.com")

**Example**

```
{
    "pksa_name": "MyPKSA",
    "auth_req_secret": "A.v3ry-$tr0nG/And>$3cUr3.$3Cr3t-K3Y",
    "auth_req_approve": false,
    "auth_req_reject": false,
    "sign_req_reject": false,
    "challenge_req_reject": false,
    "auth_timeout_days": 1,

	"hive_api": "https://api.hive.blog",
	"has_server": "ws://has.hiveauth.com",
    "keys": "./keys.json"
	"hideEncryptedData": true,

    "accounts": [
        {
            "name": "account1",
            "auths": [
                {
                    "expire": 1634590013188,
                    "key": "45e9e195-b5d1-47f4-bc74-ce1da747424e",
                    "app": "peakd.com"
                },
                {
                    "expire": 1634591331195,
                    "key": "ed880eee-f354-41a2-84bb-ef08f18c891a",
                    "app": "peakd-mobile"
                }
            ]
        },
        {
            "name": "account2",
            "auths": [
                {
                    "expire": 1634590013188,
                    "key": "45e9e195-b5d1-47f4-bc74-ce1da7471a2e",
                    "app": "peakd.com"
                },
                {
                    "expire": 1634591331195,
                    "key": "ed880eee-f354-41a2-84bb-ef08f18c8899",
                    "app": "splinterlands"
                }
            ]
        }
    ]
}
```

### keys.json file

The `keys.json` file is where the private keys of the Hive accounts managed by the PKSA are stored.

**Structure**

```
[
    { 
        "name": string,
        "posting": string,
        "active": string ,
        "memo": string
    },
    { ... }
]
```
* `name`: the hive account username
* `posting`: (optional) the account posting private key
* `active`: (optional) the account active private key
* `memo`: (optional) the account memo private key

At least one account key should be present to enable authentication.

**Example**

```
[
    {
        "name": "user1",		
        "posting": "5...",
        "active": "5..." 
    },
    {
        "name": "user2",
        "posting": "5...",
        "memo": "5..."
    },
    {
        "name": "user3",
        "posting": "5..."
    }
]
```

### Running as a service

To run the app continuously in background, you can use use [PM2](https://pm2.io/). 
Generate `ecosystem.config.js` file with `pm2 init` command.

When you are done start the PKSA with following command.

`pm2 start ecosystem.config.js --env production`

### Contributing

If you have any suggestions or want to report bugs, please create an issue.

### Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.