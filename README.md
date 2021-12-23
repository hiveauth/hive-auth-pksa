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
    "token_timeout_days": number
    "accounts": [
        {
            "name": "string"
            "auths": [
                {
                    "token": string
                    "expire": number
                    "key": string
                    "app": string
                }
            ]
        },
        { ... }
    ]
}
```

* `pksa_name`: the PKSA nameencryption secret used to encrypt/decrypt the `auth_key` when an app send it with its `auth_req`. Should be defined only if the PKSA runs in "service mode"
* `auth_req_secret`: the PKSA encryption secret used to encrypt/decrypt the `auth_key` when an app send it with its `auth_req`. Should be defined only if the PKSA runs in "service mode"
* `auth_req_approve`: if set to true, the PKSA will automatically approve authentication requests and create new tokens for the managed accounts. It should be left to false for secury reasons.
* `auth_req_reject`: if set to true, the PKSA will automatically reply with an `auth_nack` to any incoming `auth_req`, preventing any other PKSA to approve them.
* `sign_req_reject`: if set to true, the PKSA will automatically reply with an `sign_nack` to any incoming `sign_req`, preventing any other PKSA to approve them.
* `challenge_req_reject`: if set to true, the PKSA will automatically reply with a `challenge_nack` to any incoming `challenge_req`, preventing any other PKSA to approve them.
* `token_timeout_days`: (optional) the number of days before an app token expires. The default value if not present is 1 day.
* `accounts`: an array of account objects for each account managed by the PKSA
    * `name`: Hive username
    * `auths`: an array of auth objects for each access token created
        * `token`: the access token (usually a uuid)
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
    "token_timeout_days": 1,
    "accounts": [
        {
            "name": "account1",
            "auths": [
                {
                    "token": "82b31850-00e0-40b4-a8a5-64a2ad8a43ff",
                    "expire": 1634590013188,
                    "key": "45e9e195-b5d1-47f4-bc74-ce1da747424e",
                    "app": "peakd.com"
                },
                {
                    "token": "0c0eeeca-88a5-48b0-ab93-d90320baa1a2",
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
                    "token": "82b31850-00e0-40b4-a8a5-64a2ad8a9876",
                    "expire": 1634590013188,
                    "key": "45e9e195-b5d1-47f4-bc74-ce1da7471a2e",
                    "app": "peakd.com"
                },
                {
                    "token": "0c0eeeca-88a5-48b0-ab93-d90320ba9b6f",
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