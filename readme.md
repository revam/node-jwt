# @revam/jwt

Server-side managing of JSON Web Tokens (JWTs)

## Install

### Install from GitHub:

#### Spesific release:

**Note:** Replace `$VERSION` with the version number.

```sh
$ npm install --save https://github.com/revam/node-jwt/releases/download/v$VERSION/package.tgz
```

### Install from git.lan:

Internet people can ignore this section.

#### Latest release:

```sh
$ npm install --save https://git.lan/mist@node/jwt@latest/npm-pack.tgz
```

#### Spesific release:

**Note:** Replace `$VERSION` with the version number.

```sh
$ npm install --save https://git.lan/mist@node/jwt@v$VERSION/npm-pack.tgz
```

## Usage

**Note:** The `await` keyword is not actually available in the global context,
but let's assume it is for the following example. For clearity-purposes is the
type of each variable provided, and the example written in typescript.

```typescript
import { JWT, JWTManager } from "@revam/jwt";

interface User {
  id: string
  name: string;
  username: string;
}

// Our example user
const user: User = {
  id: "00000000-0000-0000-0000-000000000000",
  name: "John Smith",
  username: "josm",
};

// Our id stack
let idCount: number = 0;

// Create a new manager instance, "find" and "generateID" are both mandatory.
const jtm: JWTManager = new JWTManager({
  // Find subject (and optional custom fields) with arguments provided to
  // `JWTManager.generate({args})`.
  find(...args: ["this", "is", "SPARTA"] | any[]): { sub: string; } & Pick<User, "name"> {
    console.log(args.join(" "));
    // Our (open) secret combination of arguments to find our example user.
    if (args.length === 3 && args[0] === "this" && args[1] === "is" && args[2] === "SPARTA") {
      return { sub: user.id, name: user.name };
    }
  },
  // Generate an unique identifier for a new token
  generateID: (): string => (++idCount).toString(),
  // Optional. Custom verification of content, e.g. verify subject or custom
  // fields.
  verify(jwt: JWT): boolean {
    return jwt.sub === user.id && jwt.name === "John Smith";
  },
});

let token: string | undefined;

// Return undefined if no subject could be found with given arguments.
token = await jtm.generate({ args: ["this", "is", "GREEK"]});

// From above we know if we provide the three arguments "this", "is", and
// "SPARTA" we get a signed token for our example user.
token = await jtm.generate({ args: ["this", "is", "SPARTA"]});

// Verifies an existing signed token, and returns the decoded content if successfull.
let obj1: JWT<User, "name"> = await jtm.verify(token);

// Decodes token without verifying signature or content.
let obj2: JWT<User, "name"> = jtm.decode(token);

// Invalidates either a stringified or decoded token.
let result1: true = await jtm.invalidate(obj1);

// We have already invalidated the token, so the following methods will return
// negative results.
let obj3: undefined = await jtm.verify(token);
let result2: false = await jtm.invalidate(token);

```

## Documentation

Documentation is available online at
[GitHub Pages](https://revam.github.io/node-jwt/), or locally at
[http://localhost:8080/](http://localhost:8080/) with the following command:

```sh
$ npm run-script serve:docs
```

## Typescript

This module includes a [TypeScript](https://www.typescriptlang.org/)
declaration file to enable auto complete in compatible editors and type
information for TypeScript projects. This module depends on the Node.js
types, so install `@types/node`:

```sh
npm install --save-dev @types/node
```

## Changelog and versioning

All notable changes to this project will be documented in [changelog.md](./changelog.md).

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## License

This project is licensed under the MIT license. See [license](./license) for the
full terms.
