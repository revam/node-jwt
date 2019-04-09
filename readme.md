# jwt-manager

Server-side manager for active JSON Web Tokens (JWTs)

## Install

### Install from GitHub:

#### Spesific release:

**Note:** Replace `$VERSION` with the version number.

```sh
$ npm install --save https://github.com/revam/node-jwt-manager/releases/download/v$VERSION/package.tgz
```

### Install from git.lan:

Internet people can ignore this section.

#### Latest release:

```sh
$ npm install --save https://git.lan/mist@node/jwt-manager@latest/npm-pack.tgz
```

#### Spesific release:

**Note:** Replace `$VERSION` with the version number.

```sh
$ npm install --save https://git.lan/mist@node/jwt-manager@v$VERSION/npm-pack.tgz
```

## Usage

**Note:** `await` is not actually available in the global context, but let's
assume it is for the following example.

```js
import { JWTManager } from "@revam/jwt";

// Our example user
const user = {
  id: "00000000-0000-0000-0000-000000000000",
  name: "John Smith",
  username: "josm",
};

// Our id stack
let idCount = 0;

// Create a new manager instance, "find" and "generateID" are both mandatory.
const jm = new { JWTManager }({
  // Find subject (and optional custom fields) with arguments provided to
  // `{ JWTManager }.generate({args})`.
  find(...args) {
    console.log(args.join(" "));
    // Our (open) secret combination of arguments to find our example user.
    if (args.length === 3 && args[0] === "this" && args[1] === "is" && args[2] === "SPARTA") {
      return { sub: user.id, name: user.name };
    }
  },
  // Generate an unique identifier for token
  generateID: () => (++idCount).toString(),
  // Custom verification of content, e.g. verify subject or custom fields.
  verify(jwt) {
    return jwt.sub === user.id && jwt.name === "John Smith";
  },
});

// Return undefined if no subject could be found with given arguments.
let token = await jm.generate({ args: ["this", "is", "GREEK"]}); // `token` is `undefined`.

// From above we know if we provide the three arguments "this", "is", and
// "SPARTA" we get a signed token for our example user.
token = await jm.generate({ args: ["this", "is", "SPARTA"]}); // `token` is a valid jwt, for our manager at least.

// Verifies an existing signed token, and returns the decoded content if successfull.
let obj1 = await jm.verify(token); // `obj1` is an object holding the decoded fields and values of the token payload.

// Decodes token without verifying signature or content.
let obj2 = jm.decode(token);// `obj` is an object holding the decoded fields and values of the token payload.

// Invalidates either a stringified or decoded token.
let result = await jm.invalidate(token || obj1); // return true if token or obj is now invalid.

// Since we just invalidated the token above, the verification will fail, and
// the object below will be `undefined`.
let obj3 = await jm.verify(token); // `obj3` is `undefined`

```

## Documentation

Documentation is available online at
[GitHub Pages](https://revam.github.io/node-jwt-manager/), or locally at
[http://localhost:8080/](http://localhost:8080/) with the following command:

```sh
$ npm run-script docs
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
