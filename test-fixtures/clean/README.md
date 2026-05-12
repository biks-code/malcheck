# My Awesome Project

A simple utility library for string manipulation.

## Installation

```bash
npm install my-awesome-project
```

## Usage

```javascript
const { capitalize, slugify } = require('my-awesome-project');

console.log(capitalize('hello world')); // "Hello World"
console.log(slugify('Hello World'));     // "hello-world"
```

## API

### capitalize(str)

Capitalizes the first letter of each word.

### slugify(str)

Converts a string to a URL-friendly slug.

## License

MIT
