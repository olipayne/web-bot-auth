const generateHTML = (status?: boolean) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>HTTP Message Signatures</title>
  <style>* {
  margin: 0;
  padding: 0;
  border: none;
}

html { font-size: 62.5%; }

body {
  margin: 0;
  font-family: open sans, HelveticaNeue, Helvetica Neue, Helvetica, Arial, sans-serif;
  font-size: 1.5em;
  font-weight: 400;
  line-height: 1.6;
  color: #222;
}

h1 {
  font-family: Montserrat, helvetica, arial, sans-serif;
  font-size: 6rem;
  font-weight: 700;
  line-height: 6.5rem;
  text-align: center;
  color: black;
}
h3 {
  font-size: 2rem;
  font-weight: 600;
  line-height: 2.4rem;
  padding-top: 3rem;
  padding-bottom: .5rem;
}
h4 {
  font-size: 1.6rem;
  font-weight: 600;
  line-height: 2.6rem;
  padding: 1.4rem 0 1rem;
}
p {
  font-size: 1.6rem;
  padding-bottom: 1.3rem;
}
a { color: #125CCA; }
a:hover { color: #3BA3BB; }

header {
  position: relative;
  width: 100%;
  padding: 40px 0 65px;
  background-color: #DDE8EF;
}

header.success {
  background-color: #B3E1EF;
}

header.failure {
  background-color: #d44613;
}

header h3 {
  text-align: center;
}

.toc li {
  display: inline-block;
  position: relative;
  width: 49%;
  box-sizing: border-box;
  background-color: #DDE8EF;
  list-style-type: none;
  text-align: center;
}
.toc li:not(:first-of-type) {
  margin-left: 2%;
}
.toc li:hover { background-color: #B3E1EF; }
.toc a {
  display: inline-block;
  width: 100%;
  padding: 2px 0 3px;
  font-weight: 600;
  text-decoration: none;
  color: #464646;
}

section {
  position: relative;
  margin: 20px 0;
  padding: 0 20px;
}
section > * {
  max-width: 640px;
  margin: 0 auto;
}

.illustrated {  }
img {
  display: block;
  margin: 0 auto;
  padding: 2rem 0;
}
.illustration {
  max-height: 350px;
  max-width: 100%;
}

#intro {
  padding-top: 65px;
}
#intro p {
  font-weight: 400;
  font-size: 1.8rem;
  line-height: 3rem;
  padding-top: 2rem;
}

/*table style from bootstrap*/
table {
  width: 100%;
  margin-bottom: 20px;
  padding: 1rem 0;
}
table th,
table td {
  padding: 8px;
  line-height: 1.42857143;
  vertical-align: top;
  border-bottom: 1px solid #ddd;
}
table > thead > tr > th {
  vertical-align: bottom;
  border-bottom: 2px solid #ddd;
}
.table-condensed th,
.table-condensed td {
  padding: 5px;
}

.form-inline {
  padding: 1.5rem 3rem 3rem;
  background-color: #DDE8EF;
}
label { display: block; }
input, button {
  -webkit-appearance: none;
  -moz-appearance: none;
  appearance: none;
  font-family: open sans, sans-serif;
  font-size: 16px;
  font-weight: 400;
  margin-top: 1rem;
}
input {
  padding: 6px 12px;
  width: 45%;
}
button {
  color: white;
  background-color: #F1592A;
  border-radius: 6px;
  padding: 6px 12px;
}
button:hover,
button:focus {
  outline: none;
  box-shadow: 0 0 0 3px #3BA3BD;
}
button:active {
  box-shadow: inset 0 1px 1px 1px rgba(0,0,0,.4);
}

.question-list {
  margin-bottom: 2rem;
}
.question-list li {
  margin-left: 1.8rem;
}

footer {
  border-top: 1px solid #ccc;
  padding: 1rem 3rem;
}
.text-muted {
  font-size: 13px;
  color: #888;
}
</style>
</head>
<body>
  <header id="top" ${status !== undefined ? `class="${status ? 'success' : 'failure'}"` : '' }>
    <h1>HTTP Message Signatures</h1>
    <h3>
    ${status === undefined ? 'Your browser does not support HTTP Message Signatures' : ''}
    ${status === false ? 'The Signature you sent does not validate against test public key' : ''}
    ${status === true ? 'You successfully authenticated as owning the test public key' : ''}
    </h3>
  </header>
  <section>
    <p>
      HTTP Message Signatures are a mechanism to create, encode, and verify signatures over components of an HTTP message.
      They are standardised by the IETF in <a href="https://datatracker.ietf.org/doc/html/rfc9421">RFC 9421</a>.

      This website validates the presence of such signature.
    </p>

		<h2>Overview</h2>
    <p>
      This website checks for an Ed25519 signature on incoming request. They should be signed by a test public key defined in <a href="https://datatracker.ietf.org/doc/html/rfc9421#name-example-ed25519-test-key">Appendix B.1.4 of RFC 9421</a>.
    </p>

    <h2>How to retrieve the public key used by this website</h2>
    <p>
      We define a key directory accessible under <a>/.well-known/http-message-signatures-directory</a>

      The directory looks as follow
      </p>
      <pre>{
  "keys": [
    {
      "alg": "ed25519",
      "key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=\n-----END PUBLIC KEY-----",
      "not-before": 1743465600000
    }
  ],
  "purpose": "rag"
}
      </pre>

      <p>
      Parameters are defined as follow:

      <ul>
        <li><strong>keys</strong>: an array of serialised public key
          <ul style="padding-left:1em">
          <li><strong>alg</strong>: algorithm name as registered with IANA registry HTTP Message Signature</li>
          <li><strong>key</strong>: PEM encoded public key. (Thibault: should be discard —BEGIN and —END?)</li>
          <li><strong>not-before</strong>: start of the validity of the public key as a unix timestamp in milliseconds.</li>
          <li><strong>not-after</strong>: end of the validity of the public key as a unix timestamp in milliseconds.</li>
          </ul>
        </li>
        <li><strong>user_agent</strong>: HTTP header “User-Agent” value for each signed request.</li>
        <li><strong>purpose</strong>: represents what a signature means. Examples could be aipref draft from Martin Thomson.</li>
      </ul>
    </p>

    <h2>It's hard to debug. How can this website help?</h2>
    <p>
    This website expose an endpoint dropping incoming request headers on <a>/debug</a>
    </p>
  </section>
</body>
</html>`

export const neutralHTML = generateHTML()
export const invalidHTML = generateHTML(false)
export const validHTML = generateHTML(true)